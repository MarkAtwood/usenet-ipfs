//! Ceph RADOS block store backend for the transit daemon.
//!
//! This module is only compiled when the `rados` Cargo feature is enabled,
//! which requires `librados-dev` to be installed at build time.
//!
//! All blocking RADOS operations are dispatched via
//! [`tokio::task::spawn_blocking`] so they do not stall the async runtime.

#![cfg(feature = "rados")]

use async_trait::async_trait;
use ceph::ceph::{connect_to_ceph, IoCtx, Rados};
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::sync::Arc;
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;
use stoa_core::ipfs_backend::RadosBackendConfig;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// IPFS block store backed by native Ceph RADOS.
///
/// Objects are stored under the CIDv1 canonical string key
/// (`cid.to_string()`, base32 lowercase multibase).
pub struct RadosStore {
    /// Kept alive to prevent `rados_shutdown` while `ioctx` is active.
    _rados: Rados,
    ioctx: Arc<IoCtx>,
    pool: String,
}

// SAFETY: librados operations via IoCtx are thread-safe per Ceph documentation.
// `Rados` is `Sync` but not `Send` in the ceph crate (the crate author did not
// add `unsafe impl Send for Rados` — an oversight for a thread-safe handle).
// We keep `_rados` alive only to prevent the Drop from calling `rados_shutdown`
// while the IoCtx is in use; all concurrent I/O goes through `Arc<IoCtx>`,
// which IS `Send + Sync`. Sending `RadosStore` between threads is safe because
// the internal `rados_t` handle and its `IoCtx` are guarded by librados's own
// internal locking.
//
// DO NOT remove this impl: without it `RadosStore` cannot be moved into a
// `spawn_blocking` closure.
//
// DO NOT wrap `_rados` in `Mutex<Rados>`: `Mutex<T>: Send` requires `T: Send`,
// which `Rados` is not, so this would not compile.
//
// DO NOT use `mem::forget(_rados)`: that would skip `rados_shutdown`, leaking
// the handle and leaving the IoCtx in use-after-shutdown territory.
//
// The correct long-term fix is an upstream `unsafe impl Send for Rados {}` PR
// to the ceph crate.  Until then this impl is the only safe option.
unsafe impl Send for RadosStore {}
unsafe impl Sync for RadosStore {}

impl RadosStore {
    /// Connect to the Ceph cluster and open an I/O context on `cfg.pool`.
    ///
    /// Performs a startup write probe (`_stoa_write_probe`) to verify the pool
    /// exists and this client has write permission.  Fails fast if authentication
    /// or pool access is denied.
    pub fn open(cfg: &RadosBackendConfig) -> Result<Self, String> {
        let rados = connect_to_ceph(&cfg.user, &cfg.conf_path).map_err(|e| {
            format!(
                "RADOS connect failed (user={}, conf={}): {e}",
                cfg.user, cfg.conf_path
            )
        })?;
        let ioctx = rados
            .get_rados_ioctx(&cfg.pool)
            .map_err(|e| format!("RADOS ioctx_create for pool '{}' failed: {e}", cfg.pool))?;

        // Startup write probe — verify pool exists and client has write permission.
        // ENOENT on cleanup is ignored: another instance may have already deleted it;
        // a successful write is sufficient to prove write access.
        let probe = "_stoa_write_probe";
        ioctx
            .rados_object_write_full(probe, b"probe")
            .map_err(|e| format!("RADOS pool '{}' write probe failed: {e}", cfg.pool))?;
        match ioctx.rados_object_remove(probe) {
            Ok(()) | Err(ceph::error::RadosError::ApiError(nix::errno::Errno::ENOENT)) => {}
            Err(e) => {
                return Err(format!(
                    "RADOS pool '{}' probe cleanup failed: {e}",
                    cfg.pool
                ))
            }
        }

        Ok(Self {
            _rados: rados,
            ioctx: Arc::new(ioctx),
            pool: cfg.pool.clone(),
        })
    }
}

impl std::fmt::Debug for RadosStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RadosStore(pool={})", self.pool)
    }
}

#[async_trait]
impl IpfsStore for RadosStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let ioctx = Arc::clone(&self.ioctx);
        let data = data.to_vec();
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            let obj_name = cid.to_string();
            ioctx
                .rados_object_write_full(&obj_name, &data)
                .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let ioctx = Arc::clone(&self.ioctx);
        let obj_name = cid.to_string();
        task::spawn_blocking(move || {
            // Stat first to learn the exact byte size.
            let (size, _mtime) = match ioctx.rados_object_stat(&obj_name) {
                Ok(s) => s,
                Err(ceph::error::RadosError::ApiError(nix::errno::Errno::ENOENT)) => {
                    return Ok(None)
                }
                Err(e) => return Err(IpfsError::ReadFailed(e.to_string())),
            };
            let mut buf = vec![0u8; size as usize];
            // Handle TOCTOU: object may be deleted between stat and read.
            // Truncate to the actual bytes returned — if the object shrinks
            // between stat and read, rados_object_read returns fewer bytes.
            match ioctx.rados_object_read(&obj_name, &mut buf, 0) {
                Ok(n) => buf.truncate(n as usize),
                Err(ceph::error::RadosError::ApiError(nix::errno::Errno::ENOENT)) => {
                    return Ok(None)
                }
                Err(e) => return Err(IpfsError::ReadFailed(e.to_string())),
            }
            Ok(Some(buf))
        })
        .await
        .map_err(|e| IpfsError::ReadFailed(e.to_string()))?
    }

    /// Remove `cid` from RADOS.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting an object
    /// that does not exist succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let ioctx = Arc::clone(&self.ioctx);
        let obj_name = cid.to_string();
        task::spawn_blocking(move || {
            match ioctx.rados_object_remove(&obj_name) {
                Ok(()) => Ok(DeletionOutcome::Immediate),
                Err(ceph::error::RadosError::ApiError(nix::errno::Errno::ENOENT)) => {
                    Ok(DeletionOutcome::Immediate) // idempotent
                }
                Err(e) => Err(IpfsError::WriteFailed(e.to_string())),
            }
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }
}

// No unit tests: RADOS I/O requires a live Ceph cluster.
// Integration tests require the ceph/demo docker image; see the epic for CI setup.
