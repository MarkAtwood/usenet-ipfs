# EC2 + S3 Deployment Runbook

This runbook walks through deploying stoa-transit and stoa-reader on a single
Amazon EC2 instance using S3 as the block store.  SQLite databases (the article
index) live on an EBS volume attached to the instance; S3 holds the content-
addressed article blocks.

**What "S3 as block store" means here**: every article is stored as a DAG-CBOR
block keyed by its CIDv1.  The S3 backend replaces Kubo (go-ipfs) — no IPFS
daemon is required.  The SQLite index and operator key still live on local EBS.

---

## Prerequisites

- An AWS account with permission to create EC2 instances, S3 buckets, IAM
  roles, and (optionally) Secrets Manager secrets.
- A registered domain name if you intend to expose NNTP to the public internet.
- Rust stable toolchain on your build machine (or build on the EC2 instance).

---

## Step 1 — Create the S3 bucket

```bash
aws s3api create-bucket \
  --bucket stoa-blocks \
  --region us-east-1

# Block all public access (articles are not public objects):
aws s3api put-public-access-block \
  --bucket stoa-blocks \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable versioning for accidental-delete recovery:
aws s3api put-bucket-versioning \
  --bucket stoa-blocks \
  --versioning-configuration Status=Enabled

# Optional: lifecycle rule to expire old non-current versions after 30 days
aws s3api put-bucket-lifecycle-configuration \
  --bucket stoa-blocks \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-noncurrent",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    }]
  }'
```

Choose a second bucket for SQLite backups (keeps article blocks and index
backups separate):

```bash
aws s3api create-bucket \
  --bucket stoa-index-backups \
  --region us-east-1

aws s3api put-public-access-block \
  --bucket stoa-index-backups \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

---

## Step 2 — Create the IAM role

Create an instance role that allows the EC2 instance to read and write S3
without embedding long-lived credentials in config files.  The S3 backend
uses the instance profile automatically when `access_key_id` and
`secret_access_key` are absent from the config.

Save the following as `stoa-s3-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlockStore",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::stoa-blocks",
        "arn:aws:s3:::stoa-blocks/*"
      ]
    },
    {
      "Sid": "IndexBackups",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::stoa-index-backups/*"
      ]
    }
  ]
}
```

```bash
# Create the policy:
aws iam create-policy \
  --policy-name StoaS3Policy \
  --policy-document file://stoa-s3-policy.json

# Create the role and attach it:
aws iam create-role \
  --role-name StoaInstanceRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name StoaInstanceRole \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/StoaS3Policy

aws iam create-instance-profile \
  --instance-profile-name StoaInstanceProfile

aws iam add-role-to-instance-profile \
  --instance-profile-name StoaInstanceProfile \
  --role-name StoaInstanceRole
```

If you want to store the admin bearer token and TLS key in Secrets Manager
instead of on disk, add these permissions to the policy and use
`secretx:aws-sm:<secret-name>` URIs in the config (see Step 6).

---

## Step 3 — Launch the EC2 instance

Recommended instance type for a single-node deployment: **t3.medium** (2 vCPU,
4 GiB RAM).  Scale up to t3.large or c6i.xlarge under sustained peering load.

Attach the EBS root volume and a second EBS volume for stoa state:

- Root: 20 GiB gp3 (OS + binaries)
- Data: 20 GiB gp3 (SQLite databases, operator key, block cache)

```bash
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \  # Amazon Linux 2023 us-east-1; check current AMI
  --instance-type t3.medium \
  --key-name your-keypair \
  --iam-instance-profile Name=StoaInstanceProfile \
  --block-device-mappings '[
    {"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}},
    {"DeviceName":"/dev/xvdf","Ebs":{"VolumeSize":20,"VolumeType":"gp3","DeleteOnTermination":false}}
  ]' \
  --security-group-ids sg-XXXXXXXX \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=stoa}]'
```

Set `DeleteOnTermination=false` on the data volume so SQLite state survives
accidental instance termination.

### Security group rules

| Direction | Port | Protocol | Source | Purpose |
|-----------|------|----------|--------|---------|
| Inbound | 119 | TCP | 0.0.0.0/0 (or peer CIDRs) | NNTP transit + reader |
| Inbound | 22 | TCP | your IP | SSH admin |
| Outbound | 443 | TCP | 0.0.0.0/0 | S3 API, Secrets Manager |
| Outbound | all | all | 0.0.0.0/0 | peer connections, DNS |

If you run stoa-mail (JMAP), add inbound 8080 (or 443 behind a load balancer).

---

## Step 4 — Prepare the data volume

SSH into the instance and format/mount the data volume:

```bash
# Format (only on first use — skips if already formatted):
sudo mkfs.ext4 -L stoa-data /dev/xvdf

# Mount:
sudo mkdir -p /srv/stoa
sudo mount /dev/xvdf /srv/stoa

# Add to /etc/fstab for automatic mount on reboot:
echo 'LABEL=stoa-data /srv/stoa ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab

# Create directory layout:
sudo mkdir -p \
  /srv/stoa/transit/db \
  /srv/stoa/reader/db \
  /srv/stoa/keys \
  /srv/stoa/backup \
  /etc/stoa

# Create a dedicated system user:
sudo useradd -r -s /sbin/nologin -d /srv/stoa stoa

# Set ownership:
sudo chown -R stoa:stoa /srv/stoa /etc/stoa
```

---

## Step 5 — Build and install the binaries

On the instance (or cross-compile and copy the binaries):

```bash
# Install Rust:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Clone and build (transit + reader only; add stoa-mail if needed):
git clone https://github.com/MarkAtwood/stoa.git
cd stoa
cargo build --release -p stoa-transit -p stoa-reader

# Install to system path:
sudo cp -f target/release/stoa-transit target/release/stoa-reader /usr/local/bin/
sudo chmod +x /usr/local/bin/stoa-transit /usr/local/bin/stoa-reader
```

Verify the build:
```bash
stoa-transit --version
stoa-reader --version
```

---

## Step 6 — Generate operator signing keys

Each daemon signs every article it ingests with an Ed25519 key.  Run `keygen`
once before the daemon's first start.  If the key is lost, previously signed
articles cannot be verified by peers.

```bash
sudo -u stoa stoa-transit keygen --output /srv/stoa/keys/transit.key
sudo -u stoa stoa-reader  keygen --output /srv/stoa/keys/reader.key
```

Expected output (one line per daemon):
```
public_key: <64-hex Ed25519 public key>
node_id:    <16-hex HLC node ID>
key_file:   /srv/stoa/keys/transit.key
```

Key files are written mode 0600.  **Back them up immediately**:

```bash
# Encrypt and store off-instance:
gpg --symmetric --cipher-algo AES256 -o transit.key.gpg /srv/stoa/keys/transit.key
gpg --symmetric --cipher-algo AES256 -o reader.key.gpg  /srv/stoa/keys/reader.key
# Upload to S3 or store in Secrets Manager.
```

---

## Step 7 — Write the config files

### `/etc/stoa/transit.toml`

```toml
[listen]
addr = "0.0.0.0:119"

[peers]
# Add remote transit peers here once they are running:
addresses = []

[groups]
names = [
    "comp.lang.rust",
    "alt.test",
]

# --- S3 block store (no Kubo required) ---
[backend]
type = "s3"

[backend.s3]
bucket = "stoa-blocks"
region = "us-east-1"
prefix = "transit/blocks"
# access_key_id and secret_access_key are omitted; the instance profile is used.
# At startup, stoa performs a PUT + DELETE probe to verify IAM permissions.

[pinning]
rules = ["pin-all-ingress"]

[gc]
schedule    = "0 3 * * *"   # 03:00 UTC daily
max_age_days = 90
report_dir   = "/srv/stoa/transit/gc-reports"

[database]
path       = "/srv/stoa/transit/db/transit.db"
core_path  = "/srv/stoa/transit/db/core.db"

[operator]
signing_key_path = "/srv/stoa/keys/transit.key"

[backup]
dest_dir  = "/srv/stoa/backup"
s3_bucket = "stoa-index-backups"
s3_prefix = "transit/"
schedule  = "0 2 * * *"    # 02:00 UTC daily, one hour before GC

[admin]
addr = "127.0.0.1:9090"
# bearer_token = "secretx:aws-sm:prod/stoa/transit-admin-token"

[log]
level  = "info"
format = "json"
```

### `/etc/stoa/reader.toml`

```toml
[listen]
addr = "0.0.0.0:119"
# NNTPS on a separate port (requires TLS config below):
# tls_addr = "0.0.0.0:563"

[limits]
max_connections      = 100
command_timeout_secs = 30

# --- S3 block store (shared bucket, different prefix) ---
[backend]
type = "s3"

[backend.s3]
bucket = "stoa-blocks"
region = "us-east-1"
prefix = "transit/blocks"   # Must match transit's prefix — same blocks, same bucket

[database]
reader_path = "/srv/stoa/reader/db/reader.db"
core_path   = "/srv/stoa/reader/db/core.db"
verify_path = "/srv/stoa/reader/db/verify.db"

[auth]
required = true

# Add one [[auth.users]] per user, or point at a credential file:
[[auth.users]]
username = "alice"
password = "$2b$12$..."   # bcrypt hash; see "Create users" below

[tls]
# Uncomment to enable NNTPS (port 563):
# cert_path = "/etc/ssl/certs/nntp.pem"
# key_path  = "/etc/ssl/private/nntp.key"

[operator]
signing_key_path = "/srv/stoa/keys/reader.key"

[admin]
addr = "127.0.0.1:9091"   # Different port from transit on the same host

[log]
level  = "info"
format = "json"
```

**Note on port 119**: both daemons are configured to bind port 119.  If they
run on the same host they must use different ports.  The common pattern is to
put transit on 119 (peer-to-peer, not user-facing) and reader on a different
port (e.g. 1199) or behind a port-based reverse proxy.  Alternatively, transit
peers on a non-standard port and reader owns 119.  Adjust the security group
accordingly.

### Create bcrypt password hashes for reader users

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt(12)).decode())"
# Paste the output into reader.toml [[auth.users]] password field.
```

---

## Step 8 — Install systemd unit files

### `/etc/systemd/system/stoa-transit.service`

```ini
[Unit]
Description=stoa transit daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=stoa
Group=stoa
ExecStart=/usr/local/bin/stoa-transit --config /etc/stoa/transit.toml
Restart=on-failure
RestartSec=5s

# Graceful shutdown: 30 s drain + 60 s buffer before SIGKILL
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=90

# Harden the service:
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/srv/stoa /etc/stoa

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/stoa-reader.service`

```ini
[Unit]
Description=stoa reader daemon
After=network-online.target stoa-transit.service
Wants=network-online.target

[Service]
Type=simple
User=stoa
Group=stoa
ExecStart=/usr/local/bin/stoa-reader --config /etc/stoa/reader.toml
Restart=on-failure
RestartSec=5s

KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=90

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/srv/stoa /etc/stoa

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable stoa-transit stoa-reader
sudo systemctl start stoa-transit stoa-reader
```

---

## Step 9 — Verify the deployment

### Transit health check

```bash
curl -s http://127.0.0.1:9090/healthz/ready | python3 -m json.tool
```

Expected when healthy (S3 backend; no `kubo_reachable` check because Kubo is
not in use):
```json
{
  "status": "ok",
  "uptime_secs": 14,
  "checks": [
    {"name": "sqlite_transit", "ok": true, "detail": ""},
    {"name": "sqlite_core",    "ok": true, "detail": ""}
  ]
}
```

HTTP 503 with `"status": "degraded"` means a SQLite check failed.  The S3
backend write probe runs at startup, not on every health poll — an S3
permission problem surfaces as a startup failure, not a degraded health
response.

### Reader NNTP handshake

```bash
{ echo "CAPABILITIES"; sleep 1; echo "QUIT"; } | nc localhost 119
```

Expected:
```
200 stoa reader ready
101 Capability list follows
VERSION 2
READER
POST
IHAVE
OVER
HDR
LIST ACTIVE NEWSGROUPS OVERVIEW.FMT
.
205 Bye
```

### S3 write probe

The transit daemon performs a write probe at startup:
```
PUT  s3://stoa-blocks/transit/blocks/_stoa_write_probe
DELETE s3://stoa-blocks/transit/blocks/_stoa_write_probe
```

If IAM permissions are wrong, the daemon exits at startup with:
```
error: S3 store init failed: ... AccessDenied
```

Check CloudTrail or the IAM policy if you see this.

### Post a test article

```bash
{ printf "POST\r\n"; sleep 0.3
  printf "From: test@example.com\r\nNewsgroups: alt.test\r\nSubject: hello\r\n\r\ntest body\r\n.\r\n"
  sleep 0.3; printf "QUIT\r\n"; } | nc localhost 119
```

Confirm the block landed in S3:
```bash
aws s3 ls s3://stoa-blocks/transit/blocks/ | head -5
```

---

## Step 10 — SQLite backup configuration

The `[backup]` section in `transit.toml` (configured in Step 7) handles
scheduled SQLite backups via `POST /admin/backup`.  The daemon calls
`aws s3 cp` after each local backup.  Ensure the AWS CLI is installed:

```bash
sudo dnf install -y aws-cli   # Amazon Linux 2023
```

The `aws` CLI inherits IAM credentials from the instance profile automatically.

Trigger a manual backup to verify:

```bash
curl -s -X POST http://127.0.0.1:9090/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Expected response:
```json
{"backups":["/srv/stoa/backup/transit-20260504T120000Z.db","/srv/stoa/backup/core-20260504T120000Z.db"]}
```

Then confirm S3 upload:
```bash
aws s3 ls s3://stoa-index-backups/transit/
```

Reader SQLite is not covered by the reader daemon's built-in backup command —
back it up separately with a cron job:

```bash
# /etc/cron.d/stoa-reader-backup
0 2 * * * stoa  sqlite3 /srv/stoa/reader/db/reader.db ".backup /srv/stoa/backup/reader-$(date -u +%Y%m%dT%H%M%SZ).db" && aws s3 cp /srv/stoa/backup/reader-*.db s3://stoa-index-backups/reader/ 2>/dev/null
```

Apply a 30-day S3 lifecycle rule to stoa-index-backups to prune old backups
automatically (see Step 1 for the JSON template — add `s3:` prefix rules for
`transit/` and `reader/` as needed).

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|-------------|--------|
| Transit exits at startup: `S3 store init failed: AccessDenied` | IAM role missing `s3:PutObject` or `s3:ListBucket` | Check the instance profile; run `aws s3 ls s3://stoa-blocks/` as the `stoa` user |
| Transit exits: `S3 store init failed: bucket not found` | Bucket name or region mismatch in config | Verify `bucket` and `region` fields match what was created |
| Reader returns `411 No such newsgroup` | No articles posted to that group yet | POST a test article; groups are discovered from article content |
| `LIST` returns empty | No articles posted yet | Post at least one article |
| Port 119 bind error on reader | Transit already owns 119 | Change reader `listen.addr` to a different port (e.g. 1199) |
| Admin endpoint 403 | `bearer_token` set in config | Pass `Authorization: Bearer <token>` header in the curl command |
| S3 backup upload fails | `aws` CLI not installed or no `s3:PutObject` on backup bucket | Install `aws-cli`, check IAM policy includes the backup bucket |
| Articles lost after SQLite restore | Restored from old backup; newer articles were in S3 but not indexed | Start reader with empty databases; it will re-ingest from S3 on next peering sync |

---

## Data layout summary

| Data | Location | Durability |
|------|----------|-----------|
| Article blocks (content) | `s3://stoa-blocks/transit/blocks/` | S3 (11 nines) |
| Transit SQLite index | `/srv/stoa/transit/db/` on EBS | EBS snapshot + S3 backup |
| Reader SQLite index | `/srv/stoa/reader/db/` on EBS | EBS snapshot + S3 backup |
| Operator signing keys | `/srv/stoa/keys/` on EBS | EBS + encrypted off-instance copy |
| SQLite backups | `s3://stoa-index-backups/` | S3 |

Article content (blocks in S3) is the source of truth.  If SQLite is lost, the
index can be rebuilt by starting the daemon with empty databases and allowing
the peering sync to re-ingest pinned articles.  The operator key cannot be
recovered from S3 — protect it accordingly.

---

## DNS setup

### Allocate an Elastic IP

EC2 public IPs change on every stop/start cycle.  Allocate an Elastic IP so
your hostname stays stable:

```bash
# Allocate:
ALLOC=$(aws ec2 allocate-address --domain vpc --query AllocationId --output text)
echo "AllocationId: $ALLOC"

# Associate with the running instance:
aws ec2 associate-address \
  --instance-id i-XXXXXXXXXXXXXXXXX \
  --allocation-id "$ALLOC"

# Confirm the public IP:
aws ec2 describe-addresses --allocation-ids "$ALLOC" \
  --query 'Addresses[0].PublicIp' --output text
```

Use this IP for all DNS records below.

### Forward DNS (A record)

Create an A record for the hostname your stoa instance will advertise.  This
is what peers use to connect and what appears in NNTP `Path:` headers.

| Name | Type | Value | TTL |
|------|------|-------|-----|
| `nntp.example.com` | A | `<Elastic IP>` | 300 |

In Route 53:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id ZXXXXXXXXXXXXX \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "nntp.example.com.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "<Elastic IP>"}]
      }
    }]
  }'
```

### Reverse DNS (PTR record)

A matching PTR record (`<IP>` → hostname) is required by most NNTP peers for
authentication and spam rejection.  AWS does not set PTR records automatically.

For addresses in AWS-owned IP space, request a PTR record via the AWS console:

1. Go to **EC2 → Elastic IPs** → select the address.
2. Click **Actions → Update reverse DNS**.
3. Enter the FQDN: `nntp.example.com`.

AWS validates that the A record for `nntp.example.com` already points at the
IP before accepting the PTR update.  Set the A record first, wait for
propagation (a few minutes), then request the PTR.

Verify propagation:
```bash
dig -x <Elastic IP> +short        # should return nntp.example.com.
dig nntp.example.com A +short     # should return <Elastic IP>
```

### Set the hostname in stoa config

Both daemons use the configured hostname in NNTP `Path:` headers and as the
HLC node-ID seed.  Set it to the FQDN you just registered.

In `/etc/stoa/transit.toml`:
```toml
[operator]
signing_key_path = "/srv/stoa/keys/transit.key"
hostname         = "nntp.example.com"
```

In `/etc/stoa/reader.toml`:
```toml
path_hostname = "nntp.example.com"

[operator]
signing_key_path = "/srv/stoa/keys/reader.key"
```

Restart both daemons after changing these fields:
```bash
sudo systemctl restart stoa-transit stoa-reader
```

### If you are also running stoa-smtp (mail)

SMTP delivery requires three additional DNS records.  Skip this section if you
are running transit + reader only.

**MX record** — tells other mail servers where to deliver mail for your domain:

| Name | Type | Priority | Value | TTL |
|------|------|----------|-------|-----|
| `example.com` | MX | 10 | `nntp.example.com` | 300 |

**SPF record** — authorises your EC2 IP to send mail for the domain:

| Name | Type | Value | TTL |
|------|------|-------|-----|
| `example.com` | TXT | `"v=spf1 a:nntp.example.com ~all"` | 300 |

**DKIM record** — publishes the public key for DKIM signing.  The selector and
key are configured in `smtp.toml`; see `docs/ops/dkim.md` for the full setup.
The DNS record takes the form:

| Name | Type | Value | TTL |
|------|------|-------|-----|
| `<selector>._domainkey.example.com` | TXT | `"v=DKIM1; k=ed25519; p=<base64pubkey>"` | 300 |

**DMARC record** (recommended) — policy for receivers when SPF/DKIM fail:

| Name | Type | Value | TTL |
|------|------|-------|-----|
| `_dmarc.example.com` | TXT | `"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"` | 300 |

Verify with:
```bash
dig example.com MX +short
dig example.com TXT +short          # SPF
dig <selector>._domainkey.example.com TXT +short   # DKIM
dig _dmarc.example.com TXT +short   # DMARC
```

---

## See also

- `docs/RUNBOOK.md` — general single-host runbook (Kubo backend)
- `docs/ops/backup_restore.md` — detailed backup and restore procedures
- `docs/ops/configuration_reference.md` — full config field reference
- `docs/ops/peering_guide.md` — adding transit peers
- `docs/ops/retention_guide.md` — GC and pinning policy
