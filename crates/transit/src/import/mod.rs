pub mod ihave_push;
pub mod mbox;
pub mod reindex;
pub mod rnews;
pub mod suck_pull;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Parse the 3-digit NNTP response code from the start of a response line.
///
/// Returns 0 if the line is too short or the first three characters are not digits.
pub(crate) fn parse_nntp_response_code(line: &str) -> u16 {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

/// Result of sending a single article via IHAVE.
#[derive(Debug)]
pub(crate) enum SendResult {
    Accepted,
    Duplicate,
    Rejected,
}

/// Open a TCP connection to `addr` and read the NNTP greeting.
///
/// Returns `Some((reader, writer))` on success, `None` on any failure.
pub(crate) async fn connect_nntp(addr: &str) -> Option<(BufReader<OwnedReadHalf>, OwnedWriteHalf)> {
    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("TCP connect to {addr} failed: {e}");
            return None;
        }
    };

    let (reader_half, writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting (200 or 201).
    if reader.read_line(&mut line).await.is_err() {
        return None;
    }
    let code = parse_nntp_response_code(&line);
    if code != 200 && code != 201 {
        tracing::warn!("unexpected greeting from {addr}: {}", line.trim());
        return None;
    }

    Some((reader, writer))
}

/// Send one article via IHAVE on an already-established connection.
///
/// The caller must have already consumed the server greeting.
/// Returns `Ok(SendResult)` on protocol success/failure, or `Err` if an I/O
/// error occurs (meaning the connection should be discarded).
pub(crate) async fn send_ihave_on_conn(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    msgid: &str,
    article_bytes: &[u8],
) -> Result<SendResult, std::io::Error> {
    let mut line = String::new();

    // Send IHAVE <msgid>.
    let ihave_cmd = format!("IHAVE {msgid}\r\n");
    writer.write_all(ihave_cmd.as_bytes()).await?;

    // Read IHAVE response.
    line.clear();
    reader.read_line(&mut line).await?;
    let code = parse_nntp_response_code(&line);

    match code {
        435 => return Ok(SendResult::Duplicate),
        335 => {} // proceed to send article
        _ => {
            tracing::info!("IHAVE {msgid} got code {code}: {}", line.trim());
            return Ok(SendResult::Rejected);
        }
    }

    // Send article with dot-stuffing, terminated by ".\r\n".
    let stuffed = stoa_core::util::nntp_dot_stuff(article_bytes);
    writer.write_all(&stuffed).await?;
    writer.write_all(b".\r\n").await?;

    // Read final transfer response.
    line.clear();
    reader.read_line(&mut line).await?;
    let code = parse_nntp_response_code(&line);

    match code {
        235 => Ok(SendResult::Accepted),
        436 => {
            tracing::info!("transfer of {msgid} failed with 436 (transient — server busy)");
            Ok(SendResult::Rejected)
        }
        437 => {
            tracing::info!("transfer of {msgid} rejected with 437 (permanent — article refused)");
            Ok(SendResult::Rejected)
        }
        _ => {
            tracing::info!("unexpected final code {code} for {msgid}");
            Ok(SendResult::Rejected)
        }
    }
}
