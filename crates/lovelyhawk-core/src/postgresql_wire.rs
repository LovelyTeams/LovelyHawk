//! Bounds the native driver's input before decoding or SCRAM computation.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_AUTH_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;
// Two bounded sweeps of 13 object catalogs plus 4 access views, parameters and
// identity metadata fit below 32 MiB. Keep framing at 1 MiB and reserve protocol
// overhead within this finite whole-connection limit.
const MAX_WIRE_READ: usize = 40 * 1024 * 1024;
const MAX_WIRE_WRITE: usize = 256 * 1024;

fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Also bounds TLS traffic, including traffic before PostgreSQL authentication.
pub(crate) struct WireBudget<S> {
    inner: S,
    read_left: usize,
    write_left: usize,
}

impl<S> WireBudget<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            read_left: MAX_WIRE_READ,
            write_left: MAX_WIRE_WRITE,
        }
    }
}

impl<S> fmt::Debug for WireBudget<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresqlWireBudget")
            .field("read_left", &self.read_left)
            .field("write_left", &self.write_left)
            .finish()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WireBudget<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read_left == 0 {
            return Poll::Ready(Err(rejected("PostgreSQL wire read limit exceeded")));
        }
        let mut scratch = Zeroizing::new([0_u8; 8192]);
        let count = this.read_left.min(out.remaining()).min(scratch.len());
        let mut input = ReadBuf::new(&mut scratch[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
            Poll::Ready(Ok(())) => {
                this.read_left -= input.filled().len();
                out.put_slice(input.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WireBudget<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_left == 0 {
            return Poll::Ready(Err(rejected("PostgreSQL wire write limit exceeded")));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..bytes.len().min(this.write_left)]) {
            Poll::Ready(Ok(count)) => {
                this.write_left -= count;
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Applied after TLS, or directly to an explicitly selected SSH-loopback stream.
/// A complete bounded frame is checked before the driver sees any of it.
pub(crate) struct FrameGuard<S> {
    inner: S,
    header: [u8; 5],
    header_len: usize,
    frame: Zeroizing<Vec<u8>>,
    expected: usize,
    delivered: usize,
    validated: bool,
}

impl<S> FrameGuard<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 5],
            header_len: 0,
            frame: Zeroizing::new(Vec::new()),
            expected: 0,
            delivered: 0,
            validated: false,
        }
    }

    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }

    fn reset(&mut self) {
        self.frame.zeroize();
        self.header.zeroize();
        self.header_len = 0;
        self.expected = 0;
        self.delivered = 0;
        self.validated = false;
    }
}

impl<S> fmt::Debug for FrameGuard<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresqlFrameGuard")
            .field("buffered_bytes", &self.frame.len())
            .field("expected_bytes", &self.expected)
            .finish()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.validated && this.delivered == this.frame.len() {
            this.reset();
        }
        while this.header_len < this.header.len() {
            let mut input = ReadBuf::new(&mut this.header[this.header_len..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = input.filled().len();
                    if count == 0 {
                        return if this.header_len == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(rejected("truncated PostgreSQL header")))
                        };
                    }
                    this.header_len += count;
                }
            }
        }
        if this.expected == 0 {
            let length =
                u32::from_be_bytes(this.header[1..5].try_into().expect("fixed header")) as usize;
            if !(4..MAX_FRAME_BYTES).contains(&length) {
                return Poll::Ready(Err(rejected(
                    "PostgreSQL frame length exceeds the supported range",
                )));
            }
            this.expected = length + 1;
            if this.header[0] == b'R' && this.expected > MAX_AUTH_BYTES {
                return Poll::Ready(Err(rejected(
                    "PostgreSQL authentication frame is too large",
                )));
            }
            this.frame.extend_from_slice(&this.header);
        }
        while this.frame.len() < this.expected {
            let mut scratch = Zeroizing::new([0_u8; 8192]);
            let count = (this.expected - this.frame.len()).min(scratch.len());
            let mut input = ReadBuf::new(&mut scratch[..count]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if input.filled().is_empty() {
                        return Poll::Ready(Err(rejected("truncated PostgreSQL frame")));
                    }
                    this.frame.extend_from_slice(input.filled());
                }
            }
        }
        if !this.validated {
            if let Err(error) = validate_authentication_frame(&this.frame) {
                return Poll::Ready(Err(error));
            }
            this.validated = true;
        }
        let count = out.remaining().min(this.frame.len() - this.delivered);
        out.put_slice(&this.frame[this.delivered..this.delivered + count]);
        this.delivered += count;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn validate_authentication_frame(frame: &[u8]) -> io::Result<()> {
    if frame[0] != b'R' {
        return Ok(());
    }
    if frame.len() < 9 {
        return Err(rejected("invalid PostgreSQL authentication frame"));
    }
    let method = u32::from_be_bytes(frame[5..9].try_into().expect("authentication code"));
    if !matches!(method, 0 | 5 | 10 | 11 | 12) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported PostgreSQL authentication method",
        ));
    }
    if method != 11 {
        return Ok(());
    }
    let message =
        std::str::from_utf8(&frame[9..]).map_err(|_| rejected("invalid SCRAM challenge"))?;
    let mut iterations = None;
    for field in message.split(',') {
        if let Some(number) = field.strip_prefix("i=") {
            if iterations.is_some()
                || number.is_empty()
                || number.len() > 7
                || !number.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(rejected("invalid SCRAM iteration count"));
            }
            iterations = number.parse::<u32>().ok();
        }
    }
    if !iterations.is_some_and(|value| (1..=MAX_SCRAM_ITERATIONS).contains(&value)) {
        return Err(rejected(
            "SCRAM iteration count exceeds the supported range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&(payload.len() as u32 + 4).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[tokio::test]
    async fn fragmented_frames_are_preserved_without_exposing_partial_authentication() {
        let (client, mut server) = duplex(8);
        let mut bytes = frame(b'R', &[0, 0, 0, 0]);
        bytes.extend(frame(b'Z', b"I"));
        let expected = bytes.clone();
        let writer = tokio::spawn(async move {
            for byte in bytes {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = FrameGuard::new(client);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        writer.await.unwrap();
        assert_eq!(actual, expected);
        assert!(reader.frame.is_empty());
    }

    #[tokio::test]
    async fn oversized_and_truncated_frames_are_rejected_before_delivery() {
        for input in [
            vec![b'D', 0xff, 0xff, 0xff, 0xff],
            vec![b'R', 0, 0, 0, 2],
            vec![b'D', 0, 0],
            vec![b'D', 0, 0, 0, 7, 1],
        ] {
            let mut reader = FrameGuard::new(input.as_slice());
            let mut output = Vec::new();
            assert!(reader.read_to_end(&mut output).await.is_err());
            assert!(output.is_empty());
            assert!(reader.frame.len() <= MAX_FRAME_BYTES);
        }
    }

    #[tokio::test]
    async fn scram_work_factor_is_bounded_before_the_native_driver_receives_it() {
        for (count, valid) in [
            ("4096", true),
            ("1000000", true),
            ("1000001", false),
            ("0", false),
            ("-1", false),
            ("2147483647", false),
            ("4096,i=4096", false),
            ("", false),
        ] {
            let mut payload = 11_u32.to_be_bytes().to_vec();
            payload.extend_from_slice(format!("r=nonce,s=c2FsdA==,i={count}").as_bytes());
            let bytes = frame(b'R', &payload);
            let mut reader = FrameGuard::new(bytes.as_slice());
            let mut output = Vec::new();
            assert_eq!(reader.read_to_end(&mut output).await.is_ok(), valid);
            assert_eq!(output.is_empty(), !valid);
            assert!(!format!("{reader:?}").contains("nonce"));
        }
    }

    #[tokio::test]
    async fn wire_budgets_apply_across_reads_and_writes() {
        let mut reader = WireBudget::new(b"abcd".as_slice());
        reader.read_left = 3;
        let mut buffer = [0; 2];
        assert_eq!(reader.read(&mut buffer).await.unwrap(), 2);
        assert_eq!(reader.read(&mut buffer).await.unwrap(), 1);
        assert!(reader.read(&mut buffer).await.is_err());
        let mut writer = WireBudget::new(Vec::new());
        writer.write_left = 3;
        assert_eq!(writer.write(b"abcde").await.unwrap(), 3);
        assert!(writer.write(b"d").await.is_err());
        assert_eq!(writer.inner, b"abc");
    }
}
