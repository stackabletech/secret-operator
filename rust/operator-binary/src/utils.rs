use std::fmt::Write as _; // import without risk of name clashing
use std::{
    fmt::{Debug, LowerHex},
    ops::{Deref, DerefMut},
    os::unix::prelude::AsRawFd,
    path::Path,
};

use futures::{pin_mut, Stream, StreamExt};
use openssl::asn1::{Asn1Time, Asn1TimeRef, TimeDiff};
use pin_project::pin_project;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use socket2::Socket;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{UnixListener, UnixStream},
};
use tonic::transport::server::Connected;

/// Adapter for using [`UnixStream`] as a [`tonic`] connection
/// Tonic usually communicates via TCP sockets, but the Kubernetes CSI interface expects
/// plugins to use Unix sockets instead.
/// This provides a wrapper implementation which delegates to tokio's [`UnixStream`] in order
/// to enable tonic to communicate via Unix sockets.
#[pin_project]
pub struct TonicUnixStream(#[pin] pub UnixStream);

impl AsyncRead for TonicUnixStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl AsyncWrite for TonicUnixStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl Connected for TonicUnixStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// Bind a Unix Domain Socket listener that is only accessible to the current user
pub fn uds_bind_private(path: impl AsRef<Path>) -> Result<UnixListener, std::io::Error> {
    // Workaround for https://github.com/tokio-rs/tokio/issues/4422
    let socket = Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    unsafe {
        // Socket-level chmod is propagated to the file created by Socket::bind.
        // We need to chmod /before/ creating the file, because otherwise there is a brief window where
        // the file is world-accessible (unless restricted by the global umask).
        if libc::fchmod(socket.as_raw_fd(), 0o600) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    socket.bind(&socket2::SockAddr::unix(path)?)?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    UnixListener::from_std(socket.into())
}

/// Helper for formatting byte arrays
pub struct FmtByteSlice<'a>(pub &'a [u8]);
impl LowerHex for FmtByteSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            f.write_fmt(format_args!("{:02x}", byte))?;
        }
        Ok(())
    }
}

/// Combines the messages of an error and its sources into a [`String`] of the form `"error: source 1: source 2: root error"`
pub fn error_full_message(err: &dyn std::error::Error) -> String {
    // Build the full hierarchy of error messages by walking up the stack until an error
    // without `source` set is encountered and concatenating all encountered error strings.
    let mut full_msg = format!("{}", err);
    let mut curr_err = err.source();
    while let Some(curr_source) = curr_err {
        let _ = write!(full_msg, ": {}", curr_source);
        curr_err = curr_source.source();
    }
    full_msg
}

/// Propagates `Ok(true)` and `Err(_)` from `stream`, otherwise returns `Ok(false)`.
pub async fn trystream_any<S: Stream<Item = Result<bool, E>>, E>(stream: S) -> Result<bool, E> {
    pin_mut!(stream);
    while let Some(value) = stream.next().await {
        if let Ok(true) | Err(_) = value {
            return value;
        }
    }
    Ok(false)
}

/// Concatenate chunks of bytes, short-circuiting on [`Err`].
///
/// This is a byte-oriented equivalent to [`Iterator::collect::<Result<String, _>>`](`Iterator::collect`).
pub fn iterator_try_concat_bytes<I1, I2, E>(iter: I1) -> Result<Vec<u8>, E>
where
    I1: IntoIterator<Item = Result<I2, E>>,
    I2: IntoIterator<Item = u8>,
{
    let mut buffer = Vec::new();
    for chunk in iter {
        buffer.extend(chunk?)
    }
    Ok(buffer)
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Asn1TimeParseError {
    #[snafu(display("unix epoch is not a valid Asn1Time"))]
    Epoch { source: openssl::error::ErrorStack },

    #[snafu(display("unable to diff Asn1Time"))]
    Diff { source: openssl::error::ErrorStack },

    #[snafu(display("unable to parse as OffsetDateTime"))]
    Parse { source: time::error::ComponentRange },

    #[snafu(display("time overflowed"))]
    Overflow,
}

/// Converts an OpenSSL [`Asn1TimeRef`] into a Rustier [`OffsetDateTime`].
pub fn asn1time_to_offsetdatetime(asn: &Asn1TimeRef) -> Result<OffsetDateTime, Asn1TimeParseError> {
    use asn1_time_parse_error::*;
    const SECS_PER_DAY: i64 = 60 * 60 * 24;
    let epoch = Asn1Time::from_unix(0).context(EpochSnafu)?;
    let TimeDiff { days, secs } = epoch.diff(asn).context(DiffSnafu)?;
    OffsetDateTime::from_unix_timestamp(
        i64::from(days)
            .checked_mul(SECS_PER_DAY)
            .and_then(|day_secs| day_secs.checked_add(i64::from(secs)))
            .context(OverflowSnafu)?,
    )
    .context(ParseSnafu)
}

/// Wrapper for (mostly) secret values that should not be logged.
// When/if migrating to Valuable, provide a dummy implementation of Value too
pub struct Unloggable<T>(pub T);

impl<T> Debug for Unloggable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> Deref for Unloggable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Unloggable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use openssl::asn1::Asn1Time;
    use time::OffsetDateTime;

    use super::{asn1time_to_offsetdatetime, iterator_try_concat_bytes};
    use crate::utils::{error_full_message, trystream_any, FmtByteSlice};

    #[test]
    fn fmt_hex_byte_slice() {
        assert_eq!(format!("{:x}", FmtByteSlice(&[1, 2, 255, 128])), "0102ff80");
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            error_full_message(anyhow::anyhow!("standalone error").as_ref()),
            "standalone error"
        );
        assert_eq!(
            error_full_message(
                anyhow::anyhow!("root error")
                    .context("middleware")
                    .context("leaf")
                    .as_ref()
            ),
            "leaf: middleware: root error"
        );
    }

    #[tokio::test]
    async fn trystream_any_should_work() {
        let bomb = |msg: &'static str| futures::stream::repeat_with(move || panic!("{msg}"));
        assert_eq!(
            trystream_any(futures::stream::iter([])).await,
            Result::<_, ()>::Ok(false)
        );
        assert_eq!(
            trystream_any(futures::stream::iter([Ok(false), Ok(false)])).await,
            Result::<_, ()>::Ok(false)
        );
        assert_eq!(
            trystream_any(futures::stream::iter([Ok(false), Ok(true)])).await,
            Result::<_, ()>::Ok(true)
        );
        assert_eq!(
            trystream_any(
                futures::stream::iter([Ok(false), Ok(true)])
                    .chain(bomb("should not continue reading stream after Ok(true)"))
            )
            .await,
            Result::<_, ()>::Ok(true)
        );
        assert_eq!(
            trystream_any(
                futures::stream::iter([Ok(false), Err(())])
                    .chain(bomb("should not continue reading stream after Err(_)"))
            )
            .await,
            Result::<_, ()>::Err(())
        );
    }

    #[test]
    fn iterator_try_concat_bytes_should_work() {
        assert_eq!(
            iterator_try_concat_bytes([Result::<_, ()>::Ok(vec![0, 1]), Ok(vec![2])]),
            Ok(vec![0, 1, 2])
        );
        assert_eq!(
            iterator_try_concat_bytes([Ok(vec![0, 1]), Err(())]),
            Err(())
        );
        assert_eq!(iterator_try_concat_bytes([Err(()), Ok(vec![2])]), Err(()));
        assert_eq!(iterator_try_concat_bytes::<_, Vec<_>, ()>([]), Ok(vec![]));
    }

    #[test]
    fn asn1time_to_offsetdatetime_should_work() {
        assert_eq!(
            asn1time_to_offsetdatetime(
                // Asn1Time uses a custom time format (https://www.openssl.org/docs/man3.2/man3/ASN1_TIME_set.html)
                // that is _roughly_ "ISO8601-1 without separator characters"
                &Asn1Time::from_str("20240102020304Z").unwrap()
            )
            .unwrap(),
            OffsetDateTime::parse(
                "2024-01-02T02:03:04Z",
                &time::format_description::well_known::Iso8601::DEFAULT
            )
            .unwrap()
        );
    }
}
