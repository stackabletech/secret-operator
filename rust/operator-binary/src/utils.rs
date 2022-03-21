use std::{os::unix::prelude::AsRawFd, path::Path};

use pin_project::pin_project;
use socket2::Socket;
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
