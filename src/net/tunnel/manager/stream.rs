pub(crate) struct SocketStreamHandle {
    handle: SocketHandle,
    recv_buffer: TcpRingBuffer,
    recv_waker: futures::task::AtomicWaker,
    send_buffer: TcpRingBuffer,
    send_waker: futures::task::AtomicWaker,
    socket_dropped: std::sync::atomic::AtomicBool,
    socket_closed: std::sync::atomic::AtomicBool,
    read_closed: std::sync::atomic::AtomicBool,
    write_closed: std::sync::atomic::AtomicBool,
    write_shutdown: std::sync::atomic::AtomicBool,
    socket_notifier: tokio::sync::mpsc::UnboundedSender<SocketEvent>,
    read_event_queued: std::sync::atomic::AtomicBool,
    write_event_queued: std::sync::atomic::AtomicBool,
    close_event_queued: std::sync::atomic::AtomicBool,
}

impl SocketStreamHandle {
    fn new(
        handle: SocketHandle,
        send_capacity: usize,
        recv_capacity: usize,
        socket_notifier: tokio::sync::mpsc::UnboundedSender<SocketEvent>,
    ) -> Self {
        Self {
            handle,
            recv_buffer: TcpRingBuffer::new(recv_capacity + 1),
            recv_waker: futures::task::AtomicWaker::new(),
            send_buffer: TcpRingBuffer::new(send_capacity + 1),
            send_waker: futures::task::AtomicWaker::new(),
            socket_dropped: std::sync::atomic::AtomicBool::new(false),
            socket_closed: std::sync::atomic::AtomicBool::new(false),
            read_closed: std::sync::atomic::AtomicBool::new(false),
            write_closed: std::sync::atomic::AtomicBool::new(false),
            write_shutdown: std::sync::atomic::AtomicBool::new(false),
            socket_notifier,
            read_event_queued: std::sync::atomic::AtomicBool::new(false),
            write_event_queued: std::sync::atomic::AtomicBool::new(false),
            close_event_queued: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn notify_read_ready(&self) {
        if !self
            .read_event_queued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = self.socket_notifier.send(SocketEvent {
                handle: self.handle,
                kind: SocketEventKind::ReadReady,
            });
        }
    }

    fn notify_write_ready(&self) {
        if !self
            .write_event_queued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = self.socket_notifier.send(SocketEvent {
                handle: self.handle,
                kind: SocketEventKind::WriteReady,
            });
        }
    }

    fn notify_closed(&self) {
        if !self
            .close_event_queued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = self.socket_notifier.send(SocketEvent {
                handle: self.handle,
                kind: SocketEventKind::Closed,
            });
        }
    }

    fn clear_read_event(&self) {
        self.read_event_queued
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn clear_write_event(&self) {
        self.write_event_queued
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn clear_close_event(&self) {
        self.close_event_queued
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn clear_all_events(&self) {
        self.clear_read_event();
        self.clear_write_event();
        self.clear_close_event();
    }
}

pub struct SocketStream {
    pub handle: SocketHandle,
    control: std::sync::Arc<SocketStreamHandle>,
}

impl SocketStream {
    fn new(
        handle: SocketHandle,
        send_capacity: usize,
        recv_capacity: usize,
        socket_notifier: tokio::sync::mpsc::UnboundedSender<SocketEvent>,
    ) -> (Self, std::sync::Arc<SocketStreamHandle>) {
        let control = std::sync::Arc::new(SocketStreamHandle::new(
            handle,
            send_capacity,
            recv_capacity,
            socket_notifier,
        ));
        (
            Self {
                handle,
                control: control.clone(),
            },
            control,
        )
    }
}

impl Drop for SocketStream {
    fn drop(&mut self) {
        self.control
            .socket_dropped
            .store(true, std::sync::atomic::Ordering::Release);
        self.control
            .read_closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.control
            .write_closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.control.recv_waker.wake();
        self.control.send_waker.wake();
        self.control.notify_closed();
    }
}

impl tokio::io::AsyncRead for SocketStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let control = &self.control;

        if control.recv_buffer.is_empty() {
            control.recv_waker.register(cx.waker());
            if control.recv_buffer.is_empty() {
                if control
                    .socket_closed
                    .load(std::sync::atomic::Ordering::Acquire)
                    || control
                        .read_closed
                        .load(std::sync::atomic::Ordering::Acquire)
                {
                    return std::task::Poll::Ready(Ok(()));
                }
                return std::task::Poll::Pending;
            }
        }

        buf.initialize_unfilled();
        let recv_buf = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                buf.unfilled_mut(),
            )
        };
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);
        if n > 0 {
            control.notify_read_ready();
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for SocketStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let control = &self.control;

        if control
            .write_closed
            .load(std::sync::atomic::Ordering::Acquire)
            || control
                .write_shutdown
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "TCP stream write half closed",
            )));
        }

        if control.send_buffer.is_full() {
            control.send_waker.register(cx.waker());
            if control.send_buffer.is_full() {
                return std::task::Poll::Pending;
            }
        }

        let was_empty = control.send_buffer.is_empty();
        let n = control.send_buffer.enqueue_slice(buf);
        if was_empty && n > 0 {
            control.notify_write_ready();
        }
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.control.send_buffer.is_empty() {
            self.control.notify_write_ready();
            self.control.send_waker.register(cx.waker());
            if !self.control.send_buffer.is_empty() {
                return std::task::Poll::Pending;
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        if !self
            .control
            .write_shutdown
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.control.notify_write_ready();
        }
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod socket_stream_tests {
    use super::*;
    use futures::task::noop_waker_ref;
    use tokio::io::{AsyncRead, AsyncWrite};

    fn build_stream(
    ) -> (
        SocketStream,
        std::sync::Arc<SocketStreamHandle>,
        tokio::sync::mpsc::UnboundedReceiver<SocketEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (stream, control) = SocketStream::new(SocketHandle::default(), 16, 16, tx);
        (stream, control, rx)
    }

    fn noop_cx() -> std::task::Context<'static> {
        std::task::Context::from_waker(noop_waker_ref())
    }

    #[test]
    fn poll_read_returns_eof_after_peer_close() {
        let (mut stream, control, _rx) = build_stream();
        control
            .read_closed
            .store(true, std::sync::atomic::Ordering::Release);
        let mut cx = noop_cx();
        let mut bytes = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);

        let result = std::pin::Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
        assert_eq!(buf.filled().len(), 0);
    }

    #[test]
    fn poll_shutdown_marks_write_shutdown() {
        let (mut stream, control, _rx) = build_stream();
        let mut cx = noop_cx();

        let result = std::pin::Pin::new(&mut stream).poll_shutdown(&mut cx);

        assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
        assert!(
            control
                .write_shutdown
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn poll_write_fails_after_write_close() {
        let (mut stream, control, _rx) = build_stream();
        control
            .write_closed
            .store(true, std::sync::atomic::Ordering::Release);
        let mut cx = noop_cx();

        let result = std::pin::Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        assert!(
            matches!(result, std::task::Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn poll_write_only_notifies_on_empty_to_non_empty_transition() {
        let (mut stream, control, mut rx) = build_stream();
        let mut cx = noop_cx();

        let result = std::pin::Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, std::task::Poll::Ready(Ok(5))));
        assert!(matches!(
            rx.try_recv(),
            Ok(SocketEvent {
                kind: SocketEventKind::WriteReady,
                ..
            })
        ));

        control.clear_all_events();
        let result = std::pin::Pin::new(&mut stream).poll_write(&mut cx, b"world");
        assert!(matches!(result, std::task::Poll::Ready(Ok(5))));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn poll_read_notifies_after_each_consumption() {
        let (mut stream, control, mut rx) = build_stream();
        let mut cx = noop_cx();

        assert_eq!(control.recv_buffer.enqueue_slice(b"0123456789ab"), 12);
        let mut bytes = [0u8; 4];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);

        let result = std::pin::Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
        assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"0123");
        assert!(matches!(
            rx.try_recv(),
            Ok(SocketEvent {
                kind: SocketEventKind::ReadReady,
                ..
            })
        ));

        control.clear_all_events();
        let mut bytes = [0u8; 4];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        let result = std::pin::Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
        assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"4567");
        assert!(matches!(
            rx.try_recv(),
            Ok(SocketEvent {
                kind: SocketEventKind::ReadReady,
                ..
            })
        ));
    }

    #[test]
    fn poll_flush_waits_until_send_buffer_is_empty() {
        let (mut stream, control, mut rx) = build_stream();
        let mut cx = noop_cx();

        let write_result = std::pin::Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(write_result, std::task::Poll::Ready(Ok(5))));
        let _ = rx.try_recv();
        control.clear_all_events();

        let flush_result = std::pin::Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(matches!(flush_result, std::task::Poll::Pending));
        assert!(matches!(
            rx.try_recv(),
            Ok(SocketEvent {
                kind: SocketEventKind::WriteReady,
                ..
            })
        ));

        control.send_buffer.consume(5);
        control.send_waker.wake();
        control.clear_all_events();

        let flush_result = std::pin::Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(matches!(flush_result, std::task::Poll::Ready(Ok(()))));
    }
}
