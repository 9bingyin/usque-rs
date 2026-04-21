// SPSC ring buffer modeled after clash-rs netstack. The proxy task is the
// producer on one side and the manager loop is the consumer on the other.
struct TcpRingBuffer {
    buffer: std::cell::UnsafeCell<Box<[u8]>>,
    capacity: usize,
    write_pos: std::sync::atomic::AtomicUsize,
    read_pos: std::sync::atomic::AtomicUsize,
}

unsafe impl Send for TcpRingBuffer {}
unsafe impl Sync for TcpRingBuffer {}

impl TcpRingBuffer {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(2);
        Self {
            buffer: std::cell::UnsafeCell::new(vec![0u8; capacity].into_boxed_slice()),
            capacity,
            write_pos: std::sync::atomic::AtomicUsize::new(0),
            read_pos: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn len(&self) -> usize {
        let read_pos = self.read_pos.load(std::sync::atomic::Ordering::Acquire);
        let write_pos = self.write_pos.load(std::sync::atomic::Ordering::Acquire);
        if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        }
    }

    fn is_empty(&self) -> bool {
        self.read_pos.load(std::sync::atomic::Ordering::Acquire)
            == self.write_pos.load(std::sync::atomic::Ordering::Acquire)
    }

    fn is_full(&self) -> bool {
        self.remaining_capacity() == 0
    }

    fn remaining_capacity(&self) -> usize {
        self.capacity - self.len() - 1
    }

    fn enqueue_slice(&self, data: &[u8]) -> usize {
        let write_pos = self.write_pos.load(std::sync::atomic::Ordering::Relaxed);
        let to_write = data.len().min(self.remaining_capacity());
        if to_write == 0 {
            return 0;
        }

        unsafe {
            let buffer = &mut *self.buffer.get();
            let first = to_write.min(self.capacity - write_pos);
            buffer[write_pos..write_pos + first].copy_from_slice(&data[..first]);

            let second = to_write - first;
            if second > 0 {
                buffer[..second].copy_from_slice(&data[first..first + second]);
            }
        }

        let new_write_pos = (write_pos + to_write) % self.capacity;
        self.write_pos
            .store(new_write_pos, std::sync::atomic::Ordering::Release);
        to_write
    }

    fn dequeue_slice(&self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.len());
        if to_read == 0 {
            return 0;
        }

        let read_pos = self.read_pos.load(std::sync::atomic::Ordering::Relaxed);
        unsafe {
            let buffer = &*self.buffer.get();
            let first = to_read.min(self.capacity - read_pos);
            dst[..first].copy_from_slice(&buffer[read_pos..read_pos + first]);

            let second = to_read - first;
            if second > 0 {
                dst[first..first + second].copy_from_slice(&buffer[..second]);
            }
        }

        let new_read_pos = (read_pos + to_read) % self.capacity;
        self.read_pos
            .store(new_read_pos, std::sync::atomic::Ordering::Release);
        to_read
    }

    fn peek_copy(&self, dst: &mut [u8]) -> usize {
        let read_pos = self.read_pos.load(std::sync::atomic::Ordering::Acquire);
        let write_pos = self.write_pos.load(std::sync::atomic::Ordering::Acquire);
        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        };
        let to_read = dst.len().min(available);
        if to_read == 0 {
            return 0;
        }

        unsafe {
            let buffer = &*self.buffer.get();
            let first = to_read.min(self.capacity - read_pos);
            dst[..first].copy_from_slice(&buffer[read_pos..read_pos + first]);

            let second = to_read - first;
            if second > 0 {
                dst[first..first + second].copy_from_slice(&buffer[..second]);
            }
        }

        to_read
    }

    fn consume(&self, count: usize) {
        let available = self.len();
        let count = count.min(available);
        if count == 0 {
            return;
        }

        let read_pos = self.read_pos.load(std::sync::atomic::Ordering::Relaxed);
        let new_read_pos = (read_pos + count) % self.capacity;
        self.read_pos
            .store(new_read_pos, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tcp_ring_buffer_tests {
    use super::TcpRingBuffer;

    #[test]
    fn ring_buffer_wraps_without_losing_order() {
        let buf = TcpRingBuffer::new(8);
        let mut out = [0u8; 8];

        assert_eq!(buf.enqueue_slice(b"abcdef"), 6);
        assert_eq!(buf.dequeue_slice(&mut out[..4]), 4);
        assert_eq!(&out[..4], b"abcd");

        assert_eq!(buf.enqueue_slice(b"ghij"), 4);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.dequeue_slice(&mut out[..6]), 6);
        assert_eq!(&out[..6], b"efghij");
        assert!(buf.is_empty());
    }

    #[test]
    fn ring_buffer_peek_and_consume_match_dequeue() {
        let buf = TcpRingBuffer::new(8);
        let mut out = [0u8; 8];
        let mut peek = [0u8; 3];

        buf.enqueue_slice(b"hello");
        assert_eq!(buf.peek_copy(&mut peek), 3);
        assert_eq!(&peek, b"hel");
        buf.consume(3);
        assert_eq!(buf.dequeue_slice(&mut out[..2]), 2);
        assert_eq!(&out[..2], b"lo");
        assert!(buf.is_empty());
    }

    #[test]
    fn ring_buffer_respects_capacity() {
        let buf = TcpRingBuffer::new(4);
        let mut out = [0u8; 8];

        assert_eq!(buf.enqueue_slice(b"abcdef"), 3);
        assert_eq!(buf.remaining_capacity(), 0);
        assert_eq!(buf.dequeue_slice(&mut out), 3);
        assert_eq!(&out[..3], b"abc");
    }
}
