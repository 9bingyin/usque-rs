use crate::tunnel::device::VirtualDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StackError {
    #[error("socket error: {0}")]
    SocketError(String),
    #[error("connection refused")]
    ConnectionRefused,
    #[error("timeout")]
    Timeout,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct NetworkStack {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    local_ipv4: Ipv4Address,
    local_ipv6: Option<Ipv6Address>,
}

impl NetworkStack {
    pub fn new(ipv4: &str, ipv6: Option<&str>, mtu: usize) -> Self {
        let mut device = VirtualDevice::new(mtu);

        let local_ipv4: Ipv4Address = ipv4.parse().unwrap_or(Ipv4Address::new(10, 0, 0, 1));
        let local_ipv6: Option<Ipv6Address> = ipv6.and_then(|s| s.parse().ok());

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        // Use the same device instance for Interface creation
        let mut iface = Interface::new(config, &mut device, Instant::now());

        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(local_ipv4), 32)).ok();
            if let Some(v6) = local_ipv6 {
                addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128)).ok();
            }
        });

        let sockets = SocketSet::new(vec![]);

        Self {
            device,
            iface,
            sockets,
            local_ipv4,
            local_ipv6,
        }
    }

    pub fn rx_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        self.device.rx_queue()
    }

    pub fn tx_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        self.device.tx_queue()
    }

    pub fn poll(&mut self) {
        let timestamp = Instant::now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
    }

    pub fn create_tcp_socket(&mut self) -> smoltcp::iface::SocketHandle {
        let rx_buffer = SocketBuffer::new(vec![0; 65535]);
        let tx_buffer = SocketBuffer::new(vec![0; 65535]);
        let socket = TcpSocket::new(rx_buffer, tx_buffer);
        self.sockets.add(socket)
    }

    pub fn connect_tcp(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<(), StackError> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        let cx = self.iface.context();
        socket
            .connect(cx, (remote_ip, remote_port), local_port)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_send(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        data: &[u8],
    ) -> Result<usize, StackError> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket
            .send_slice(data)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_recv(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, StackError> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_is_active(&mut self, handle: smoltcp::iface::SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.is_active()
    }

    pub fn tcp_may_send(&mut self, handle: smoltcp::iface::SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.may_send()
    }

    pub fn tcp_may_recv(&mut self, handle: smoltcp::iface::SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.may_recv()
    }

    pub fn tcp_close(&mut self, handle: smoltcp::iface::SocketHandle) {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
    }

    pub fn remove_socket(&mut self, handle: smoltcp::iface::SocketHandle) {
        self.sockets.remove(handle);
    }

    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.device.inject_packet(packet);
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.device.take_packet()
    }
}
