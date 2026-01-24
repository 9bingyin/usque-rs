use crate::tunnel::device::VirtualDevice;
use bytes::BytesMut;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{Socket, tcp::{Socket as TcpSocket, SocketBuffer}};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StackError {
    #[error("socket error: {0}")]
    SocketError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("smoltcp poll panicked")]
    PollPanic,
}

pub struct NetworkStack {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    valid_handles: HashSet<SocketHandle>,
    local_ipv4: Option<Ipv4Address>,
    local_ipv6: Option<Ipv6Address>,
}

impl NetworkStack {
    fn socket_snapshot(&self) -> String {
        const MAX_TCP_DETAILS: usize = 16;
        let mut total = 0usize;
        let mut tcp_count = 0usize;
        let mut udp_count = 0usize;
        let mut tcp_details = Vec::new();

        for (handle, socket) in self.sockets.iter() {
            total += 1;
            match socket {
                Socket::Tcp(sock) => {
                    tcp_count += 1;
                    if tcp_details.len() < MAX_TCP_DETAILS {
                        tcp_details.push(format!(
                            "{} state={:?} local={:?} remote={:?} tx={} rx={}",
                            handle,
                            sock.state(),
                            sock.local_endpoint(),
                            sock.remote_endpoint(),
                            sock.send_queue(),
                            sock.recv_queue()
                        ));
                    }
                }
                Socket::Udp(_) => {
                    udp_count += 1;
                }
                _ => {}
            }
        }

        let mut snapshot = format!(
            "local_ipv4={:?} local_ipv6={:?} sockets: total={}, tcp={}, udp={}",
            self.local_ipv4, self.local_ipv6, total, tcp_count, udp_count
        );

        if !tcp_details.is_empty() {
            snapshot.push_str("; tcp=[");
            snapshot.push_str(&tcp_details.join(", "));
            snapshot.push(']');
            if tcp_count > MAX_TCP_DETAILS {
                snapshot.push_str(" (truncated)");
            }
        }

        snapshot
    }

    pub fn new(ipv4: Option<&str>, ipv6: Option<&str>, mtu: usize) -> Self {
        let mut device = VirtualDevice::new(mtu);

        let mut local_ipv4 = match ipv4.filter(|s| !s.trim().is_empty()) {
            Some(s) => match s.parse() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    log::warn!("Invalid IPv4 address '{}': {}", s, e);
                    Some(Ipv4Address::new(10, 0, 0, 1))
                }
            },
            None => None,
        };
        let local_ipv6: Option<Ipv6Address> = ipv6
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| match s.parse() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    log::warn!("Invalid IPv6 address '{}': {}", s, e);
                    None
                }
            });

        if local_ipv4.is_none() && local_ipv6.is_none() {
            log::warn!("No valid IP addresses configured, using fallback IPv4 10.0.0.1");
            local_ipv4 = Some(Ipv4Address::new(10, 0, 0, 1));
        }

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        // Use the same device instance for Interface creation
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = local_ipv4 {
                addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32)).ok();
            }
            if let Some(v6) = local_ipv6 {
                addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128)).ok();
            }
        });

        let sockets = SocketSet::new(vec![]);

        Self {
            device,
            iface,
            sockets,
            valid_handles: HashSet::new(),
            local_ipv4,
            local_ipv6,
        }
    }

    pub fn poll(&mut self) -> Result<(), StackError> {
        let timestamp = SmolInstant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
        }));
        if result.is_err() {
            log::error!("smoltcp poll panicked, snapshot: {}", self.socket_snapshot());
            return Err(StackError::PollPanic);
        }
        Ok(())
    }

    fn get_tcp_socket_mut(&mut self, handle: SocketHandle) -> Option<&mut TcpSocket<'static>> {
        if self.valid_handles.contains(&handle) {
            Some(self.sockets.get_mut::<TcpSocket>(handle))
        } else {
            None
        }
    }

    fn get_udp_socket_mut(&mut self, handle: SocketHandle) -> Option<&mut UdpSocket<'static>> {
        if self.valid_handles.contains(&handle) {
            Some(self.sockets.get_mut::<UdpSocket>(handle))
        } else {
            None
        }
    }

    pub fn create_tcp_socket_with_buffer(&mut self, buffer_size: usize) -> SocketHandle {
        let rx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let tx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let handle = self.sockets.add(socket);
        self.valid_handles.insert(handle);
        handle
    }

    pub fn connect_tcp(
        &mut self,
        handle: SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<(), StackError> {
        if !self.valid_handles.contains(&handle) {
            return Err(StackError::SocketError("invalid socket handle".into()));
        }
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket
            .connect(cx, (remote_ip, remote_port), local_port)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_send(
        &mut self,
        handle: SocketHandle,
        data: &[u8],
    ) -> Result<usize, StackError> {
        let socket = self.get_tcp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .send_slice(data)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, StackError> {
        let socket = self.get_tcp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_is_active(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.is_active())
            .unwrap_or(false)
    }

    pub fn tcp_may_send(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.may_send())
            .unwrap_or(false)
    }

    pub fn tcp_may_recv(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.may_recv())
            .unwrap_or(false)
    }

    pub fn tcp_close(&mut self, handle: SocketHandle) {
        if let Some(socket) = self.get_tcp_socket_mut(handle) {
            socket.close();
        }
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        if self.valid_handles.remove(&handle) {
            self.sockets.remove(handle);
        }
    }

    pub fn inject_packet(&mut self, packet: &[u8]) {
        self.device.inject_packet(packet);
    }

    pub fn take_packet(&mut self) -> Option<BytesMut> {
        self.device.take_packet()
    }

    pub fn recycle_tx_buffer(&mut self, buf: BytesMut) {
        self.device.recycle_tx_buffer(buf);
    }

    fn local_addr_for_remote(&self, remote_ip: IpAddress) -> Result<IpAddress, StackError> {
        match remote_ip {
            IpAddress::Ipv4(_) => self.local_ipv4
                .map(IpAddress::Ipv4)
                .ok_or_else(|| StackError::SocketError("No IPv4 address configured".into())),
            IpAddress::Ipv6(_) => self.local_ipv6
                .map(IpAddress::Ipv6)
                .ok_or_else(|| StackError::SocketError("No IPv6 address configured".into())),
        }
    }

    fn local_addr_default(&self) -> Result<IpAddress, StackError> {
        if let Some(v4) = self.local_ipv4 {
            return Ok(IpAddress::Ipv4(v4));
        }
        if let Some(v6) = self.local_ipv6 {
            return Ok(IpAddress::Ipv6(v6));
        }
        Err(StackError::SocketError("No IP address configured".into()))
    }

    fn bind_udp_socket(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
    ) -> Result<SocketHandle, StackError> {
        let rx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 16],
            vec![0; 8192],
        );
        let tx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 16],
            vec![0; 8192],
        );
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);

        let local_endpoint = IpEndpoint::new(local_addr, local_port);
        socket
            .bind(local_endpoint)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))?;

        let handle = self.sockets.add(socket);
        self.valid_handles.insert(handle);
        Ok(handle)
    }

    // UDP socket methods for DNS resolution and UDP associate
    pub fn create_udp_socket_for(
        &mut self,
        local_port: u16,
        remote_ip: IpAddress,
    ) -> Result<SocketHandle, StackError> {
        let local_addr = self.local_addr_for_remote(remote_ip)?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn create_udp_socket_default(
        &mut self,
        local_port: u16,
    ) -> Result<SocketHandle, StackError> {
        let local_addr = self.local_addr_default()?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn udp_send(
        &mut self,
        handle: SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        data: &[u8],
    ) -> Result<(), StackError> {
        let socket = self.get_udp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        let endpoint = IpEndpoint::new(remote_ip, remote_port);
        socket
            .send_slice(data, endpoint)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<(usize, UdpMetadata), StackError> {
        let socket = self.get_udp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_can_recv(&mut self, handle: SocketHandle) -> bool {
        self.get_udp_socket_mut(handle)
            .map(|s| s.can_recv())
            .unwrap_or(false)
    }
}
