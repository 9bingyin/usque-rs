use crate::tunnel::device::VirtualDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use thiserror::Error;

const DEFAULT_TCP_BUFFER_SIZE: usize = 1048576; // 1MB

#[derive(Error, Debug)]
pub enum StackError {
    #[error("socket error: {0}")]
    SocketError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct NetworkStack {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    local_ipv4: Option<Ipv4Address>,
    local_ipv6: Option<Ipv6Address>,
}

impl NetworkStack {
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
            local_ipv4,
            local_ipv6,
        }
    }

    pub fn poll(&mut self) -> bool {
        let timestamp = SmolInstant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
        }));
        if result.is_err() {
            log::error!("smoltcp poll panicked, recovering...");
            return false;
        }
        true
    }

    pub fn create_tcp_socket(&mut self) -> smoltcp::iface::SocketHandle {
        self.create_tcp_socket_with_buffer(DEFAULT_TCP_BUFFER_SIZE)
    }

    pub fn create_tcp_socket_with_buffer(&mut self, buffer_size: usize) -> smoltcp::iface::SocketHandle {
        let rx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let tx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
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

    pub fn inject_packet(&mut self, packet: &[u8]) {
        self.device.inject_packet(packet);
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.device.take_packet()
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
    ) -> Result<smoltcp::iface::SocketHandle, StackError> {
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

        Ok(self.sockets.add(socket))
    }

    // UDP socket methods for DNS resolution and UDP associate
    pub fn create_udp_socket_for(
        &mut self,
        local_port: u16,
        remote_ip: IpAddress,
    ) -> Result<smoltcp::iface::SocketHandle, StackError> {
        let local_addr = self.local_addr_for_remote(remote_ip)?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn create_udp_socket_default(
        &mut self,
        local_port: u16,
    ) -> Result<smoltcp::iface::SocketHandle, StackError> {
        let local_addr = self.local_addr_default()?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn udp_send(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        data: &[u8],
    ) -> Result<(), StackError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        let endpoint = IpEndpoint::new(remote_ip, remote_port);
        socket
            .send_slice(data, endpoint)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_recv(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        buf: &mut [u8],
    ) -> Result<(usize, UdpMetadata), StackError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_can_recv(&mut self, handle: smoltcp::iface::SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.can_recv()
    }
}
