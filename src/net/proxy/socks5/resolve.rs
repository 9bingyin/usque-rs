use super::{Socks5Error, format_ip_addr, std_ip_to_smoltcp};
use crate::net::tunnel::manager::TunnelManager;
use fast_socks5::util::target_addr::TargetAddr;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::net::IpAddr;

pub(crate) async fn resolve_target_addr(
    manager: &TunnelManager,
    target: &TargetAddr,
) -> Result<(IpAddress, u16), Socks5Error> {
    match target {
        TargetAddr::Ip(addr) => Ok((std_ip_to_smoltcp(addr.ip()), addr.port())),
        TargetAddr::Domain(domain, port) => {
            log::debug!("resolving {} through tunnel", domain);
            let ip = manager.resolve(domain, true).await.map_err(|e| {
                Socks5Error::ProtocolError(format!("DNS resolution failed: {:?}", e))
            })?;
            log::debug!("resolved {} -> {}", domain, format_ip_addr(ip));
            Ok((ip, *port))
        }
    }
}

pub(crate) async fn target_addr_to_ip(
    target: &TargetAddr,
    manager: &TunnelManager,
) -> Option<(IpAddress, u16)> {
    match target {
        TargetAddr::Ip(addr) => {
            let ip = match addr.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    IpAddress::Ipv6(Ipv6Address::new(
                        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                    ))
                }
            };
            Some((ip, addr.port()))
        }
        TargetAddr::Domain(domain, port) => match manager.resolve(domain, true).await {
            Ok(ip) => Some((ip, *port)),
            Err(e) => {
                log::warn!("UDP DNS resolution failed for {}: {:?}", domain, e);
                None
            }
        },
    }
}
