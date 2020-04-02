use libc::{c_int, socket, socklen_t, IPPROTO_IP, PF_INET, SOCK_RAW};
use nix::sys::socket::{InetAddr, IpAddr, Ipv4Addr, SockAddr};
use std::io::{Error, ErrorKind, Result};
use std::net::{AddrParseError};
use std::mem::size_of;

pub mod ip;
pub mod udp;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SockProtocol {
    Tcp = 253,
    Udp = 254,
}

pub fn create_raw_socket(protocol: SockProtocol) -> Result<c_int> {
    // See README.md for discussion of SOCK_RAW on macOS
    // The nix package provides a Rust-safe version of socket(2), but it won't let us specify any
    // protocol except Udp or Tcp (https://github.com/nix-rust/nix/issues/854). We work around this
    // by directly using the socket(2) provided by the libc crate, which takes a c_int for which we
    // can provide an arbitrary value. Fortunately, libc::socket returns an fd (as a c_int) which
    // can then be passed to nix's various functions that take file descriptors, since nix::RawFd is
    // just an alias to libc::c_int.
    let sock: c_int;
    unsafe {
        sock = socket(PF_INET, SOCK_RAW, protocol as c_int);
        if sock == -1 {
            return Err(Error::last_os_error());
        }
        // We don't want anything from the IP headers, and dealing with their variable length is a
        // hassle, so instruct the kernel not to give them to us. Once again nix has a nice
        // setsockopt(2), but it doesn't provide an implementation of the SetSockOpt trait for
        // IP_STRIPHDR, and since that trait implementation would amount to a call to
        // libc::SetSockOptanyway, we can just do that directly here. Crate libc doesn't expose the
        // macOS-specific IP_STRIPHDR, so we provide its value from /usr/include/netinet/in.h.
        let val: c_int = 1;
        let res = libc::setsockopt(sock, IPPROTO_IP, 23,
            &val as *const c_int as *const libc::c_void, size_of::<c_int>() as socklen_t);
        if res != 0 {
            return Err(Error::last_os_error());
        }
    }



    Ok(sock)
}

/// Parse a string like "127.0.0.1:8080" into a nix::sys::socket::SockAddr suitable for use with
/// functions like nix::sys::socket::bind or nix::sys::socket::sendto.
/// Ideally this would be an implementation of FromStr for SockAddr, but this is not permitted as
/// neither FromStr or SockAddr are implemented in this crate.
pub fn sockaddr_from_str(s: &str) -> std::result::Result<SockAddr, AddrParseError> {
    Ok(SockAddr::new_inet(InetAddr::from_std(&s.parse()?)))
}


// Decompose a SockAddr into an Ipv4Addr and a port number, if the SockAddr is a Inet IPv4 address
// and raise an error otherwise. This is probably a bit too clever.
pub fn ipv4_and_port_from_sockaddr(sockaddr: SockAddr) -> Result<(u16, Ipv4Addr)> {
    Ok(if let SockAddr::Inet(inetaddr) = sockaddr {
        (inetaddr.port(), if let IpAddr::V4(ipv4addr) = inetaddr.ip() {
            ipv4addr
        } else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("IP address {} is not v4", sockaddr)));
        })
    } else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("address {} is not an Inet address", sockaddr)));
    })
}
