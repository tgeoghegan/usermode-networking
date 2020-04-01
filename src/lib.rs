use libc::{c_int, socket, PF_INET, SOCK_RAW};
use nix::sys::socket::{InetAddr, SockAddr};
use std::io::{Error, Result};
use std::net::{AddrParseError};

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
    }
    if sock == -1 {
        return Err(Error::last_os_error());
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
