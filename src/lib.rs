use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::Bytes;
use libc::{c_int, socket, PF_INET, SOCK_RAW};
use nix::errno::{errno, Errno};
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddrV4};

pub mod ip_packet;
pub mod udp_packet;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SockProtocol {
    Tcp = 253,
    Udp = 254,
}

pub fn create_raw_socket(protocol: SockProtocol) -> Result<c_int, &'static str> {
    // On macOS (and the BSDs it is derived from), IP packets whose protocol field is UDP or TCP
    // will never be passed to a SOCK_RAW socket (see https://sock-raw.org/papers/sock_raw), so for
    // our toy implementation, we use protocol numbers 253 and 254, for UDP and TCP, respectively,
    // which are reserved by RFC3692 for just this kind of "experimentation and testing".
    // The nix package provides a Rust-safe version of socket(2), but it won't let us specify any
    // protocol except Udp or Tcp (https://github.com/nix-rust/nix/issues/854). We work around this
    // by directly using the socket(2) provided by the libc crate, which takes a c_int for which we
    // can provide an arbitrary value. Fortunately, libc::socket returns an fd (as a c_int) which
    // can then be passed to nix's various functions that take file descriptors, since nix::RawFd is
    // just an alias to libc::c_int.
    let sock: c_int;
    println!("protocol: {}", protocol as c_int);
    unsafe {
        sock = socket(PF_INET, SOCK_RAW, protocol as c_int);
    }
    if sock == -1 {
        return Err("failed to create raw socket");
    }

    Ok(sock)
}
