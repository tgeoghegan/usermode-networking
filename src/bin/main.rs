use bytes::{BytesMut};
use nix::sys::socket::recvfrom;
use std::process;

use usermode_networking::ip_packet::IpPacket;
use usermode_networking::*;

fn main() {
    println!("Creating socket");
    let sock = match create_raw_socket(SockProtocol::Udp) {
        Ok(fd) => fd,
        Err(msg) => {
            println!("failed to create raw socket: {}", msg);
            process::exit(1);
        }
    };

    println!("created a socket: {}. Listening for messages.", sock);

    loop {
    	let mut buf = BytesMut::new();
    	buf.resize(128, 0);
        match recvfrom(sock, buf.as_mut()) {
            Ok((count, sender_addr)) => {
                println!(
                    "read {} bytes from socket from sender {:?}",
                    count, sender_addr
                );
            }
            Err(err) => {
                println!("failed to read from socket: {}", err);
                process::exit(1);
            }
        }
        let packet = IpPacket::from_bytes(&buf.freeze()).unwrap();
        println!("{}", packet);
    }
}
