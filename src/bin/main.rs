use bytes::{Bytes, BytesMut};
use nix::sys::socket::{bind, recvfrom, sendto, MsgFlags};
use std::process;
use std::thread;

use usermode_networking::{create_raw_socket, sockaddr_from_str, SockProtocol};
use usermode_networking::ip::IpPacket;
use usermode_networking::udp::UdpPacket;

fn main() {
    let server_thread = thread::spawn(|| {
        println!("Creating server socket");
        let sock = match create_raw_socket(SockProtocol::Udp) {
            Ok(fd) => fd,
            Err(msg) => {
                println!("failed to create raw socket: {}", msg);
                process::exit(1);
            }
        };

        if let Err(err) = bind(sock, &sockaddr_from_str("127.0.0.1:8080").unwrap()) {
            println!("failed to bind socket: {}", err);
            process::exit(1);
        }

        println!("Server listening for messages...");
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
            return IpPacket::from_bytes(&buf.freeze()).unwrap();
        }
    });

    println!("Creating client socket");
    let sock = match create_raw_socket(SockProtocol::Udp) {
        Ok(fd) => fd,
        Err(msg) => {
            println!("failed to create raw socket: {}", msg);
            process::exit(1);
        }
    };

    if let Err(err) = bind(sock, &sockaddr_from_str("192.168.86.21:8081").unwrap()) {
        println!("failed to bind socket: {}", err);
        process::exit(1);
    }

    let message = UdpPacket::new(9000, 8080, Bytes::from_static(b"hello udp"));
    let mut buf = BytesMut::with_capacity(128);
    if let Err(err) = message.into_bytes(&mut buf) {
        println!("failed to serialize UDP packet into buf: {}", err);
        process::exit(1);
    }
    match sendto(sock, buf.as_mut(), &sockaddr_from_str("127.0.0.1:8080").unwrap(), MsgFlags::empty()) {
        Ok(count) => {
            println!("wrote {} bytes to socket", count);
        }
        Err(err) => {
            println!("failed to write to socket: {}", err);
            process::exit(1);
        }
    }

    let packet = match server_thread.join() {
        Ok(packet) => { packet }
        Err(_) => {
            println!("thread panicked");
            process::exit(1);
        }
    };

    println!("Server got IP packet: {}", packet);

    let received_message = match UdpPacket::from_bytes(&packet.data) {
        Ok(p) => { p }
        Err(err) => {
            println!("failed to parse UDP packet: {}", err);
            process::exit(1);
        }
    };
    println!("Server got datagram: {}", received_message);
}
