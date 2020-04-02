use bytes::{Bytes, BytesMut};
use nix::sys::socket::{bind, sendto, Ipv4Addr, MsgFlags};
use pretty_hex::pretty_hex;
use std::process;
use std::thread;

use usermode_networking::{create_raw_socket, sockaddr_from_str, SockProtocol};
use usermode_networking::udp::{UdpPacket, UdpSocket};

fn main() {
    let server_thread = thread::spawn(|| {
        println!("Creating server socket");
        let server_sock = match UdpSocket::bind("127.0.0.1:8080") {
            Ok(fd) => fd,
            Err(msg) => {
                println!("failed to create raw socket: {}", msg);
                process::exit(1);
            }
        };

        println!("Server listening for messages...");
        loop {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            match server_sock.recv_from(&mut buf) {
                Ok(count) => {
                    println!("read {} bytes from socket", count);
                    pretty_hex(&buf);
                }
                Err(err) => {
                    println!("failed to read from socket: {}", err);
                    process::exit(1);

                }
            }
        }
    });

    send_from_port(8080);
    send_from_port(8081);

    if let Err(_) = server_thread.join() {
        println!("thread panicked");
        process::exit(1);
    }
}

fn send_from_port(port: u16) {
    println!("Creating client socket");
    let sock = match create_raw_socket(SockProtocol::Udp) {
        Ok(fd) => fd,
        Err(msg) => {
            println!("failed to create raw socket: {}", msg);
            process::exit(1);
        }
    };

    if let Err(err) = bind(sock, &sockaddr_from_str(format!("127.0.0.1:{}", port).as_str()).unwrap()) {
        println!("failed to bind socket: {}", err);
        process::exit(1);
    }
    println!("client socket {}", sock);

    let message = Bytes::from_static(b"hello udp");

    let mut header = UdpPacket {
        source: port,
        destination: 8080,
        length: message.len() as u16 + 8,
        checksum: 0,
    };

    header.fill_checksum(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 1), message.as_ref());

    let mut header_buf = BytesMut::with_capacity(8);
    header_buf.resize(8, 0);
    if let Err(err) = header.into_bytes(&mut header_buf) {
        println!("failed to serialize UDP packet into buf: {}", err);
        process::exit(1);
    }
    match sendto(sock, header_buf.as_ref(), &sockaddr_from_str("127.0.0.1:8080").unwrap(), MsgFlags::empty()) {
        Ok(count) => {
            println!("wrote {} header bytes to socket", count);
        }
        Err(err) => {
            println!("failed to write header to socket: {}", err);
            process::exit(1);
        }
    }
    match sendto(sock, message.as_ref(), &sockaddr_from_str("127.0.0.1:8080").unwrap(), MsgFlags::empty()) {
        Ok(count) => {
            println!("wrote {} body bytes to socket", count);
        }
        Err(err) => {
            println!("failed to write body to socket: {}", err);
            process::exit(1);
        }
    }
}
