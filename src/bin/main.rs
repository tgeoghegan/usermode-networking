use bytes::BytesMut;
use pretty_hex::pretty_hex;
use std::process;
use std::thread;

use usermode_networking::sockaddr_from_str;
use usermode_networking::udp::UdpSocket;

fn main() {
    let server_thread = thread::spawn(|| {
        println!("Creating server socket");
        let server_sock = match UdpSocket::bind("127.0.0.1:8080") {
            Ok(fd) => fd,
            Err(msg) => {
                println!("failed to create UDP socket: {}", msg);
                process::exit(1);
            }
        };

        println!("Server listening for messages...");
        loop {
            let mut buf = BytesMut::new();
            buf.resize(8, 0);
            match server_sock.recv_from(&mut buf) {
                Ok(count) => {
                    println!("read {} bytes from socket\n{}", count, pretty_hex(&buf));
                }
                Err(err) => {
                    println!("failed to read from socket: {}", err);
                    buf.resize(128, 0);
                    match server_sock.recv_from(&mut buf) {
                        Ok(count) => {
                            println!("read {} bytes from socket\n{}", count, pretty_hex(&buf));
                        }
                        Err(err) => {
                            println!("failed to read from socket: {}", err);
                        }
                    }

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
    let sock = match UdpSocket::bind(format!("127.0.0.1:{}", port).as_ref()) {
        Ok(fd) => fd,
        Err(err) => {
            println!("failed to create UDP socket: {}", err);
            process::exit(1);
        }
    };

    match sock.send_to(
        &mut BytesMut::from(&b"hello udp"[..]),
        &sockaddr_from_str("127.0.0.1:8080").unwrap(),
    ) {
        Ok(count) => {
            println!("wrote {} bytes to socket", count);
        }
        Err(err) => {
            println!("failed to write to socket: {}", err);
            process::exit(1);
        }
    }
}
