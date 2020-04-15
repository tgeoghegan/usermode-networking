use bytes::BytesMut;
use std::thread;

use usermode_networking::sockaddr_from_str;
use usermode_networking::udp::UdpSocket;

#[test]
fn retry_when_receive_buffer_too_small() {
    let server_thread = thread::spawn(|| {
        let server_sock = UdpSocket::bind("127.0.0.1:8080").unwrap();

        loop {
            let mut buf = BytesMut::new();
            // Make buffer too small for message. First read should fail, then
            // succeed once resized buffer is provided.
            buf.resize(8, 0);
            server_sock.recv_from(&mut buf).unwrap_err();
            buf.resize(128, 0);
            let len = server_sock.recv_from(&mut buf).unwrap();
            assert_eq!(buf.as_ref()[..len], b"hello udp"[..]);
            break;
        }
    });

    let sock = UdpSocket::bind("127.0.0.1:8080").unwrap();
    sock.send_to(
        &mut BytesMut::from(&b"hello udp"[..]),
        &sockaddr_from_str("127.0.0.1:8080").unwrap(),
    ).unwrap();

    server_thread.join().unwrap()
}

#[test]
fn reject_messages_for_other_port() {
    let server_thread = thread::spawn(|| {
        let server_sock_8080 = UdpSocket::bind("127.0.0.1:8080").unwrap();
        let server_sock_8081 = UdpSocket::bind("127.0.0.1:8081").unwrap();

        loop {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            let len = server_sock_8080.recv_from(&mut buf).unwrap();
            assert_eq!(buf.as_ref()[..len], b"hello 8080"[..]);
            let len = server_sock_8081.recv_from(&mut buf).unwrap();
            assert_eq!(buf.as_ref()[..len], b"hello 8081"[..]);
            break;
        }
    });

    let sock = UdpSocket::bind("127.0.0.1:8082").unwrap();
    sock.send_to(
        &mut BytesMut::from(&b"hello 8081"[..]),
        &sockaddr_from_str("127.0.0.1:8081").unwrap(),
    ).unwrap();
    sock.send_to(
        &mut BytesMut::from(&b"hello 8080"[..]),
        &sockaddr_from_str("127.0.0.1:8080").unwrap(),
    ).unwrap();

    server_thread.join().unwrap()
}
