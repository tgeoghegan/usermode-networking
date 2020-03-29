use nix::sys::socket::{
    bind, socket, AddressFamily, InetAddr, IpAddr, SockAddr, SockFlag, SockProtocol, SockType,
};
use nix::unistd::read;
use std::process;

fn main() {
    println!("Creating socket");
    let sock = socket(
        AddressFamily::Inet,
        SockType::Raw,
        SockFlag::empty(),
        None
    );
    let fd = match sock {
        Ok(fd) => fd,
        Err(err) => {
            println!("failed to create datagram socket: {}", err);
            process::exit(1);
        }
    };

    println!("created a socket: {}", fd);

    println!("listening on 127.0.0.1:8080");
    if let Err(err) = bind(
        fd,
        &SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), 8080)),
    ) {
        println!("failed to bind socket: {}", err);
        process::exit(1);
    }

    let mut buffer = [0u8; 1024];
    match read(fd, &mut buffer) {
        Ok(count) => {
            println!("read {} bytes from socket", count);
            println!("{}", String::from_utf8_lossy(&buffer));
        }
        Err(err) => {
            println!("failed to read from socket: {}", err);
            process::exit(1);
        }
    }

    println!("all done!");
}
