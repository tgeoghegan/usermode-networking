use byteorder::{ByteOrder, NativeEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::BytesMut;
use internet_checksum::Checksum;
use nix::sys::socket::{bind, recvfrom, sendto, InetAddr, IpAddr, Ipv4Addr, MsgFlags, SockAddr};
use nix::unistd::close;
use std::fmt;
use std::io::{Cursor, Error, ErrorKind, Result};
use std::os::unix::io::RawFd;

use crate::{create_raw_socket, ipv4_and_port_from_sockaddr, sockaddr_from_str, SockProtocol};

const UDP_HEADER_LENGTH: usize = 8;

pub struct UdpSocket {
    bound_address: Ipv4Addr,
    bound_port: u16,
    socket: RawFd,
}

impl UdpSocket {
    pub fn bind(addr: &str) -> Result<UdpSocket> {
        let sock = create_raw_socket(SockProtocol::Udp)?;
        let sockaddr = match sockaddr_from_str(addr) {
            Ok(s) => s,
            Err(err) => {
                return Err(Error::new(ErrorKind::InvalidInput, err));
            }
        };

        // The port does nothing in the bind(2) call, but we need it at our level to appropriately
        // filter packets.
        let (bound_port, bound_address) = ipv4_and_port_from_sockaddr(&sockaddr)?;

        if let Err(err) = bind(sock, &sockaddr) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to bind(2) to {}: {}", addr, err),
            ));
        }

        Ok(UdpSocket {
            bound_address,
            bound_port,
            socket: sock,
        })
    }

    pub fn recv_from(&self, buf: &mut BytesMut) -> Result<usize> {
        let mut packet_buf = BytesMut::with_capacity(UDP_HEADER_LENGTH);
        packet_buf.resize(packet_buf.capacity(), 0);

        loop {
            // The kernel will only send us IP packets that match our protocol, and we assume it
            // will handle reassembling IP packets for us. Read in the fixed-length UDP header so we
            // can figure out how big the whole message is.
            let sender_addr = match recvfrom(self.socket, packet_buf.as_mut()) {
                Ok((count, _)) if count < packet_buf.len() => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "short read while fetching header",
                    ));
                }
                Ok((_, None)) => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "no sender address found",
                    ));
                }
                Ok((_, Some(sender_addr))) => sender_addr,
                Err(err) => {
                    return Err(Error::new(ErrorKind::Other, err));
                }
            };

            // The IP protocol level sockaddr won't have a meaningful port, so drop that value
            let (_, sender_ipv4_addr) = ipv4_and_port_from_sockaddr(&sender_addr)?;

            let udp_header = UdpPacket::from_bytes(&packet_buf)?;

            let mut to_read = udp_header.data_length();

            // Check whether this UDP datagram is for our bound port. If it's not, we seek past this
            // message looking for more UDP headers. As far as I can tell, there's no risk to consuming
            // packets not intended for this socket, as any other sockets bound to the same IP will get
            // all the packets anyway.
            if udp_header.destination == self.bound_port {
                if to_read > buf.len() {
                    // XXX client will want to try again with a bigger buffer, but we have already
                    // moved the stream past the header, so subsequent reads will fail, unless we
                    // somehow hold on to the header to reuse in next recv_from call.
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "message too big for buffer",
                    ));
                }
            }

            // Kinda sketchy: we want to skip this UDP packet, but to do that we have to read bytes
            // from the socket and put them *somewhere*. So we will use the caller provided buffer,
            // possibly more than once if the packet being skipped is bigger than that buffer!
            while to_read > 0 {
                let mut slice = buf.split_off(udp_header.data_length() - to_read);
                to_read -= match recvfrom(self.socket, slice.as_mut()) {
                    Ok((count, _)) => count,
                    Err(err) => {
                        return Err(Error::new(ErrorKind::Other, err));
                    }
                };
                buf.unsplit(slice);
            }

            if udp_header.destination == self.bound_port {
                udp_header.verify_checksum(sender_ipv4_addr, self.bound_address, buf)?;
                break Ok(udp_header.data_length());
            }
        }
    }

    pub fn send_to(&self, buf: &mut BytesMut, dest: &SockAddr) -> Result<usize> {
        let packet_len = buf.len() + UDP_HEADER_LENGTH;
        if packet_len > std::u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidInput, "message too long"));
        }

        let (dest_port, dest_address) = ipv4_and_port_from_sockaddr(dest)?;
        let mut header = UdpPacket {
            source: self.bound_port,
            destination: dest_port,
            length: packet_len as u16,
            checksum: 0,
        };

        header.fill_checksum(self.bound_address, dest_address, buf.as_ref());

        let mut header_buf = BytesMut::with_capacity(UDP_HEADER_LENGTH);
        header_buf.resize(header_buf.capacity(), 0);
        header.into_bytes(&mut header_buf)?;

        match sendto(self.socket, header_buf.as_ref(), dest, MsgFlags::empty()) {
            Ok(count) if count < header_buf.len() => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "short write when writing header",
                ));
            }
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to write to socket: {}", err),
                ));
            }
            Ok(_) => (),
        }

        let mut to_write = buf.len();

        while to_write > 0 {
            let slice = buf.split_off(buf.len() - to_write);
            to_write -= match sendto(self.socket, slice.as_ref(), dest, MsgFlags::empty()) {
                Ok(count) => count,
                Err(err) => {
                    return Err(Error::new(ErrorKind::Other, err));
                }
            };
            buf.unsplit(slice);
        }
        Ok(buf.len())
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        close(self.socket).unwrap();
    }
}

/// An individual UDP datagram. Specified according to RFC 768.
///
///  0      7 8     15 16    23 24    31
/// +--------+--------+--------+--------+
/// |     Source      |   Destination   |
/// |      Port       |      Port       |
/// +--------+--------+--------+--------+
/// |                 |                 |
/// |     Length      |    Checksum     |
/// +--------+--------+--------+--------+
/// |
/// |          data octets ...
/// +---------------- ...
#[derive(Debug)]
pub struct UdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpPacket {
    // XXX reimplement this as try_from<&Bytes>
    // XXX should take a plain Bytes, but that causes headaches for callers who cannot make their
    // a buffer mutable again if they've called freeze() on it.
    // (https://github.com/tokio-rs/bytes/issues/350)
    pub fn from_bytes(bytes: &BytesMut) -> Result<UdpPacket> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "packet is not long enough",
            ));
        }
        if bytes.len() > std::u16::MAX as usize {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "buffer is too big for legal UDP packet",
            ));
        }

        // We use a std::io::Cursor to provide std::io::Read on our buf, which is required for the
        // ReadBytesExt trait to apply.
        let mut cursor = Cursor::new(bytes);

        Ok(UdpPacket {
            source: cursor.read_u16::<NetworkEndian>()?,
            destination: cursor.read_u16::<NetworkEndian>()?,
            length: cursor.read_u16::<NetworkEndian>()?,
            checksum: cursor.read_u16::<NetworkEndian>()?,
        })
    }

    pub fn data_length(&self) -> usize {
        self.length() - UDP_HEADER_LENGTH
    }

    pub fn length(&self) -> usize {
        self.length as usize
    }

    pub fn into_bytes(&self, buf: &mut BytesMut) -> Result<()> {
        if buf.capacity() < UDP_HEADER_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "provided buffer is not long enough",
            ));
        }
        buf.resize(UDP_HEADER_LENGTH, 0);

        // This is odd: Cursor implements std::io::Read<T>, meaning we can use ReadBytesExt without
        // ceremony above. But it only provides std::io::Write<'_ mut [u8]>, so we have to get the
        // mutable u8 slice reference out of the BytesMut with core::convert::AsMut::as_mut<[u8]>.
        // But you'd think Cursor could implement std::io::Write<T: AsMut<[u8]>>.
        let mut cursor = Cursor::new(buf.as_mut());
        cursor.write_u16::<NetworkEndian>(self.source)?;
        cursor.write_u16::<NetworkEndian>(self.destination)?;
        cursor.write_u16::<NetworkEndian>(self.length as u16)?;
        cursor.write_u16::<NetworkEndian>(self.checksum)?;

        Ok(())
    }

    pub fn verify_checksum(
        &self,
        source_address: Ipv4Addr,
        dest_address: Ipv4Addr,
        data: &[u8],
    ) -> Result<()> {
        if self.checksum == self.compute_checksum(source_address, dest_address, data) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("incorrect UDP checksum {}", self.checksum),
            ))
        }
    }

    pub fn fill_checksum(&mut self, source_address: Ipv4Addr, dest_address: Ipv4Addr, data: &[u8]) {
        self.checksum = self.compute_checksum(source_address, dest_address, data);
    }

    pub fn compute_checksum(
        &self,
        source_address: Ipv4Addr,
        dest_address: Ipv4Addr,
        data: &[u8],
    ) -> u16 {
        let mut c = Checksum::new();
        // Feed in pseudo-header: source address (4 bytes), dest address (4 bytes), one zero byte,
        // protocol number (1 byte), UDP packet length (2 bytes)
        c.add_bytes(&source_address.octets());
        c.add_bytes(&dest_address.octets());
        c.add_bytes(&[0u8]);
        c.add_bytes(&[SockProtocol::Udp as u8]);
        c.add_bytes(&[((self.length as u16 & 0xff00) >> 4) as u8]);
        c.add_bytes(&[(self.length as u16 & 0x00ff) as u8]);
        c.add_bytes(data);

        NativeEndian::read_u16(&c.checksum())
    }
}

impl fmt::Display for UdpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Source port: {}\nDestination port: {}\nLength: {}\nChecksum: {}",
            self.source, self.destination, self.length, self.checksum
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_packet() {
        let raw_packet: &'static [u8] = &[
            28u8, 04u8, // src port 7172
            00u8, 80u8, // dst port 80
            00u8, 13u8, // packet len
            00u8, 00u8, // checksum
            104u8, 101u8, 108u8, 108u8, 111u8, // data octets; "hello"
        ];
        let packet = UdpPacket::from_bytes(&BytesMut::from(raw_packet)).unwrap();

        assert_eq!(packet.source, 7172);
        assert_eq!(packet.destination, 80);
        assert_eq!(packet.length, 13);
        assert_eq!(packet.checksum, 0);
    }
}
