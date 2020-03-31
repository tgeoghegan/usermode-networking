use byteorder::{ByteOrder, NativeEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pretty_hex::pretty_hex;
use std::fmt;
use std::io::{Cursor, Error, ErrorKind, Result, Write};
use std::net::Ipv4Addr;

use crate::SockProtocol;

const UDP_HEADER_LENGTH: usize = 8;

pub struct UdpSocket {
}

impl UdpSocket {
    pub fn bind(_addr: Ipv4Addr) -> Result<UdpSocket> {
        Err(Error::new(ErrorKind::Other, "unimplemented!"))
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
    source: u16,
    destination: u16,
    checksum: u16,
    data: Bytes,
}

impl UdpPacket {
    pub fn new(source: u16, destination: u16, data: Bytes) -> UdpPacket {
        assert!(data.len() + UDP_HEADER_LENGTH <= std::u16::MAX as usize);
        UdpPacket {
            source: source,
            destination: destination,
            checksum: 0,
            data: data,
        }
    }

    // XXX reimplement this as try_from<&Bytes>
    pub fn from_bytes(bytes: &Bytes) -> Result<UdpPacket> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err(Error::new(ErrorKind::InvalidInput, "packet is not long enough"));
        }
        if bytes.len() > std::u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidInput, "buffer is too big for legal UDP packet"));
        }

        // We use a std::io::Cursor to provide std::io::Read on our buf, which is required for the
        // ReadBytesExt trait to apply.
        let mut cursor = Cursor::new(bytes);

        let source = cursor.read_u16::<NetworkEndian>()?;
        let destination = cursor.read_u16::<NetworkEndian>()?;
        let length = cursor.read_u16::<NetworkEndian>()?;

        println!("buf len {} header len {}", bytes.len(), length);
        if bytes.len() != length as usize {
            return Err(Error::new(ErrorKind::InvalidInput, "length field in packet is incorrect."));
        }

        let checksum = cursor.read_u16::<NetworkEndian>()?;

        Ok(UdpPacket {
            source,
            destination,
            checksum,
            data: bytes.slice(UDP_HEADER_LENGTH..),
        })
    }

    pub fn length(&self) -> usize {
        self.data.len() + UDP_HEADER_LENGTH
    }

    pub fn into_bytes(&self, buf: &mut BytesMut) -> Result<()> {
        if buf.capacity() < self.length() {
            return Err(Error::new(ErrorKind::InvalidInput, "provided buffer is not long enough"));
        }
        buf.resize(self.length(), 0);

        // This is odd: Cursor implements std::io::Read<T>, meaning we can use ReadBytesExt without
        // ceremony above. But it only provides std::io::Write<'_ mut [u8]>, so we have to get the
        // mutable u8 slice reference out of the BytesMut with core::convert::AsMut::as_mut<[u8]>.
        // But you'd think Cursor could implement std::io::Write<T: AsMut<[u8]>>.
        let mut cursor = Cursor::new(buf.as_mut());
        cursor.write_u16::<NetworkEndian>(self.source)?;
        cursor.write_u16::<NetworkEndian>(self.destination)?;
        cursor.write_u16::<NetworkEndian>(UDP_HEADER_LENGTH as u16 + self.data.len() as u16)?;
        cursor.write_u16::<NetworkEndian>(self.checksum)?;
        // It seems unlikely that we would ever fail to write the desired number of bytes since this
        // is just a copy to memory, so assert on the write length
        assert!(cursor.write(self.data.as_ref())? == self.data.len());

        Ok(())
    }

    pub fn verify_checksum(&self, source_address: Ipv4Addr, dest_address: Ipv4Addr) -> Result<()> {
        if self.checksum == self.compute_checksum(source_address, dest_address) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "incorrect checksum"))
        }
    }

    pub fn fill_checksum(&mut self, source_address: Ipv4Addr, dest_address: Ipv4Addr) {
        self.checksum = self.compute_checksum(source_address, dest_address);
    }

    fn compute_checksum(&self, source_address: Ipv4Addr, dest_address: Ipv4Addr) -> u16 {
        let mut c = Checksum::new();
        // Feed in pseudo-header: source address (4 bytes), dest address (4 bytes), one zero byte,
        // protocol number (1 byte), UDP packet length (2 bytes)
        c.add_bytes(&source_address.octets());
        c.add_bytes(&dest_address.octets());
        c.add_bytes(&[0u8]);
        c.add_bytes(&[SockProtocol::Udp as u8]);
        c.add_bytes(&[(self.data.len() + UDP_HEADER_LENGTH) as u8]);

        NativeEndian::read_u16(&c.checksum())
    }
}

impl fmt::Display for UdpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Source port: {}\nDestination port: {}\nLength: {}\nChecksum: {}\nPacket contents: {}",
            self.source, self.destination, self.data.len(), self.checksum, pretty_hex(&self.data))
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
        let packet = UdpPacket::from_bytes(&Bytes::from(raw_packet)).unwrap();

        assert_eq!(packet.source, 7172);
        assert_eq!(packet.destination, 80);
        assert_eq!(packet.checksum, 0);
        assert_eq!(packet.data.len(), 5);
        assert_eq!(&packet.data[..], b"hello");
    }
}
