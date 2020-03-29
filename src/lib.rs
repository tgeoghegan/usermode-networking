use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::Bytes;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddrV4};

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
pub struct UdpPacket {
    source: u16,
    destination: u16,
    checksum: u16,
    contents: Bytes,
}

const UDP_HEADER_LENGTH: usize = 8;

impl UdpPacket {
    pub fn new(source: u16, destination: u16, contents: Bytes) -> UdpPacket {
        UdpPacket {
            source: source,
            destination: destination,
            checksum: 0,
            contents: contents,
        }
    }

    pub fn from_bytes(bytes: &Bytes) -> Result<UdpPacket, &'static str> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err("packet is not long enough");
        }
        let mut cursor = Cursor::new(bytes);

        let source = cursor.read_u16::<NetworkEndian>().unwrap();
        let destination = cursor.read_u16::<NetworkEndian>().unwrap();
        let length = cursor.read_u16::<NetworkEndian>().unwrap();

        if bytes.len() != length as usize {
            return Err("length field in packet is incorrect.");
        }

        let checksum = cursor.read_u16::<NetworkEndian>().unwrap();

        // todo: verify checksum
        Ok(UdpPacket {
            source,
            destination,
            checksum,
            contents: bytes.slice(UDP_HEADER_LENGTH..),
        })
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
        assert_eq!(packet.contents.len(), 5);
        assert_eq!(&packet.contents[..], b"hello");
    }
}
