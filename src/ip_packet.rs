use byteorder::{NativeEndian, NetworkEndian, ReadBytesExt};
use bytes::Bytes;
use pretty_hex::pretty_hex;
use std::fmt;
use std::io::Cursor;
use std::net::Ipv4Addr;

/// An individual IP packet. Specified according to RFC 791. This is only a
/// partial implementation and ignores several fields not used by higher-level
/// UDP and TCP implementations.
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct IpPacket {
    version: u8,
    internet_header_length: u8,
    total_length: u16,
    protocol: u8,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
    data: Bytes,
}

// Per RFC 791, "minimum value for a correct header is 5", in 32 bit words,
// hence 20 bytes.
const MINIMUM_IP_PACKET_LEN: usize = 20;

impl IpPacket {
    pub fn from_bytes(bytes: &Bytes) -> Result<IpPacket, &'static str> {
        if bytes.len() < MINIMUM_IP_PACKET_LEN {
            return Err("packet is not long enough");
        }

        let mut cursor = Cursor::new(bytes);

        let version_and_ihl = cursor.read_u8().unwrap();
        let internet_header_len = version_and_ihl & 0x0f;
        let data_start = internet_header_len as u16 * 4;
        // seek past type of service field, which we ignore
        let _ = cursor.read_u8().unwrap();
        // When using SOCK_RAW, macOS mangles the total length field seen by userspace in two
        // surprising ways. First, the value does *not* include the length of the header, only the
        // message that follows, which contradicts RFC 791. Even stranger, the length field is
        // presented in host byte order, though everything else is network order.
        let mut total_length = cursor.read_u16::<NativeEndian>().unwrap();
        total_length += data_start;
        // seek past identification, flags, fragment offset, TTL
        let _ = cursor.read_u16::<NetworkEndian>().unwrap();
        let _ = cursor.read_u16::<NetworkEndian>().unwrap();
        let _ = cursor.read_u8().unwrap();
        let protocol = cursor.read_u8().unwrap();
        // seek past header checksum
        let _ = cursor.read_u16::<NetworkEndian>().unwrap();
        let source_address = cursor.read_u32::<NetworkEndian>().unwrap();
        let destination_address = cursor.read_u32::<NetworkEndian>().unwrap();

        Ok(IpPacket {
            version: (version_and_ihl & 0xf0) >> 4,
            internet_header_length: internet_header_len,
            total_length,
            protocol,
            source_address: Ipv4Addr::from(source_address),
            destination_address: Ipv4Addr::from(destination_address),
            data: bytes.slice(data_start as usize..total_length as usize),
        })
    }
}

impl fmt::Display for IpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Version {}
Header length: {}
total length: {}
protocol: {}
source address: {}
destination address {}
Packet contents: {}", 
            self.version, self.internet_header_length * 4, self.total_length, self.protocol,
            self.source_address, self.destination_address, pretty_hex(&self.data))
    }
}
