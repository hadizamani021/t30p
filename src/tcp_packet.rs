use std::net::Ipv4Addr;

pub struct TCPPacket<'a> {
    payload_bytes: &'a [u8],
}
pub struct NotSupportedPacketError<'a> {
    pub message: &'a str,
}

impl<'a> TCPPacket<'a> {
    pub fn new(packet_bytes: &'a [u8]) -> Result<Self, NotSupportedPacketError> {
        let payload_bytes = &packet_bytes[4..];
        if !Self::is_ipv4_packet(packet_bytes) {
            return Err(NotSupportedPacketError {
                message: "this is not an IPV4 packet.",
            });
        }
        if !Self::is_tcp_packet(packet_bytes) {
            return Err(NotSupportedPacketError {
                message: "this is not an tcp packet.",
            });
        }
        return Ok(Self { payload_bytes });
    }
    pub fn source_address(&self) -> Result<Ipv4Addr, etherparse::err::ipv4::HeaderSliceError> {
        match etherparse::Ipv4HeaderSlice::from_slice(self.payload_bytes) {
            Ok(header) => Ok(header.source_addr()),
            Err(e) => return Err(e),
        }
    }
    pub fn source_port(&self) -> Result<u16, etherparse::err::tcp::HeaderSliceError> {
        match etherparse::TcpHeaderSlice::from_slice(self.payload_bytes) {
            Ok(header) => Ok(header.source_port()),
            Err(e) => return Err(e),
        }
    }
    pub fn destination_address(&self) -> Result<Ipv4Addr, etherparse::err::ipv4::HeaderSliceError> {
        match etherparse::Ipv4HeaderSlice::from_slice(self.payload_bytes) {
            Ok(header) => Ok(header.destination_addr()),
            Err(e) => return Err(e),
        }
    }
    pub fn destination_port(&self) -> Result<u16, etherparse::err::tcp::HeaderSliceError> {
        match etherparse::TcpHeaderSlice::from_slice(self.payload_bytes) {
            Ok(header) => Ok(header.destination_port()),
            Err(e) => return Err(e),
        }
    }
    fn is_ipv4_packet(packet_bytes: &[u8]) -> bool {
        let tun_protocol = u16::from_be_bytes([packet_bytes[2], packet_bytes[3]]);
        if tun_protocol != 0x0800 {
            return false;
        }
        true
    }
    fn is_tcp_packet(packet_bytes: &[u8]) -> bool {
        if let Ok(header) = etherparse::Ipv4HeaderSlice::from_slice(packet_bytes) {
            return header.protocol() == etherparse::IpNumber(0x06);
        }
        false
    }
}
