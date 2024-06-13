use std::net::Ipv4Addr;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

pub struct TCPPacket<'a> {
    ipv4_header_slice: Ipv4HeaderSlice<'a>,
    tcp_header_slice: TcpHeaderSlice<'a>,
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

        let ipv4_header_slice = etherparse::Ipv4HeaderSlice::from_slice(payload_bytes).unwrap();
        if !Self::is_tcp_packet(ipv4_header_slice) {
            return Err(NotSupportedPacketError {
                message: "this is not an tcp packet.",
            });
        }

        return Ok(Self {
            ipv4_header_slice,
            tcp_header_slice: etherparse::TcpHeaderSlice::from_slice(
                &payload_bytes[ipv4_header_slice.slice().len()..],
            )
            .unwrap(),
        });
    }
    pub fn source_address(&self) -> Ipv4Addr {
        self.ipv4_header_slice.source_addr()
    }
    pub fn source_port(&self) -> u16 {
        self.tcp_header_slice.source_port()
    }
    pub fn destination_address(&self) -> Ipv4Addr {
        self.ipv4_header_slice.destination_addr()
    }
    pub fn destination_port(&self) -> u16 {
        self.tcp_header_slice.destination_port()
    }
    fn is_ipv4_packet(packet_bytes: &[u8]) -> bool {
        let tun_protocol = u16::from_be_bytes([packet_bytes[2], packet_bytes[3]]);
        if tun_protocol != 0x0800 {
            return false;
        }
        true
    }
    fn is_tcp_packet(header: Ipv4HeaderSlice) -> bool {
        return header.protocol() == etherparse::IpNumber(6);
    }
}
