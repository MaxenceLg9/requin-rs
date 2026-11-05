use zerocopy::{
    FromBytes, Immutable, KnownLayout, Unaligned,
    byteorder::network_endian::{U16, U32},
};

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: U16,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct ArpHeader {
    pub hardware_type: U16,
    pub protocol_type: U16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub operation: U16,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct Ipv4Header {
    pub version_ihl: u8,
    pub differentiated_services: u8,
    pub total_len: U16,
    pub identification: U16,
    pub flags_fragment_offset: U16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: U16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct Ipv6Header {
    pub version_traffic_flow: [u8; 4],
    pub payload_len: U16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct TcpHeader {
    pub source_port: U16,
    pub destination_port: U16,
    pub sequence: U32,
    pub acknowledgment: U32,
    pub data_offset_reserved: u8,
    pub flags: u8,
    pub window: U16,
    pub checksum: U16,
    pub urgent_pointer: U16,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct UdpHeader {
    pub source_port: U16,
    pub destination_port: U16,
    pub length: U16,
    pub checksum: U16,
}

pub(super) fn view<T>(bytes: &[u8]) -> Option<&T>
where
    T: FromBytes + KnownLayout + Immutable,
{
    T::ref_from_prefix(bytes).ok().map(|(header, _)| header)
}
