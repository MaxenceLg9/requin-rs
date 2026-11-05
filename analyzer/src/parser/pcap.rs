use std::{
    fmt::{self, Display, Formatter},
    fs::File,
    io::{BufReader, Error, ErrorKind, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    parser::{
        frame::Frame,
        header::{NumberFormat, PCapHeader, TsFormat},
    },
    proto::{DecoderRegistry, PacketSummary, decode_frame, summarize_packet},
};

const PCAPNG_SECTION_HEADER: u32 = 0x0a0d0d0a;
const MAX_PACKET_SIZE: u32 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFormat {
    Pcap,
    PcapNg,
}

#[derive(Clone, Debug)]
struct Interface {
    link_type: u16,
    snap_len: u32,
    timestamp_denominator: u64,
}

struct PacketRecord {
    timestamp: Duration,
    original_len: u32,
    link_type: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureSummary {
    pub number: u64,
    pub timestamp: Duration,
    pub original_len: u32,
    pub captured_len: u32,
    pub link_type: u16,
    pub packet: PacketSummary,
}

enum ReaderFormat {
    Pcap {
        header: PCapHeader,
    },
    PcapNg {
        byte_order: NumberFormat,
        interfaces: Vec<Interface>,
    },
}

pub struct CaptureReader<R: Read> {
    reader: R,
    format: ReaderFormat,
    format_kind: CaptureFormat,
    frame_number: u64,
    decoders: DecoderRegistry,
    packet_buffer: Vec<u8>,
}

impl<R: Read> CaptureReader<R> {
    pub fn from_reader(mut reader: R) -> Result<Self, Error> {
        let mut magic = [0; 4];
        reader.read_exact(&mut magic)?;
        if magic == PCAPNG_SECTION_HEADER.to_be_bytes() {
            let mut section_header = [0; 8];
            reader.read_exact(&mut section_header)?;
            let byte_order = match &section_header[4..8] {
                [0x1a, 0x2b, 0x3c, 0x4d] => NumberFormat::BigEndian,
                [0x4d, 0x3c, 0x2b, 0x1a] => NumberFormat::LittleEndian,
                _ => return Err(invalid_data("invalid pcapng byte-order magic")),
            };
            let block_len = read_u32(byte_order, &section_header[..4])?;
            if block_len < 28 || block_len % 4 != 0 {
                return Err(invalid_data("invalid pcapng section-header length"));
            }
            skip_exact(&mut reader, block_len as usize - 16)?;
            let trailer = read_u32_from(&mut reader, byte_order)?;
            if trailer != block_len {
                return Err(invalid_data("pcapng section-header length mismatch"));
            }
            return Ok(Self {
                reader,
                format: ReaderFormat::PcapNg {
                    byte_order,
                    interfaces: Vec::new(),
                },
                format_kind: CaptureFormat::PcapNg,
                frame_number: 0,
                decoders: DecoderRegistry::new(),
                packet_buffer: Vec::new(),
            });
        }

        let mut header_bytes = [0; 24];
        header_bytes[..4].copy_from_slice(&magic);
        reader.read_exact(&mut header_bytes[4..])?;
        let header = PCapHeader::parse(&header_bytes)?;
        Ok(Self {
            reader,
            format: ReaderFormat::Pcap { header },
            format_kind: CaptureFormat::Pcap,
            frame_number: 0,
            decoders: DecoderRegistry::new(),
            packet_buffer: Vec::new(),
        })
    }

    pub fn format(&self) -> CaptureFormat {
        self.format_kind
    }

    pub fn pcap_header(&self) -> Option<&PCapHeader> {
        match &self.format {
            ReaderFormat::Pcap { header } => Some(header),
            ReaderFormat::PcapNg { .. } => None,
        }
    }

    pub fn decoders_mut(&mut self) -> &mut DecoderRegistry {
        &mut self.decoders
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        let Some(packet) = self.next_record()? else {
            return Ok(None);
        };
        self.frame_number += 1;
        let link_type = packet.link_type;
        let mut frame = Frame::new(
            self.frame_number,
            packet.timestamp,
            packet.original_len,
            link_type,
            std::mem::take(&mut self.packet_buffer),
        );
        decode_frame(&mut frame, link_type, &self.decoders);
        Ok(Some(frame))
    }

    pub fn with_next_frame<T>(
        &mut self,
        consume: impl FnOnce(&Frame) -> T,
    ) -> Result<Option<T>, Error> {
        let Some(packet) = self.next_record()? else {
            return Ok(None);
        };
        self.frame_number += 1;
        let link_type = packet.link_type;
        let mut frame = Frame::new(
            self.frame_number,
            packet.timestamp,
            packet.original_len,
            link_type,
            std::mem::take(&mut self.packet_buffer),
        );
        decode_frame(&mut frame, link_type, &self.decoders);
        let result = consume(&frame);
        self.packet_buffer = frame.raw_data;
        Ok(Some(result))
    }

    pub fn next_summary(&mut self) -> Result<Option<CaptureSummary>, Error> {
        let Some(packet) = self.next_record()? else {
            return Ok(None);
        };
        self.frame_number += 1;
        Ok(Some(CaptureSummary {
            number: self.frame_number,
            timestamp: packet.timestamp,
            original_len: packet.original_len,
            captured_len: u32::try_from(self.packet_buffer.len()).unwrap_or(u32::MAX),
            link_type: packet.link_type,
            packet: summarize_packet(&self.packet_buffer, packet.link_type),
        }))
    }

    fn next_record(&mut self) -> Result<Option<PacketRecord>, Error> {
        match &mut self.format {
            ReaderFormat::Pcap { header } => {
                read_pcap_packet(&mut self.reader, header, &mut self.packet_buffer)
            }
            ReaderFormat::PcapNg {
                byte_order,
                interfaces,
            } => read_pcapng_packet(
                &mut self.reader,
                byte_order,
                interfaces,
                &mut self.packet_buffer,
            ),
        }
    }
}

fn read_pcap_packet<R: Read>(
    reader: &mut R,
    header: &PCapHeader,
    packet_buffer: &mut Vec<u8>,
) -> Result<Option<PacketRecord>, Error> {
    let mut record = [0; 16];
    if !read_record(reader, &mut record)? {
        return Ok(None);
    }
    let order = header.number_format;
    let seconds = read_u32(order, &record[..4])?;
    let fraction = read_u32(order, &record[4..8])?;
    let captured_len = read_u32(order, &record[8..12])?;
    let original_len = read_u32(order, &record[12..16])?;
    if captured_len > MAX_PACKET_SIZE || captured_len > header.snap_len {
        return Err(invalid_data("pcap packet exceeds supported capture size"));
    }
    let timestamp = match header.ts_format {
        TsFormat::Nano if fraction < 1_000_000_000 => Duration::new(u64::from(seconds), fraction),
        TsFormat::Micro if fraction < 1_000_000 => {
            Duration::new(u64::from(seconds), fraction * 1_000)
        }
        _ => return Err(invalid_data("invalid pcap packet timestamp fraction")),
    };
    packet_buffer.resize(captured_len as usize, 0);
    reader.read_exact(packet_buffer)?;
    Ok(Some(PacketRecord {
        timestamp,
        original_len,
        link_type: header.link_type,
    }))
}

fn read_pcapng_packet<R: Read>(
    reader: &mut R,
    byte_order: &mut NumberFormat,
    interfaces: &mut Vec<Interface>,
    packet_buffer: &mut Vec<u8>,
) -> Result<Option<PacketRecord>, Error> {
    loop {
        let mut block_type_bytes = [0; 4];
        if !read_record(reader, &mut block_type_bytes)? {
            return Ok(None);
        }
        let mut len_bytes = [0; 4];
        reader.read_exact(&mut len_bytes)?;

        if block_type_bytes == PCAPNG_SECTION_HEADER.to_be_bytes() {
            let mut bom = [0; 4];
            reader.read_exact(&mut bom)?;
            *byte_order = match bom {
                [0x1a, 0x2b, 0x3c, 0x4d] => NumberFormat::BigEndian,
                [0x4d, 0x3c, 0x2b, 0x1a] => NumberFormat::LittleEndian,
                _ => return Err(invalid_data("invalid pcapng byte-order magic")),
            };
            let block_len = read_u32(*byte_order, &len_bytes)?;
            validate_block_len(block_len, 28)?;
            skip_exact(reader, block_len as usize - 16)?;
            if read_u32_from(reader, *byte_order)? != block_len {
                return Err(invalid_data("pcapng section-header length mismatch"));
            }
            interfaces.clear();
            continue;
        }

        let order = *byte_order;
        let block_type = read_u32(order, &block_type_bytes)?;
        let block_len = read_u32(order, &len_bytes)?;
        validate_block_len(block_len, 12)?;
        match block_type {
            1 => {
                if block_len < 20 {
                    return Err(invalid_data("invalid pcapng interface block"));
                }
                let mut fixed = [0; 8];
                reader.read_exact(&mut fixed)?;
                let link_type = read_u16(order, &fixed[..2])?;
                let snap_len = read_u32(order, &fixed[4..])?;
                let mut interface = Interface {
                    link_type,
                    snap_len: if snap_len == 0 {
                        MAX_PACKET_SIZE
                    } else {
                        snap_len
                    },
                    timestamp_denominator: 1_000_000,
                };
                let options_len = block_len as usize - 20;
                read_interface_options(reader, options_len, order, &mut interface)?;
                if read_u32_from(reader, order)? != block_len {
                    return Err(invalid_data("pcapng interface block length mismatch"));
                }
                interfaces.push(interface);
            }
            3 => {
                if block_len < 16 {
                    return Err(invalid_data("invalid pcapng simple-packet block"));
                }
                let original_len = read_u32_from(reader, order)?;
                let Some(interface) = interfaces.first() else {
                    return Err(invalid_data("pcapng packet has no interface"));
                };
                let captured_len = original_len.min(interface.snap_len);
                if captured_len > MAX_PACKET_SIZE {
                    return Err(invalid_data("pcapng packet exceeds supported capture size"));
                }
                let packet_space = block_len as usize - 16;
                if captured_len as usize > packet_space {
                    return Err(invalid_data("invalid pcapng packet length"));
                }
                packet_buffer.resize(captured_len as usize, 0);
                reader.read_exact(packet_buffer)?;
                skip_exact(reader, packet_space - captured_len as usize)?;
                if read_u32_from(reader, order)? != block_len {
                    return Err(invalid_data("pcapng simple-packet block length mismatch"));
                }
                return Ok(Some(PacketRecord {
                    timestamp: Duration::ZERO,
                    original_len,
                    link_type: interface.link_type,
                }));
            }
            6 => {
                if block_len < 32 {
                    return Err(invalid_data("invalid pcapng enhanced-packet block"));
                }
                let mut fixed = [0; 20];
                reader.read_exact(&mut fixed)?;
                let interface_id = read_u32(order, &fixed[..4])? as usize;
                let high = read_u32(order, &fixed[4..8])?;
                let low = read_u32(order, &fixed[8..12])?;
                let captured_len = read_u32(order, &fixed[12..16])?;
                let original_len = read_u32(order, &fixed[16..20])?;
                let interface = interfaces
                    .get(interface_id)
                    .ok_or_else(|| invalid_data("pcapng packet references unknown interface"))?;
                if captured_len > MAX_PACKET_SIZE || captured_len > interface.snap_len {
                    return Err(invalid_data("pcapng packet exceeds supported capture size"));
                }
                let padding = (4 - (captured_len as usize % 4)) % 4;
                let fixed_block_bytes = 8 + fixed.len() + captured_len as usize + padding + 4;
                let remainder = (block_len as usize)
                    .checked_sub(fixed_block_bytes)
                    .ok_or_else(|| invalid_data("invalid pcapng enhanced-packet length"))?;
                packet_buffer.resize(captured_len as usize, 0);
                reader.read_exact(packet_buffer)?;
                skip_exact(reader, padding + remainder)?;
                if read_u32_from(reader, order)? != block_len {
                    return Err(invalid_data("pcapng enhanced-packet block length mismatch"));
                }
                let ticks = (u64::from(high) << 32) | u64::from(low);
                let nanos = (u128::from(ticks) * 1_000_000_000)
                    / u128::from(interface.timestamp_denominator);
                let timestamp = Duration::new(
                    (nanos / 1_000_000_000) as u64,
                    (nanos % 1_000_000_000) as u32,
                );
                return Ok(Some(PacketRecord {
                    timestamp,
                    original_len,
                    link_type: interface.link_type,
                }));
            }
            _ => {
                skip_exact(reader, block_len as usize - 12)?;
                if read_u32_from(reader, order)? != block_len {
                    return Err(invalid_data("pcapng block length mismatch"));
                }
            }
        }
    }
}

fn read_interface_options<R: Read>(
    reader: &mut R,
    mut remaining: usize,
    order: NumberFormat,
    interface: &mut Interface,
) -> Result<(), Error> {
    while remaining >= 4 {
        let mut option_header = [0; 4];
        reader.read_exact(&mut option_header)?;
        remaining -= 4;
        let code = read_u16(order, &option_header[..2])?;
        let length = usize::from(read_u16(order, &option_header[2..])?);
        let padded_len = (length + 3) & !3;
        if padded_len > remaining {
            return Err(invalid_data("invalid pcapng interface option length"));
        }
        if code == 9 && length == 1 {
            let mut value = [0];
            reader.read_exact(&mut value)?;
            let resolution = value[0];
            interface.timestamp_denominator = if resolution & 0x80 == 0 {
                10_u64
                    .checked_pow(u32::from(resolution))
                    .unwrap_or(u64::MAX)
            } else {
                2_u64
                    .checked_pow(u32::from(resolution & 0x7f))
                    .unwrap_or(u64::MAX)
            };
            skip_exact(reader, padded_len - 1)?;
        } else {
            skip_exact(reader, padded_len)?;
        }
        remaining -= padded_len;
        if code == 0 {
            if length != 0 {
                return Err(invalid_data("invalid pcapng end-of-options marker"));
            }
            skip_exact(reader, remaining)?;
            return Ok(());
        }
    }
    skip_exact(reader, remaining)?;
    Ok(())
}

fn validate_block_len(length: u32, minimum: u32) -> Result<(), Error> {
    if length < minimum || !length.is_multiple_of(4) {
        Err(invalid_data("invalid pcapng block length"))
    } else {
        Ok(())
    }
}

fn read_u16(order: NumberFormat, bytes: &[u8]) -> Result<u16, Error> {
    order
        .read_u16(bytes)
        .ok_or_else(|| invalid_data("truncated capture field"))
}

fn read_u32(order: NumberFormat, bytes: &[u8]) -> Result<u32, Error> {
    order
        .read_u32(bytes)
        .ok_or_else(|| invalid_data("truncated capture field"))
}

fn read_u32_from<R: Read>(reader: &mut R, order: NumberFormat) -> Result<u32, Error> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    read_u32(order, &bytes)
}

fn skip_exact<R: Read>(reader: &mut R, mut length: usize) -> Result<(), Error> {
    let mut buffer = [0; 8192];
    while length > 0 {
        let count = length.min(buffer.len());
        reader.read_exact(&mut buffer[..count])?;
        length -= count;
    }
    Ok(())
}

fn read_record<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<bool, Error> {
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(Error::from(ErrorKind::UnexpectedEof)),
            read => filled += read,
        }
    }
    Ok(true)
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

pub struct PCapStream {
    path: PathBuf,
    reader: CaptureReader<BufReader<File>>,
}

impl PCapStream {
    pub fn new(filepath: &str) -> Result<Self, Error> {
        let path = Path::new(filepath).to_path_buf();
        let reader = open_capture(&path)?;
        Ok(Self { path, reader })
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        self.reader = open_capture(&self.path)?;
        Ok(())
    }

    pub fn get_header(&self) -> Option<&PCapHeader> {
        self.reader.pcap_header()
    }

    pub fn load_plugin(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.reader.decoders_mut().load_plugin(path)
    }

    pub fn load_plugins_from_dir(&mut self, path: impl AsRef<Path>) -> Result<usize, Error> {
        self.reader.decoders_mut().load_plugins_from_dir(path)
    }

    pub fn parse_next(&mut self) -> Result<Option<Frame>, Error> {
        self.reader.next_frame()
    }

    pub fn with_next_frame<T>(
        &mut self,
        consume: impl FnOnce(&Frame) -> T,
    ) -> Result<Option<T>, Error> {
        self.reader.with_next_frame(consume)
    }

    pub fn parse_next_summary(&mut self) -> Result<Option<CaptureSummary>, Error> {
        self.reader.next_summary()
    }
}

impl CaptureReader<BufReader<File>> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        open_capture(path.as_ref())
    }
}

fn open_capture(path: &Path) -> Result<CaptureReader<BufReader<File>>, Error> {
    CaptureReader::from_reader(BufReader::new(File::open(path)?))
}

impl Display for PCapStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Capture file: {}", self.path.display())?;
        writeln!(f, "Format: {:?}", self.reader.format())?;
        if let Some(header) = self.reader.pcap_header() {
            write!(f, "{header}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{
        parser::layer::{Field, Layer},
        proto::{ApplicationDecoder, TransportInfo},
    };

    struct MarkerDecoder;

    impl ApplicationDecoder for MarkerDecoder {
        fn decode(
            &self,
            payload: &[u8],
            _transport: TransportInfo,
            offset: usize,
        ) -> Option<Layer> {
            payload
                .starts_with(b"XPROTO")
                .then(|| Layer::new("XPROTO").field(Field::new("Marker", "present").at(offset, 6)))
        }
    }

    fn pcap(packet: &[u8]) -> Vec<u8> {
        let mut capture = Vec::new();
        capture.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        capture.extend_from_slice(&2_u16.to_le_bytes());
        capture.extend_from_slice(&4_u16.to_le_bytes());
        capture.extend_from_slice(&[0; 8]);
        capture.extend_from_slice(&65535_u32.to_le_bytes());
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(packet);
        capture
    }

    #[test]
    fn streams_and_decodes_little_endian_pcap() {
        let mut packet = vec![0; 14 + 20];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&20_u16.to_be_bytes());
        packet[22] = 64;
        packet[23] = 99;
        packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
        packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
        let mut reader = CaptureReader::from_reader(Cursor::new(pcap(&packet))).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.number, 1);
        assert_eq!(frame.protocol, "IPv4");
        assert_eq!(frame.source.as_deref(), Some("192.0.2.1"));
        assert_eq!(frame.raw_data, packet);
        assert!(reader.next_frame().unwrap().is_none());
    }

    #[test]
    fn streams_packet_summaries_without_constructing_frames() {
        let mut packet = vec![0; 14 + 20];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&20_u16.to_be_bytes());
        packet[22] = 64;
        packet[23] = 99;
        packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
        packet[30..34].copy_from_slice(&[198, 51, 100, 2]);

        let mut reader = CaptureReader::from_reader(Cursor::new(pcap(&packet))).unwrap();
        let summary = reader.next_summary().unwrap().unwrap();
        assert_eq!(summary.number, 1);
        assert_eq!(summary.captured_len, packet.len() as u32);
        assert_eq!(summary.packet.protocol, "IPv4");
        assert_eq!(
            summary.packet.source,
            Some(crate::proto::Address::Ipv4([192, 0, 2, 1]))
        );
        assert!(reader.next_summary().unwrap().is_none());
    }

    #[test]
    fn consumes_decoded_frames_without_giving_up_the_reusable_packet_buffer() {
        let mut packet = vec![0; 14];
        packet[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        let mut capture = pcap(&packet);
        capture.extend_from_slice(&pcap(&packet)[24..]);
        let mut reader = CaptureReader::from_reader(Cursor::new(capture)).unwrap();

        for expected_number in 1..=2 {
            let result = reader
                .with_next_frame(|frame| {
                    (
                        frame.number,
                        frame.captured_len,
                        frame.protocol.to_string(),
                        frame.raw_data.len(),
                    )
                })
                .unwrap()
                .unwrap();
            assert_eq!(result, (expected_number, 14, "Ethernet".to_owned(), 14));
        }
        assert!(reader.with_next_frame(|_| ()).unwrap().is_none());
    }

    #[test]
    fn rejects_truncated_packet_data() {
        let mut capture = pcap(&[1, 2]);
        capture.truncate(capture.len() - 1);
        let mut reader = CaptureReader::from_reader(Cursor::new(capture)).unwrap();
        assert_eq!(
            reader.next_frame().unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn rejects_invalid_magic_instead_of_panicking() {
        let error = match CaptureReader::from_reader(Cursor::new([0; 24])) {
            Ok(_) => panic!("invalid capture unexpectedly parsed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn reads_pcapng_interface_and_enhanced_packet_blocks() {
        let mut capture = Vec::new();
        capture.extend_from_slice(&PCAPNG_SECTION_HEADER.to_be_bytes());
        capture.extend_from_slice(&28_u32.to_le_bytes());
        capture.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]);
        capture.extend_from_slice(&1_u16.to_le_bytes());
        capture.extend_from_slice(&0_u16.to_le_bytes());
        capture.extend_from_slice(&u64::MAX.to_le_bytes());
        capture.extend_from_slice(&28_u32.to_le_bytes());

        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&20_u32.to_le_bytes());
        capture.extend_from_slice(&1_u16.to_le_bytes());
        capture.extend_from_slice(&0_u16.to_le_bytes());
        capture.extend_from_slice(&65535_u32.to_le_bytes());
        capture.extend_from_slice(&20_u32.to_le_bytes());

        let packet = [0; 14];
        capture.extend_from_slice(&6_u32.to_le_bytes());
        capture.extend_from_slice(&48_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&1_000_000_u32.to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&packet);
        capture.extend_from_slice(&[0; 2]);
        capture.extend_from_slice(&48_u32.to_le_bytes());

        let mut reader = CaptureReader::from_reader(Cursor::new(capture)).unwrap();
        assert_eq!(reader.format(), CaptureFormat::PcapNg);
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.number, 1);
        assert_eq!(frame.timestamp, Duration::from_secs(1));
        assert_eq!(frame.raw_data, packet);
        assert_eq!(frame.protocol, "Ethernet");
        assert!(reader.next_frame().unwrap().is_none());
    }

    #[test]
    fn decodes_tcp_fields_and_http_start_line() {
        let http = b"GET / HTTP/1.1\r\n";
        let ip_len = 20 + 20 + http.len();
        let mut packet = vec![0; 14 + ip_len];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut packet[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
        let tcp = &mut packet[34..54];
        tcp[0..2].copy_from_slice(&12345_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80_u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&42_u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&77_u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[14..16].copy_from_slice(&4096_u16.to_be_bytes());
        packet[54..].copy_from_slice(http);
        let mut reader = CaptureReader::from_reader(Cursor::new(pcap(&packet))).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.protocol, "HTTP");
        assert_eq!(frame.info, "GET / HTTP/1.1");
        let tcp = frame
            .layers
            .iter()
            .find(|layer| layer.name == "Transmission Control Protocol")
            .unwrap();
        assert!(
            tcp.fields
                .iter()
                .any(|field| field.name == "ACK" && field.value == true.into())
        );
        assert!(
            tcp.fields
                .iter()
                .any(|field| field.name == "PSH" && field.value == true.into())
        );
    }

    #[test]
    fn allows_registering_application_decoders_at_runtime() {
        let payload = b"XPROTO";
        let ip_len = 20 + 8 + payload.len();
        let mut packet = vec![0; 14 + ip_len];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut packet[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        let udp = &mut packet[34..42];
        udp[0..2].copy_from_slice(&9000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&9001_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[42..].copy_from_slice(payload);

        let mut reader = CaptureReader::from_reader(Cursor::new(pcap(&packet))).unwrap();
        reader.decoders_mut().register(MarkerDecoder);
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.protocol, "XPROTO");
        assert!(frame.layers.iter().any(|layer| layer.name == "XPROTO"));
    }
}
