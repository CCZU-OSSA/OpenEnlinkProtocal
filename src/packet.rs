///! Use packet to replace it

pub use zero_packet as packet;

use std::io::ErrorKind;

use zero_packet::{
    packet::parser::PacketParser,
    transport::{tcp::TcpReader, udp::UdpReader},
};

#[derive(Debug)]
pub enum Packet<'a> {
    UDP(UdpReader<'a>, PacketParser<'a>),
    TCP(TcpReader<'a>, PacketParser<'a>),
}

/// Malloc the size of packet yourself.
///
/// This method returns a [`Packet`].
///
/// A [`Packet`] contains a [`TcpReader`] or [`UdpReader`] and [`PacketParser`]
///
///
/// ```
/// let mut data = vec![0u8, 512];
///
/// match protocal.read_packet(&mut data){
///     Packet::UDP(transport, parsed) => ...
///     Packet::TCP(transport, parsed) => ...
///     _ => ...
/// }
/// ```
///
/// FYI,
///
/// [`zero_packet::transport::tcp::TCP_MIN_HEADER_LENGTH`]
///
/// [`zero_packet::transport::udp::UDP_HEADER_LENGTH`]
pub fn parse_packet<'a>(packet: &'a [u8]) -> Result<Packet<'a>, tokio::io::Error> {
    let parsed = PacketParser::parse(packet)
        .map_err(|err| tokio::io::Error::new(ErrorKind::InvalidData, err))?;

    if let Ok(tcp) = TcpReader::new(packet) {
        Ok(Packet::TCP(tcp, parsed))
    } else if let Ok(udp) = UdpReader::new(packet) {
        Ok(Packet::UDP(udp, parsed))
    } else {
        Err(tokio::io::Error::new(
            ErrorKind::Unsupported,
            format!("Unsupport packet: {:?}", packet),
        ))
    }
}
