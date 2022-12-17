const ETHERNET_HEADER_DESTINATION_MAC_LEN_NUM_BYTES: usize = 6;
const ETHERNET_HEADER_SOURCE_MAC_LEN_NUM_BYTES: usize = 6;
const ETHERNET_HEADER_LENGTH_NUM_BYTES: usize = 2;

#[derive(Debug)]
struct UdpFrame {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    data: Vec<u8>,
}

#[derive(Debug)]
struct EthernetHeader {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    length: u16,
}

#[derive(Debug, thiserror::Error)]
enum EthernetHeaderParseError {
    #[error("invalid header length; invalid destination mac")]
    InvalidDestinationMac,
    #[error("invalid header length; invalid source mac")]
    InvalidSourceMac,
    #[error("invalid header length; invalid payload length")]
    InvalidPayloadLength,
}

impl TryFrom<&[u8]> for EthernetHeader {
    type Error = EthernetHeaderParseError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let mut i = 0;

        let destination_mac = &input[i..ETHERNET_HEADER_DESTINATION_MAC_LEN_NUM_BYTES];
        if destination_mac.len() != ETHERNET_HEADER_DESTINATION_MAC_LEN_NUM_BYTES {
            return Err(EthernetHeaderParseError::InvalidDestinationMac);
        }
        i += ETHERNET_HEADER_DESTINATION_MAC_LEN_NUM_BYTES;

        let source_mac = &input[i..i + ETHERNET_HEADER_SOURCE_MAC_LEN_NUM_BYTES];
        if source_mac.len() != ETHERNET_HEADER_SOURCE_MAC_LEN_NUM_BYTES {
            return Err(EthernetHeaderParseError::InvalidSourceMac);
        }
        i += ETHERNET_HEADER_SOURCE_MAC_LEN_NUM_BYTES;

        let length = &input[i..i + ETHERNET_HEADER_LENGTH_NUM_BYTES];
        if length.len() != ETHERNET_HEADER_LENGTH_NUM_BYTES {
            return Err(EthernetHeaderParseError::InvalidPayloadLength);
        }

        let mut header = EthernetHeader {
            destination_mac: [0_u8; ETHERNET_HEADER_DESTINATION_MAC_LEN_NUM_BYTES],
            source_mac: [0_u8; ETHERNET_HEADER_SOURCE_MAC_LEN_NUM_BYTES],
            length: 0,
        };
        header.destination_mac.copy_from_slice(destination_mac);
        header.source_mac.copy_from_slice(source_mac);
        let mut len = [0_u8; ETHERNET_HEADER_LENGTH_NUM_BYTES];
        len.copy_from_slice(length);
        header.length = u16::from_be_bytes(len);

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use socket2::{Domain, Socket, Type};

    use crate::EthernetHeader;

    #[test]
    fn debug() -> Result<(), Box<dyn std::error::Error>> {
        let socket = Socket::new(Domain::PACKET, Type::RAW, None)?;

        let mut buffer = [MaybeUninit::uninit(); 10];
        let (buffer_len, _sock_addr) = socket.recv_from(&mut buffer)?;
        let buffer: Vec<u8> = buffer[0..buffer_len]
            .into_iter()
            .map(|maybe_uninit_byte| unsafe { maybe_uninit_byte.assume_init() })
            .collect();

        let ethernet_header = EthernetHeader::try_from(buffer.as_ref())?;
        dbg!(ethernet_header);

        Ok(())
    }
}
