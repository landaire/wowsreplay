
extern crate nom;
use nom::{
  IResult,
  bytes::complete::{tag, take_while_m_n, take},
  number::complete::le_u32,
  combinator::map_res,
  sequence::tuple
};
use crate::wows::packet::Packet;

#[derive(Debug)]
pub struct Header<'a> {
    pub magic: u32,
    pub block_count: u32,
    pub metadata: &'a [u8]
}


pub fn header<'a>(input: &'a [u8]) -> IResult<&'a [u8], Header<'a>> {
    let (input, magic) = le_u32(input)?;
    let (input, block_count) = le_u32(input)?;
    let (input, len) = le_u32(input)?;
    let (input, metadata) = take(len)(input)?;

    Ok((input, Header {
        magic, block_count, metadata
    }))
}

pub fn block(input: &[u8]) -> IResult<&[u8], (usize, &[u8])> {
    let (input, unk) = le_u32(input)?;
    let (input, len) = le_u32(input)?;
    let mut padded_len = len as usize;
    let extra = padded_len % 8;
    if extra != 0 {
        padded_len += 8 - extra;
    }
    // println!("len: {:X}", len);
    // println!("input len: {:X}", input.len());

    let (input, block) = take(padded_len)(input)?;
    IResult::Ok((input, (len as usize, block)))

}

pub fn parse_replay_network_data<'a>(input: &'a [u8]) -> IResult<&'a [u8], Packet<'a>> {
    let (input, data_len) = le_u32(input)?;
    let (input, ty) = le_u32(input)?;
    let (input, time) = le_u32(input)?;

    let (input, data) = take(data_len)(input)?;

    IResult::Ok((input, Packet { data_len, ty, time, data }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsing_header_works() {
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let res = header(data);
        assert!(res.is_ok());
        //println!("{:#X?}", res.unwrap().1);
    }

    #[test]
    fn parsing_block_works() {
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let header = header(data);
        assert!(header.is_ok());
        let (data, header) = header.unwrap();
        //println!("{}", std::str::from_utf8(header.metadata).unwrap());
    }

    #[test]
    fn parsing_decrypting_block_works() {
        let data = include_bytes!("../test_data/smaland2.wowsreplay");
        let header = header(data);
        assert!(header.is_ok());
        let (data, _) = header.unwrap();

        let res = block(data);
        assert!(res.is_ok());
        let (len, encrypted_block) = res.unwrap().1;
        let mut encrypted_block = encrypted_block.to_vec();

        let mut unpacker = crate::Unpacker::new();
        let unpacked = unpacker.unpack(encrypted_block.as_mut_slice(), len);

        use nom::HexDisplay;

        let mut network_data = unpacked.as_slice();

        let mut unique_packet_types = std::collections::BTreeMap::<u32, usize>::new();
        while network_data.len() > 0xC {
            let parse_result = parse_replay_network_data(network_data).unwrap();
            network_data = parse_result.0;
            let packet = parse_result.1;

            println!("{:#X?}", packet);
            *unique_packet_types.entry(packet.ty).or_default() += 1;
            match packet.deserialize() {
                Some(deserialized_data) => println!("{:#X?}", deserialized_data),
                None => println!("{}", packet.data.to_hex(16)),
            }
        }

        println!("{:#X?}", unique_packet_types);

        // let res =decrypted_block(data.1);
        // assert!(res.is_ok());
        // let res = res.unwrap();
    }
}