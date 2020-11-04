
extern crate nom;
use nom::{
  IResult,
  bytes::complete::{tag, take_while_m_n, take},
  number::complete::le_u32,
  combinator::map_res,
  sequence::tuple
};

#[derive(Debug)]
struct Header<'a> {
    magic: u32,
    block_count: u32,
    metadata: &'a [u8]
}


fn header<'a>(input: &'a [u8]) -> IResult<&'a [u8], Header<'a>> {
    let (input, magic) = le_u32(input)?;
    let (input, block_count) = le_u32(input)?;
    let (input, len) = le_u32(input)?;
    let (input, metadata) = take(len)(input)?;

    Ok((input, Header {
        magic, block_count, metadata
    }))
}

fn block(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, unk) = le_u32(input)?;
    let (input, mut len) = le_u32(input)?;
    let extra = len % 8;
    if extra != 0 {
        len += 8 - extra;
    }
    // println!("len: {:X}", len);
    // println!("input len: {:X}", input.len());

    take(len)(input)
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
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let header = header(data);
        assert!(header.is_ok());
        let (data, _) = header.unwrap();

        let res = block(data);
        assert!(res.is_ok());
        let mut encrypted_block = res.unwrap().1.to_vec();

        let mut unpacker = crate::Unpacker::new();
        let unpacked = unpacker.unpack(encrypted_block.as_mut_slice());

        use nom::HexDisplay;

        // let res =decrypted_block(data.1);
        // assert!(res.is_ok());
        // let res = res.unwrap();
    }
}