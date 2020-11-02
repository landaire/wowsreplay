
extern crate nom;
use nom::{
  IResult,
  bytes::complete::{tag, take_while_m_n, take},
  number::complete::le_u32,
  combinator::map_res,
  sequence::tuple
};

#[derive(Debug)]
struct Header {
    magic: u32,
    block_count: u32,
}


fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, magic) = le_u32(input)?;
    let (input, block_count) = le_u32(input)?;

    Ok((input, Header {
        magic, block_count
    }))
}

fn block(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, len) = le_u32(input)?;

    take(len)(input)
}

fn decrypted_block(input: &[u8]) -> IResult<&[u8], &[u8]> {

}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsing_header_works() {
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let res = header(data);
        assert!(res.is_ok());
        println!("{:#X?}", res.unwrap().1);
    }

    #[test]
    fn parsing_block_works() {
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let header = header(data);
        assert!(header.is_ok());
        let (data, _) = header.unwrap();
        let res = block(data);
        assert!(res.is_ok());
        let res = res.unwrap();
        println!("{}", std::str::from_utf8(res.1).unwrap());
    }

    #[test]
    fn parsing_decrypting_block_works() {
        let data = include_bytes!("../test_data/smaland.wowsreplay");
        let header = header(data);
        assert!(header.is_ok());
        let (data, _) = header.unwrap();
        let res = block(data);
        assert!(res.is_ok());
        let res = res.unwrap();

        let res =decrypted_block(data.1);
        assert!(res.is_ok());
        let res = res.unwrap();
    }
}