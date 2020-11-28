use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct Packet<'a> {
    pub data_len: u32,
    pub ty: u32,
    pub time: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub enum PacketData<'a> {
    String(&'a str),
}

#[derive(Debug)]
#[repr(u32)]
pub enum PacketType {
    Message = 0x8,
    String = 0x16,
    EOF = 0xFFFF_FFFF,
}

impl TryFrom<u32> for PacketType {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let ty = match value {
            0x8 => PacketType::Message,
            0x16 => PacketType::String,
            0xFFFF_FFFF => PacketType::EOF,
            _ => return Err("unknown packet type")
        };

        Ok(ty)
    }
}

impl<'a> Packet<'a> {
    pub fn ty(&self) -> Option<PacketType> {
        self.ty.try_into().ok()
    }

    pub fn deserialize(&self) -> Option<PacketData<'a>> {
        let ty = self.ty()?;

        match ty {
            // Game version
            PacketType::String => {
                let str_len = u32::from_le_bytes(
                    self.data[0..4]
                        .try_into()
                        .expect("failed to construct fixed-size array"),
                );

                if str_len  as usize > self.data.len() - std::mem::size_of_val(&str_len) {
                    eprintln!("Invalid string length specified: 0x{:X} -- cannot decode string", str_len);
                    return None;
                }

                Some(PacketData::String(
                    std::str::from_utf8(&self.data[4..str_len as usize + 4])
                        .expect("failed to convert packet string data to utf8 string"),
                ))
            }
            // EOF
            PacketType::EOF => {
                None
            }
            PacketType::Message => {
                None
            }
        }
    }
}
