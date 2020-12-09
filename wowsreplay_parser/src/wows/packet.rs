use byteorder::{LittleEndian, ReadBytesExt};
use std::convert::{TryFrom, TryInto};
use std::io::Cursor;

#[derive(Debug)]
pub struct Packet<'a> {
    pub data_len: u32,
    pub ty: u32,
    pub time: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub enum PacketData<'a> {
    CreateEntity(CreateEntity<'a>),
    ResetEntities(u8),
    SetGameTimer(u64),
    Packet0x25(u32, u16, &'a [u8]),
    String(&'a str),
}

#[derive(Debug)]
pub struct CreateEntity<'a> {
    pub unk: u32,
    pub entity_id: u32,
    pub args: CreateEntityArgs<'a>,
}

#[derive(Debug)]
pub struct MessageArgs<'a> {
    pub sender_id: u32,
    pub channel: &'a str,
    pub text: &'a str,
}


#[derive(Debug)]
pub enum CreateEntityArgs<'a> {
    Message(MessageArgs<'a>),
    Other(&'a [u8]),
}

#[derive(Debug)]
pub enum ChatChannel {
    Team,
    Division,
    All,
}

use std::str::FromStr;
impl FromStr for ChatChannel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "battle_team" => Ok(Self::Team),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum PacketType {
    MaybeCreateEntity = 0x8,
    ResetEntities = 0x10,
    SetGameStartTimeMicroSeconds = 0xF,
    GameVersion = 0x16,
    // BWEntities::handleBasePlayerCreate
    HandleBasePlayerCreate = 0x25,
    EOF = 0xFFFF_FFFF,
}

impl TryFrom<u32> for PacketType {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let ty = match value {
            0x8 => PacketType::MaybeCreateEntity,
            0xF => PacketType::SetGameStartTimeMicroSeconds,
            0x16 => PacketType::GameVersion,
            0x25 => PacketType::HandleBasePlayerCreate,
            0xFFFF_FFFF => PacketType::EOF,
            _ => return Err("unknown packet type"),
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
        let mut rdr = Cursor::new(&self.data);

        match ty {
            // Game version
            PacketType::GameVersion => {
                let str_len = rdr.read_u32::<LittleEndian>().unwrap();

                if str_len as usize > self.data.len() - std::mem::size_of_val(&str_len) {
                    eprintln!(
                        "Invalid string length specified: 0x{:X} -- cannot decode string",
                        str_len
                    );
                    return None;
                }

                let offset = rdr.position() as usize;
                Some(PacketData::String(
                    std::str::from_utf8(&self.data[offset..offset + str_len as usize])
                        .expect("failed to convert packet string data to utf8 string"),
                ))
            }
            PacketType::ResetEntities => Some(PacketData::ResetEntities(self.data[0])),
            PacketType::HandleBasePlayerCreate => {
                //let data_len: u32 = u32::from_le_bytes(self.data[6..10].try_into().unwrap());
                Some(PacketData::Packet0x25(
                    rdr.read_u32::<LittleEndian>().unwrap(),
                    rdr.read_u16::<LittleEndian>().unwrap(),
                    &self.data[rdr.position() as usize..],
                ))
            }
            PacketType::MaybeCreateEntity => {
                let unk = rdr.read_u32::<LittleEndian>().unwrap();
                let entity_id = rdr.read_u32::<LittleEndian>().unwrap();
                let data_len = rdr.read_u32::<LittleEndian>().unwrap();
                let args = match entity_id {
                    0x72 => {
                        let sender_id = rdr.read_u32::<LittleEndian>().unwrap();

                        let channel_len = rdr.read_u8().unwrap() as usize;
                        let offset = rdr.position() as usize;
                        let channel =
                            std::str::from_utf8(&self.data[offset..offset + channel_len]).unwrap();

                        rdr.set_position((offset+channel_len) as u64);

                        let text_len = rdr.read_u8().unwrap() as usize;
                        let offset = rdr.position() as usize;
                        let text =
                            std::str::from_utf8(&self.data[offset..offset + text_len]).unwrap();

                        rdr.set_position((offset+channel_len) as u64);

                        CreateEntityArgs::Message(MessageArgs {
                            sender_id,
                            channel,
                            text,
                        })
                    }
                    _ => {
                        let offset = rdr.position() as usize;
                        CreateEntityArgs::Other(&self.data[offset..])
                    }
                };
                Some(PacketData::CreateEntity(CreateEntity { unk, entity_id, args }))
            }
            PacketType::SetGameStartTimeMicroSeconds => Some(PacketData::SetGameTimer(
                rdr.read_u64::<LittleEndian>().unwrap(),
            )),
            // EOF
            PacketType::EOF => None,
        }
    }
}
