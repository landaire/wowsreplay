use wowsreplay_parser::*;
use wowsreplay_parser::parser::*;
use wowsreplay_parser::wows::packet::*;
use structopt::StructOpt;
use std::path::PathBuf;
use std::fs::File;
use memmap::MmapOptions;

#[derive(Debug, StructOpt)]
#[structopt(name = "wowsreplay", about = "WoWs replay parser")]
struct Opt {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Output file for the decrypted/decompressed blob contents
    #[structopt(long = "packets", parse(from_os_str))]
    packet_output: Option<PathBuf>,

    /// Output file for the JSON metadata
    #[structopt(long = "metadata", parse(from_os_str))]
    metadata_output: Option<PathBuf>,
}

fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    let file = File::open(opt.input)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let data = &mmap;

    let header = header(data);
    assert!(header.is_ok());
    let (data, header) = header.unwrap();

    if let Some(game_metadata_output) = opt.metadata_output {
        let json: serde_json::Value = serde_json::from_slice(header.metadata).unwrap();
        std::fs::write(game_metadata_output, serde_json::to_string_pretty(&json).unwrap())?;
    }

    let res = block(data);
    assert!(res.is_ok());

    let (len, encrypted_block) = res.unwrap().1;
    let mut encrypted_block = encrypted_block.to_vec();

    let mut unpacker = wowsreplay_parser::Unpacker::new();
    let unpacked = unpacker.unpack(encrypted_block.as_mut_slice(), len);

    if let Some(packets_out) = opt.packet_output {
        std::fs::write(packets_out, &unpacked)?;
    }

    let mut network_data = unpacked.as_slice();

    let mut unique_packet_types = std::collections::BTreeMap::<u32, usize>::new();
    while network_data.len() > 0xC {
        let parse_result = parse_replay_network_data(network_data).unwrap();
        network_data = parse_result.0;
        let packet = parse_result.1;

        *unique_packet_types.entry(packet.ty).or_default() += 1;
        if let Some(PacketType::MaybeCreateEntity) = packet.ty() {
            if let Some(PacketData::CreateEntity(entity_args)) = packet.deserialize() {
                if let CreateEntityArgs::Message(message_data) = entity_args.args {
                    println!("0x{:X} ({}): {}", message_data.sender_id, message_data.channel, message_data.text);
                }
            }
        }
    }

    // let res =decrypted_block(data.1);
    // assert!(res.is_ok());
    // let res = res.unwrap();

    Ok(())
}
