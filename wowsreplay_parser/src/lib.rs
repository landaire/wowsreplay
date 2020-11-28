pub mod parser;
pub mod wows;

use blowfish::cipher::{NewBlockCipher, BlockCipher};
use std::convert::TryInto;

const ENCRYPTION_KEY: [u8; 16] = [0x29, 0xb7, 0xc9, 0x09, 0x38, 0x3f, 0x84, 0x88, 0xfa, 0x98, 0xec, 0x4e, 0x13, 0x19, 0x79, 0xfb];

pub struct Unpacker {
    blowfish: blowfish::Blowfish,
}

impl Unpacker {
    pub fn new() -> Self {
        Unpacker {
            blowfish: blowfish::Blowfish::new_varkey(&ENCRYPTION_KEY).unwrap(),
        }
    }

    fn unpack(&mut self, data: &mut [u8], unpadded_len: usize) -> Vec<u8> {
        self.decrypt(data);
        self.decompress(&mut data[..unpadded_len])
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        let mut previous_block = &mut [0u8; 8];
        let mut chunks_iter = data.chunks_exact_mut(8);
        while let Some(block) = chunks_iter.next() {
            let block: &mut [u8] = block.try_into().unwrap();
            self.blowfish.decrypt_block(block.into());

            for (i, b) in previous_block.iter().enumerate() {
                block[i] ^= *b;
            }

            previous_block = block.try_into().unwrap();
        }

        let remainder = chunks_iter.into_remainder();
        if !remainder.is_empty() {
            let mut padded_block = [0u8; 8];
            for i in 0..remainder.len() {
                padded_block[i] = remainder[i];
            }

            let padded_block: &mut [u8] = &mut padded_block[..];

            self.blowfish.decrypt_block(padded_block.into());

            for (i, b) in previous_block.iter().enumerate() {
                padded_block[i] ^= *b;
            }

            for (i, b) in remainder.iter_mut().enumerate() {
                *b = padded_block[i];
            }
        }
    }

    fn decompress(&mut self, data: &mut [u8]) -> Vec<u8> {
        std::fs::write("data2.zlib", &*data);
        use std::io::prelude::*;
        use flate2::write::ZlibDecoder;
        let mut writer = Vec::new();

        let mut d = ZlibDecoder::new(writer);
        d.write_all(&*data).expect("failed to write");
        let output = d.finish().expect("failed to finish");
        //std::fs::write("data2.bin", &output);

        output
    }
}
