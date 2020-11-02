pub mod parser;
use blowfish::cipher::{NewBlockCipher, BlockCipher, block::Key};

const ENCRYPTION_KEY: [u8; 16] = [0xDE, 0x72, 0xBE, 0xA0, 0xDE, 0x04, 0xBE, 0xB1, 0xDE, 0xFE, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];

struct Decryptor {
    prev_block: Option<[u8; 8]>,
    blowfish: blowfish::Blowfish,
}

impl Decryptor {
    pub fn new() -> Self {
        Decryptor {
            prev_block: None,
            blowfish: blowfish::Blowfish::new_varkey(&ENCRYPTION_KEY).unwrap(),
        }
    }

    fn decrypt_block(&mut self, encrypted_block: &mut [u8; 8]) {
        self.blowfish.decrypt_block(encrypted_block.into());
        if let Some(prev_block) = self.prev_block.take() {
            for (i, b) in prev_block.iter().enumerate() {
                encrypted_block[i] ^= *b;
            }
            self.prev_block = Some(encrypted_block.clone());
        }
    }
}
