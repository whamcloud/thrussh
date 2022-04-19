// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use super::super::Error;
use byteorder::{BigEndian, ByteOrder};
use sodium::aes256gcm::*;
use sodium::random::randombytes;

pub struct OpeningKey {
    key: Key,
    nonce: Nonce,
}
pub struct SealingKey {
    key: Key,
    nonce: Nonce,
}

const TAG_LEN: usize = 16;

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: KEY_BYTES,
    nonce_len: NONCE_BYTES,
    make_sealing_cipher,
    make_opening_cipher,
};

pub const NAME: super::Name = super::Name("aes256-gcm@openssh.com");

fn make_sealing_cipher(k: &[u8], n: &[u8]) -> super::SealingCipher {
    let mut key = Key([0; KEY_BYTES]);
    let mut nonce = Nonce([0; NONCE_BYTES]);
    key.0.clone_from_slice(k);
    nonce.0.clone_from_slice(n);
    super::SealingCipher::AES256GCM(SealingKey { key, nonce })
}

fn make_opening_cipher(k: &[u8], n: &[u8]) -> super::OpeningCipher {
    let mut key = Key([0; KEY_BYTES]);
    let mut nonce = Nonce([0; NONCE_BYTES]);
    key.0.clone_from_slice(k);
    nonce.0.clone_from_slice(n);
    super::OpeningCipher::AES256GCM(OpeningKey { key, nonce })
}

const GCM_COUNTER_OFFSET: u64 = 3;

fn make_nonce(nonce: &Nonce, sequence_number: u32) -> Nonce {
    let mut new_nonce = Nonce([0; NONCE_BYTES]);
    new_nonce.0.clone_from_slice(&nonce.0);
    // Increment the nonce
    let i0 = NONCE_BYTES - 8;

    #[allow(clippy::indexing_slicing)] // length checked
    let ctr = BigEndian::read_u64(&new_nonce.0[i0..]);

    // GCM requires the counter to start from 1
    #[allow(clippy::indexing_slicing)] // length checked
    BigEndian::write_u64(
        &mut new_nonce.0[i0..],
        ctr + sequence_number as u64 - GCM_COUNTER_OFFSET,
    );
    new_nonce
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        // Packet length is sent unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];

        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&ciphertext_in_plaintext_out[..super::PACKET_LENGTH_LEN]);

        // Prepare a buffer for libsodium to read from
        let mut buffer = vec![0; ciphertext_in_plaintext_out.len() - super::PACKET_LENGTH_LEN];

        #[allow(clippy::indexing_slicing)] // length checked
        buffer.copy_from_slice(&ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..]);

        let nonce = make_nonce(&self.nonce, sequence_number);

        #[allow(clippy::indexing_slicing)] // length checked
        if !aes256gcm_decrypt(
            &mut ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..],
            tag,
            &buffer,
            &packet_length,
            &nonce,
            &self.key,
        ) {
            return Err(Error::DecryptionError);
        }
        Ok(ciphertext_in_plaintext_out)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        randombytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        // Packet length is received unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        // Prepare an output buffer
        let mut buffer = vec![0; plaintext_in_ciphertext_out.len()];
        buffer.splice(..super::PACKET_LENGTH_LEN, packet_length);

        let nonce = make_nonce(&self.nonce, sequence_number);
        #[allow(clippy::indexing_slicing)] // length checked
        aes256gcm_encrypt(
            &mut buffer[super::PACKET_LENGTH_LEN..],
            tag_out,
            &plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
            &packet_length,
            &nonce,
            &self.key,
        );
        plaintext_in_ciphertext_out.clone_from_slice(&buffer);
    }
}
