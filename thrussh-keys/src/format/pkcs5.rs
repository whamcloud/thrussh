use super::{decode_rsa, pkcs_unpad, Encryption};
use crate::key;
use crate::Error;

use openssl::hash::{Hasher, MessageDigest};
use openssl::symm::{decrypt, Cipher};

/// Decode a secret key in the PKCS#5 format, possible deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&[u8]>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut h = Hasher::new(MessageDigest::md5()).unwrap();
                h.update(pass).unwrap();
                h.update(&iv[..8]).unwrap();
                let md5 = h.finish().unwrap();
                let mut dec = decrypt(Cipher::aes_128_cbc(), &md5, Some(&iv[..]), secret)?;
                pkcs_unpad(&mut dec);
                dec
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        decode_rsa(&sec)
    } else {
        Err(Error::KeyIsEncrypted.into())
    }
}
