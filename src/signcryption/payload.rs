use crate::signcryption::header::SigncryptedMessageHeader;
use dryoc::{
    classic::{
        crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy},
        crypto_sign::{crypto_sign_detached, crypto_sign_verify_detached},
    },
    constants::{CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SIGN_BYTES},
};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::error::Error;

#[derive(Debug, Clone)]
pub struct SigncryptedMessagePayload {
    payload_secretbox: Vec<u8>,
    pub final_flag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodedData<'a> {
    Packed(&'a [u8]),
    Unpacked(Vec<u8>, bool),
}

impl SigncryptedMessagePayload {
    // const PAYLOAD_NONCE_PREFIX: &'static [u8] = b"saltpack_ploadsb";

    pub fn new(payload_secretbox: Vec<u8>, final_flag: bool) -> Self {
        Self {
            payload_secretbox,
            final_flag,
        }
    }

    pub fn create(
        header: &SigncryptedMessageHeader,
        payload_key: &[u8; 32],
        private_key: Option<&[u8; 64]>,
        data: &[u8],
        index: u64,
        final_flag: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let header_hash = header.hash()?;
        let nonce = Self::generate_nonce(&header_hash, index, final_flag);

        let signature = if let Some(pk) = private_key {
            let signature_data =
                Self::generate_signature_data(&header_hash, &nonce, final_flag, data);
            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_detached(&mut signature, &signature_data, &pk);
            signature
        } else {
            [0u8; 64]
        };

        let message = &[signature.as_ref(), data].concat();
        let mut payload_secretbox = vec![0u8; message.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(&mut payload_secretbox, message, &nonce, payload_key);

        Ok(Self::new(payload_secretbox, final_flag))
    }

    fn generate_nonce(header_hash: &[u8], index: u64, final_flag: bool) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&header_hash[..16]);
        nonce[15] = if final_flag {
            nonce[15] | 0x01
        } else {
            nonce[15] & 0xfe
        };
        nonce[16..].copy_from_slice(&index.to_be_bytes());
        nonce
    }

    fn generate_signature_data(
        header_hash: &[u8],
        nonce: &[u8],
        final_flag: bool,
        data: &[u8],
    ) -> Vec<u8> {
        let mut signature_input = Vec::new();
        signature_input.extend_from_slice(b"saltpack encrypted signature");
        signature_input.push(0x00);
        signature_input.extend_from_slice(header_hash);
        signature_input.extend_from_slice(nonce);
        signature_input.push(if final_flag { 0x01 } else { 0x00 });
        signature_input.extend_from_slice(&Sha512::digest(data));
        signature_input
    }

    pub fn encode(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        let mut serializer = Serializer::new(&mut buf);
        (&self.payload_secretbox, self.final_flag).serialize(&mut serializer)?;
        Ok(buf)
    }

    pub fn decode(encoded: EncodedData, unpacked: bool) -> Result<Self, Box<dyn Error>> {
        let (payload_secretbox, final_flag) = match encoded {
            EncodedData::Packed(slice) => {
                if !unpacked {
                    let mut deserializer = Deserializer::new(slice);
                    Deserialize::deserialize(&mut deserializer)?
                } else {
                    return Err("Invalid data for packed format".into());
                }
            }
            EncodedData::Unpacked(payload_secretbox, final_flag) => {
                if unpacked {
                    (payload_secretbox, final_flag)
                } else {
                    return Err("Invalid data for unpacked format".into());
                }
            }
        };

        Ok(Self::new(payload_secretbox, final_flag))
    }

    pub fn decrypt(
        &self,
        header: &SigncryptedMessageHeader,
        public_key: Option<&[u8; 32]>,
        payload_key: &[u8; 32],
        index: u64,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (header_hash, _) = header.encode()?;
        let nonce = Self::generate_nonce(&header_hash, index, self.final_flag);

        let mut decrypted = vec![0u8; &self.payload_secretbox.len() - CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_open_easy(&mut decrypted, &self.payload_secretbox, &nonce, payload_key)
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?;

        let (signature, data) = decrypted.split_at(64);

        if let Some(pk) = public_key {
            let sign_data =
                Self::generate_signature_data(&header_hash, &nonce, self.final_flag, &data);

            let res = crypto_sign_verify_detached(&signature.try_into().unwrap(), &sign_data, &pk);
            if res.is_err() {
                return Err("Invalid payload signature".into());
            }
        }

        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use dryoc::{
        classic::{crypto_box::crypto_box_keypair, crypto_sign::crypto_sign_keypair},
        rng::randombytes_buf,
    };

    use super::*;

    #[test]
    fn test_generate_nonce_final() {
        let header_hash: [u8; 32] = randombytes_buf(32).try_into().unwrap();
        let index = 42;
        let final_flag = true;

        let nonce = SigncryptedMessagePayload::generate_nonce(&header_hash, index, final_flag);

        assert_eq!(nonce[..15], header_hash[..15]);
        assert_eq!(nonce[15] & 0x01, 0x01);
        assert_eq!(nonce[16..], index.to_be_bytes());
    }

    #[test]
    fn test_generate_nonce_non_final() {
        let header_hash: [u8; 32] = randombytes_buf(32).try_into().unwrap();
        let index = 42;
        let final_flag = false;

        let nonce = SigncryptedMessagePayload::generate_nonce(&header_hash, index, final_flag);

        assert_eq!(nonce[..15], header_hash[..15]);
        assert_eq!(nonce[15] & 0x01, 0x00);
        assert_eq!(nonce[16..], index.to_be_bytes());
    }

    #[test]
    fn test_generate_signature_data() {
        let header_hash: [u8; 32] = randombytes_buf(32).try_into().unwrap();
        let nonce: [u8; 24] = randombytes_buf(24).try_into().unwrap();
        let final_flag = false;
        let data = b"Test data";

        let signature_data = SigncryptedMessagePayload::generate_signature_data(
            &header_hash,
            &nonce,
            final_flag,
            data,
        );

        let expected_signature_data = [
            b"saltpack encrypted signature".as_ref(),
            &[0x00],
            header_hash.as_ref(),
            nonce.as_ref(),
            &[0x00],
            &Sha512::digest(data),
        ]
        .concat();

        assert_eq!(signature_data, expected_signature_data);
    }

    #[test]
    fn test_encode_and_decode() {
        let payload_secretbox: [u8; 100] = randombytes_buf(100).try_into().unwrap();
        let final_flag = true;

        let payload =
            SigncryptedMessagePayload::new(payload_secretbox.clone().to_vec(), final_flag);

        let encoded = payload.encode().expect("Failed to encode payload");
        let decoded = SigncryptedMessagePayload::decode(EncodedData::Packed(&encoded), false)
            .expect("Failed to decode payload");

        assert_eq!(decoded.payload_secretbox, payload_secretbox);
        assert_eq!(decoded.final_flag, final_flag);
    }

    #[test]
    fn test_create_and_decrypt_payload() {
        // Generate recipient's encryption keypair
        let (recipient_public_key, recipient_secret_key) = crypto_box_keypair();

        // Generate sender's signing keypair
        let (sender_public_key, sender_secret_key) = crypto_sign_keypair();
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        // Create a header with the recipient's public key
        let header = SigncryptedMessageHeader::create(
            recipient_public_key,
            payload_key.clone(),
            Some(sender_public_key.as_ref().to_vec()),
            vec![],
        )
        .expect("Failed to create header");

        // Sample data to signcrypt
        let data = b"Hello, world!";

        // Create a payload
        let payload = SigncryptedMessagePayload::create(
            &header,
            &payload_key,
            Some(&sender_secret_key),
            data,
            0,
            true,
        )
        .expect("Failed to create payload");

        // Decrypt the payload
        let decrypted_data = payload
            .decrypt(&header, Some(&sender_public_key), &payload_key, 0)
            .expect("Failed to decrypt payload");

        assert_eq!(decrypted_data, data);
    }
}
