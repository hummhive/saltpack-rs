use dryoc::{
    classic::{
        crypto_box::crypto_box_easy,
        crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy},
    },
    constants::{CRYPTO_BOX_MACBYTES, CRYPTO_SECRETBOX_MACBYTES},
};
use hmac_sha512::HMAC;

#[derive(Debug, Clone)]
pub struct SymmetricKeyRecipient {
    pub key: [u8; 32],
    pub identifier: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SigncryptedMessageRecipient {
    pub recipient_identifier: Vec<u8>,
    pub encrypted_payload_key: Vec<u8>,
    pub index: u64,
    pub recipient_index: [u8; 24],
}

impl SigncryptedMessageRecipient {
    const SHARED_KEY_NONCE: &'static [u8; 24] = b"saltpack_derived_sboxkey";
    const HMAC_KEY: &'static [u8] = b"saltpack signcryption box key identifier";
    pub const HMAC_KEY_SYMMETRIC: &'static [u8] = b"saltpack signcryption derived symmetric key";
    const PAYLOAD_KEY_BOX_NONCE_PREFIX_V2: &'static [u8] = b"saltpack_recipsb";

    pub fn new(
        recipient_identifier: Vec<u8>,
        encrypted_payload_key: Vec<u8>,
        index: u64,
    ) -> Result<Self, &'static str> {
        if recipient_identifier.len() != 32 {
            return Err("recipient_identifier must be a 32 byte Vec<u8>");
        }
        if encrypted_payload_key.len() != 48 {
            return Err("payload_key_box must be a 48 byte Vec<u8>");
        }

        let recipient_index = Self::generate_recipient_index(index);

        Ok(Self {
            recipient_identifier,
            encrypted_payload_key,
            index,
            recipient_index,
        })
    }

    pub fn create(
        public_key: &[u8; 32],
        ephemeral_private_key: &[u8; 32],
        payload_key: &[u8],
        index: u64,
    ) -> Result<Self, &'static str> {
        let recipient_index = Self::generate_recipient_index(index);

        let (shared_symmetric_key, recipient_identifier) =
            Self::generate_recipient_identifier_for_sender(
                public_key,
                ephemeral_private_key,
                &recipient_index,
            )?;
        log::info!("shared_symmetric_key: {:?}", shared_symmetric_key);

        let mut encrypted_payload_key = vec![0u8; payload_key.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(
            &mut encrypted_payload_key,
            payload_key,
            &recipient_index,
            &shared_symmetric_key,
        )
        .expect("Failed to encrypt payload key");

        let recip = Self::new(recipient_identifier, encrypted_payload_key, index)?;
        log::info!("recip: {:?}", recip);
        Ok(recip)
    }

    pub fn create_symmetric(
        recipient: SymmetricKeyRecipient,
        ephemeral_public_key: &[u8],
        payload_key: &[u8],
        index: u64,
    ) -> Result<Self, &'static str> {
        let recipient_index = Self::generate_recipient_index(index);
        let derived_key: [u8; 32] = HMAC::mac(
            &[ephemeral_public_key, &recipient.key].concat(),
            Self::HMAC_KEY_SYMMETRIC,
        )[..32]
            .try_into()
            .expect("HMAC output length is guaranteed to be 32 bytes");
        log::info!("ephemeral_public_key: {:?}", ephemeral_public_key);
        log::info!("recipient.key: {:?}", recipient.key);
        log::info!(
            "data: {:?}",
            [ephemeral_public_key, &recipient.key].concat()
        );
        log::info!("create derived_key: {:?}", derived_key);

        let mut encrypted_payload_key = vec![0u8; payload_key.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(
            &mut encrypted_payload_key,
            payload_key,
            &recipient_index,
            &derived_key,
        );

        let recip = Self::new(recipient.identifier, encrypted_payload_key, index)?;
        log::info!("recip: {:?}", recip);
        Ok(recip)
    }

    pub fn from(
        recipient_identifier: Vec<u8>,
        encrypted_payload_key: Vec<u8>,
        index: u64,
    ) -> Result<Self, &'static str> {
        Self::new(recipient_identifier, encrypted_payload_key, index)
    }

    fn generate_recipient_index(index: u64) -> [u8; 24] {
        let mut result = [0u8; 24];
        result[..16].copy_from_slice(Self::PAYLOAD_KEY_BOX_NONCE_PREFIX_V2);
        result[16..].copy_from_slice(&index.to_be_bytes());
        result
        // let mut buffer = [0u8; 8];
        // buffer.copy_from_slice(&index.to_be_bytes());
        // [Self::PAYLOAD_KEY_BOX_NONCE_PREFIX_V2, &buffer].concat()
    }

    pub fn decrypt_payload_key(&self, shared_symmetric_key: &[u8; 32]) -> Option<[u8; 32]> {
        let mut decrypted_message =
            vec![0u8; &self.encrypted_payload_key.len() - CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_open_easy(
            &mut decrypted_message,
            &self.encrypted_payload_key,
            &self.recipient_index,
            shared_symmetric_key,
        )
        .expect("Failed to decrypt payload key");

        Some(
            decrypted_message
                .try_into()
                .expect("payload key is not 32 bytes"),
        )
    }

    pub fn generate_recipient_identifier_for_sender(
        public_key: &[u8; 32],
        ephemeral_private_key: &[u8; 32],
        recipient_index: &[u8],
    ) -> Result<([u8; 32], Vec<u8>), &'static str> {
        // Create a 32-byte zero-filled message
        let message = vec![0u8; 32];
        let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
        crypto_box_easy(
            &mut ciphertext,
            &message,
            &Self::SHARED_KEY_NONCE,
            &public_key,
            &ephemeral_private_key,
        );
        let shared_symmetric_key: [u8; 32] =
            ciphertext[ciphertext.len() - 32..].try_into().unwrap();

        let recipient_identifier = HMAC::mac(
            &[shared_symmetric_key.as_ref(), recipient_index].concat(),
            Self::HMAC_KEY,
        );

        Ok((shared_symmetric_key, recipient_identifier[..32].to_vec()))
    }

    pub fn generate_recipient_identifier_for_recipient(
        ephemeral_public_key: &[u8; 32],
        private_key: &[u8; 32],
        recipient_index: &[u8],
    ) -> Result<([u8; 32], Vec<u8>), &'static str> {
        // Create a 32-byte zero-filled message
        let message = vec![0u8; 32];
        let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
        crypto_box_easy(
            &mut ciphertext,
            &message,
            &Self::SHARED_KEY_NONCE,
            &ephemeral_public_key,
            &private_key,
        );
        let shared_symmetric_key: [u8; 32] =
            ciphertext[ciphertext.len() - 32..].try_into().unwrap();

        let recipient_identifier = HMAC::mac(
            &[shared_symmetric_key.as_ref(), recipient_index].concat(),
            Self::HMAC_KEY,
        );

        Ok((shared_symmetric_key, recipient_identifier[..32].to_vec()))
    }
}
