use hmac_sha512::HMAC;
use sodiumoxide::crypto::box_::Nonce;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox;

#[derive(Debug, Clone)]
pub struct SymmetricKeyRecipient {
    pub key: Vec<u8>,
    pub identifier: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SigncryptedMessageRecipient {
    pub recipient_identifier: Vec<u8>,
    pub encrypted_payload_key: Vec<u8>,
    pub index: u64,
    pub recipient_index: Vec<u8>,
}

impl SigncryptedMessageRecipient {
    const SHARED_KEY_NONCE: &'static [u8] = b"saltpack_derived_sboxkey";
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
        public_key: &[u8],
        ephemeral_private_key: &[u8],
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

        let encrypted_payload_key = secretbox::seal(
            payload_key,
            &secretbox::Nonce::from_slice(&recipient_index).unwrap(),
            &secretbox::Key::from_slice(&shared_symmetric_key).unwrap(),
        );

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
        let derived_key = &HMAC::mac(
            &[ephemeral_public_key, &recipient.key].concat(),
            Self::HMAC_KEY_SYMMETRIC,
        )[..32];
        log::info!("ephemeral_public_key: {:?}", ephemeral_public_key);
        log::info!("recipient.key: {:?}", recipient.key);
        log::info!(
            "data: {:?}",
            [ephemeral_public_key, &recipient.key].concat()
        );
        log::info!("create derived_key: {:?}", derived_key);

        let encrypted_payload_key = secretbox::seal(
            payload_key,
            &secretbox::Nonce::from_slice(&recipient_index).unwrap(),
            &secretbox::Key::from_slice(&derived_key).unwrap(),
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

    fn generate_recipient_index(index: u64) -> Vec<u8> {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&index.to_be_bytes());
        [Self::PAYLOAD_KEY_BOX_NONCE_PREFIX_V2, &buffer].concat()
    }

    pub fn decrypt_payload_key(&self, shared_symmetric_key: &[u8]) -> Option<Vec<u8>> {
        secretbox::open(
            &self.encrypted_payload_key,
            &secretbox::Nonce::from_slice(&self.recipient_index).unwrap(),
            &secretbox::Key::from_slice(shared_symmetric_key).unwrap(),
        )
        .ok()
    }

    pub fn generate_recipient_identifier_for_sender(
        public_key: &[u8],
        ephemeral_private_key: &[u8],
        recipient_index: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        // Convert inputs to sodiumoxide types
        let recipient_pk = PublicKey::from_slice(public_key).ok_or("Invalid public key")?;
        let ephemeral_sk =
            SecretKey::from_slice(ephemeral_private_key).ok_or("Invalid private key")?;
        let nonce = Nonce::from_slice(Self::SHARED_KEY_NONCE).unwrap();

        // Create a 32-byte zero-filled message
        let message = vec![0u8; 32];
        let ciphertext = box_::seal(&message, &nonce, &recipient_pk, &ephemeral_sk);
        let shared_symmetric_key = ciphertext[ciphertext.len() - 32..].to_vec();

        let recipient_identifier = HMAC::mac(
            &[shared_symmetric_key.as_ref(), recipient_index].concat(),
            Self::HMAC_KEY,
        );

        Ok((shared_symmetric_key, recipient_identifier[..32].to_vec()))
    }

    pub fn generate_recipient_identifier_for_recipient(
        ephemeral_public_key: &[u8],
        private_key: &[u8],
        recipient_index: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        // Convert inputs to sodiumoxide types
        let ephemeral_pk =
            PublicKey::from_slice(ephemeral_public_key).ok_or("Invalid private key")?;
        let recipient_sk = SecretKey::from_slice(private_key).ok_or("Invalid public key")?;
        let nonce = Nonce::from_slice(Self::SHARED_KEY_NONCE).unwrap();

        // Create a 32-byte zero-filled message
        let message = vec![0u8; 32];
        let ciphertext = box_::seal(&message, &nonce, &ephemeral_pk, &recipient_sk);
        let shared_symmetric_key = ciphertext[ciphertext.len() - 32..].to_vec();

        let recipient_identifier = HMAC::mac(
            &[shared_symmetric_key.as_ref(), recipient_index].concat(),
            Self::HMAC_KEY,
        );

        Ok((shared_symmetric_key, recipient_identifier[..32].to_vec()))
    }
}
