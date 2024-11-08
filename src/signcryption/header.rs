use dryoc::classic::crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy};
use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;
use hmac_sha512::HMAC;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::error::Error;
use std::fmt;

use super::recipient::SigncryptedMessageRecipient;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    Encryption = 0,
    AttachedSigning = 1,
    DetachedSigning = 2,
    Signcryption = 3,
}

#[derive(Debug, Clone)]
pub struct SigncryptedMessageHeader {
    public_key: [u8; 32],
    sender_secretbox: Vec<u8>,
    pub recipients: Vec<SigncryptedMessageRecipient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderData(
    String,
    (u8, u8),
    MessageType,
    [u8; 32],
    Vec<u8>,
    Vec<(Vec<u8>, Vec<u8>)>,
);

impl SigncryptedMessageHeader {
    const SENDER_KEY_SECRETBOX_NONCE: &'static [u8; 24] = b"saltpack_sender_key_sbox";

    pub fn new(
        public_key: [u8; 32],
        sender_secretbox: Vec<u8>,
        recipients: Vec<SigncryptedMessageRecipient>,
    ) -> Result<Self, SigncryptedMessageHeaderError> {
        if public_key.len() != 32 {
            return Err(SigncryptedMessageHeaderError::InvalidPublicKey);
        }
        if sender_secretbox.len() != 48 {
            return Err(SigncryptedMessageHeaderError::InvalidSenderSecretbox);
        }

        Ok(Self {
            public_key,
            sender_secretbox,
            recipients,
        })
    }

    pub fn encoded(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(Self::encode(self)?.1)
    }
    /** The SHA512 hash of the MessagePack encoded inner header data */
    pub fn hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(Self::encode(self)?.0)
    }

    pub fn create(
        public_key: [u8; 32],
        payload_key: [u8; 32],
        sender_public_key: Option<Vec<u8>>,
        recipients: Vec<SigncryptedMessageRecipient>,
    ) -> Result<Self, SigncryptedMessageHeaderError> {
        // if let Some(ref spk) = sender_public_key {
        //     if spk.len() != 32 {
        //         return Err(SigncryptedMessageHeaderError::InvalidSenderPublicKey);
        //     }
        // }
        if payload_key.len() != 32 {
            return Err(SigncryptedMessageHeaderError::InvalidPayloadKey);
        }

        // If Alice wants to be anonymous to recipients as well, she can supply an all-zero signing public key
        let sender_public_key = sender_public_key.unwrap_or_else(|| vec![0; 32]);

        // Encrypt the sender's long-term public key signing key using crypto_secretbox with the payload key and
        // the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        let mut sender_secretbox = vec![0u8; sender_public_key.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(
            &mut sender_secretbox,
            &sender_public_key,
            &Self::SENDER_KEY_SECRETBOX_NONCE,
            &payload_key,
        )
        .expect("Failed to encrypt sender secretbox");

        Self::new(public_key, sender_secretbox, recipients)
    }

    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let data: HeaderData = HeaderData(
            "saltpack".to_string(),
            (2, 0),
            MessageType::Signcryption,
            self.public_key.clone(),
            self.sender_secretbox.clone(),
            self.recipients
                .iter()
                .map(|recipient| {
                    (
                        recipient.recipient_identifier.clone(),
                        recipient.encrypted_payload_key.clone(),
                    )
                })
                .collect::<Vec<_>>(),
        );

        let encoded = rmp_serde::to_vec(&data)?;
        let header_hash = Sha512::digest(&encoded);
        let double_encoded = rmp_serde::to_vec(&encoded)?;

        Ok((header_hash.to_vec(), double_encoded))
    }

    pub fn decode(encoded: &[u8], unwrapped: Option<bool>) -> Result<Self, Box<dyn Error>> {
        let unwrapped = unwrapped.unwrap_or(false);

        // 1-3
        let data = if unwrapped {
            encoded.to_vec()
        } else {
            rmp_serde::from_slice(encoded).map_err(|_| "Failed to decode MessagePack data")?
        };

        let mut hasher = Sha512::new();
        hasher.update(&data);
        let header_hash = hasher.finalize().to_vec();

        let inner: HeaderData = rmp_serde::from_slice(&data)
            .map_err(|e| format!("Failed to decode inner MessagePack data: {:?}", e))?;

        let HeaderData(
            format_name,
            version,
            message_type,
            public_key,
            sender_secretbox,
            recipients,
        ) = inner;

        if format_name != "saltpack" {
            return Err("Invalid data".into());
        }

        if version != (2, 0) {
            return Err("Unsupported version".into());
        }

        if !matches!(message_type, MessageType::Signcryption) {
            return Err("Invalid data".into());
        }

        // Ok((header_hash, inner))

        if message_type != MessageType::Signcryption {
            return Err(Box::new(SigncryptedMessageHeaderError::InvalidData));
        }

        let recipients = recipients
            .into_iter()
            .enumerate()
            .map(|(index, (recipient_identifier, encrypted_payload_key))| {
                SigncryptedMessageRecipient::new(
                    recipient_identifier,
                    encrypted_payload_key,
                    index as u64,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            public_key,
            sender_secretbox,
            recipients,
        })
    }

    pub fn decrypt_payload_key_with_curve25519_keypair(
        &self,
        private_key: &[u8; 32],
    ) -> Result<Option<([u8; 32], SigncryptedMessageRecipient)>, Box<dyn Error>> {
        for recipient in &self.recipients {
            let (shared_symmetric_key, recipient_identifier) =
                SigncryptedMessageRecipient::generate_recipient_identifier_for_recipient(
                    &self.public_key,
                    private_key,
                    &recipient.recipient_index,
                )?;

            if recipient_identifier.ne(&recipient.recipient_identifier) {
                continue;
            }

            let payload_key = recipient
                .decrypt_payload_key(&shared_symmetric_key)
                .unwrap();
            return Ok(Some((payload_key, recipient.clone())));
        }

        Ok(None)
    }

    pub fn decrypt_payload_key_with_symmetric_key(
        &self,
        shared_symmetric_key: &[u8],
        recipient_identifier: Option<&[u8]>,
    ) -> Option<([u8; 32], SigncryptedMessageRecipient)> {
        let mut data = self.public_key.clone().to_vec();
        data.extend_from_slice(shared_symmetric_key);

        let derived_key: [u8; 32] =
            HMAC::mac(&data, SigncryptedMessageRecipient::HMAC_KEY_SYMMETRIC)[..32]
                .try_into()
                .unwrap();

        for recipient in &self.recipients {
            if let Some(identifier) = recipient_identifier {
                if identifier != recipient.recipient_identifier {
                    continue;
                }
            }

            if let Some(payload_key) = recipient.decrypt_payload_key(&derived_key) {
                return Some((payload_key, recipient.clone()));
            }
        }

        None
    }

    pub fn decrypt_sender(
        &self,
        payload_key: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, Box<dyn Error>> {
        let mut sender_public_key =
            vec![0u8; self.sender_secretbox.len() - CRYPTO_SECRETBOX_MACBYTES];
        let res = crypto_secretbox_open_easy(
            &mut sender_public_key,
            &self.sender_secretbox,
            &Self::SENDER_KEY_SECRETBOX_NONCE,
            payload_key,
        );

        if res.is_err() {
            return Err(Box::new(
                SigncryptedMessageHeaderError::InvalidSenderPublicKey,
            ));
        }

        if sender_public_key.clone() == vec![0; 32] {
            return Ok(None);
        }

        Ok(Some(
            sender_public_key
                .try_into()
                .expect("sender public key is not 32 bytes"),
        ))
    }
}

#[derive(Debug)]
pub enum SigncryptedMessageHeaderError {
    InvalidPublicKey,
    InvalidSenderSecretbox,
    InvalidSenderPublicKey,
    InvalidPayloadKey,
    InvalidData,
}

impl fmt::Display for SigncryptedMessageHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for SigncryptedMessageHeaderError {}

#[cfg(test)]
mod tests {
    use dryoc::{
        classic::{crypto_box::crypto_box_keypair, crypto_sign::crypto_sign_keypair},
        rng::randombytes_buf,
    };

    use crate::signcryption::recipient::SymmetricKeyRecipient;

    use super::*;

    #[test]
    fn test_create_and_decode_header() {
        // Generate recipient's encryption keypair
        let (recipient_public_key, _recipient_secret_key) = crypto_box_keypair();

        // Generate sender's signing keypair
        let (sender_public_key, _sender_secret_key) = crypto_sign_keypair();

        // Generate a random payload key
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        // Create a header
        let header = SigncryptedMessageHeader::create(
            recipient_public_key,
            payload_key.clone(),
            Some(sender_public_key.as_ref().to_vec()),
            vec![],
        )
        .expect("Failed to create header");

        // Encode the header
        let encoded_header = header.encoded().expect("Failed to encode header");

        // Decode the header
        let decoded_header = SigncryptedMessageHeader::decode(&encoded_header, None)
            .expect("Failed to decode header");

        // Check if the decoded header matches the original header
        assert_eq!(decoded_header.public_key, recipient_public_key);
        assert_eq!(decoded_header.sender_secretbox, header.sender_secretbox);
        // assert_eq!(decoded_header.recipients, header.recipients);
    }

    #[test]
    fn test_decrypt_payload_key_with_curve25519_keypair() {
        // Generate recipient's encryption keypair
        let (recipient_public_key, recipient_secret_key) = crypto_box_keypair();

        // Generate sender's signing keypair
        let (sender_public_key, _sender_secret_key) = crypto_sign_keypair();

        // Generate a random payload key
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        let ephemeral_keypair = crypto_box_keypair();
        let recipient = SigncryptedMessageRecipient::create(
            &recipient_public_key,
            &ephemeral_keypair.1,
            &payload_key,
            0,
        )
        .unwrap();

        // Create a header with the recipient's public key
        let header = SigncryptedMessageHeader::create(
            ephemeral_keypair.0,
            payload_key.clone(),
            Some(sender_public_key.as_ref().to_vec()),
            vec![recipient],
        )
        .expect("Failed to create header");

        // Decrypt the payload key using the recipient's secret key
        let decrypted_payload_key = header
            .decrypt_payload_key_with_curve25519_keypair(&recipient_secret_key)
            .expect("Failed to decrypt payload key")
            .expect("Payload key not found");

        // Check if the decrypted payload key matches the original payload key
        assert_eq!(decrypted_payload_key.0, payload_key);
    }

    #[test]
    fn test_decrypt_payload_key_with_symmetric_key() {
        // Generate sender's signing keypair
        let (sender_public_key, _sender_secret_key) = crypto_sign_keypair();

        // Generate a random payload key
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        let ephemeral_keypair = crypto_box_keypair();

        // Generate a random shared symmetric key
        let shared_symmetric_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        let symmetric_key_recipient = SymmetricKeyRecipient {
            identifier: [1u8; 32].to_vec(),
            key: shared_symmetric_key.clone(),
        };

        // Create a recipient with the shared symmetric key
        // let recipient = SigncryptedMessageRecipient::new_with_symmetric_key(
        //     &recipient_public_key,
        //     &payload_key,
        //     &shared_symmetric_key,
        // )
        // .expect("Failed to create recipient");

        let recipient = SigncryptedMessageRecipient::create_symmetric(
            symmetric_key_recipient.clone(),
            ephemeral_keypair.0.as_ref(),
            &payload_key,
            0,
        )
        .unwrap();

        // Create a header with the recipient
        let header = SigncryptedMessageHeader::create(
            ephemeral_keypair.0,
            payload_key.clone(),
            Some(sender_public_key.as_ref().to_vec()),
            vec![recipient.clone()],
        )
        .expect("Failed to create header");

        // Decrypt the payload key using the shared symmetric key
        let decrypted_payload_key = header
            .decrypt_payload_key_with_symmetric_key(
                &shared_symmetric_key,
                Some(&recipient.recipient_identifier),
            )
            .expect("Failed to decrypt payload key");

        // Check if the decrypted payload key matches the original payload key
        assert_eq!(decrypted_payload_key.0, payload_key);
    }

    #[test]
    fn test_decrypt_sender() {
        // Generate recipient's encryption keypair
        let (recipient_public_key, _recipient_secret_key) = crypto_box_keypair();

        // Generate sender's signing keypair
        let (sender_public_key, _sender_secret_key) = crypto_sign_keypair();

        // Generate a random payload key
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();
        // Create a header with the sender's public key
        let header = SigncryptedMessageHeader::create(
            recipient_public_key,
            payload_key.clone(),
            Some(sender_public_key.as_ref().to_vec()),
            vec![],
        )
        .expect("Failed to create header");

        // Decrypt the sender's public key
        let decrypted_sender_public_key = header
            .decrypt_sender(&payload_key)
            .expect("Failed to decrypt sender public key")
            .expect("Sender public key not found");

        // Check if the decrypted sender's public key matches the original sender's public key
        assert_eq!(decrypted_sender_public_key, sender_public_key);
    }
}
