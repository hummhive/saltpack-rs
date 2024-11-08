use crate::signcryption::header::SigncryptedMessageHeader;
use crate::signcryption::payload::SigncryptedMessagePayload;
use crate::signcryption::recipient::{SigncryptedMessageRecipient, SymmetricKeyRecipient};
use dryoc::classic::crypto_box::crypto_box_keypair;
use dryoc::rng::randombytes_buf;
use rmp_serde::Deserializer;
use std::error::Error;

use super::payload::EncodedData;

const CHUNK_LENGTH: usize = 1024 * 1024;

pub struct Signcryption;

impl Signcryption {
    pub fn signcrypt(
        data: &[u8],
        keypair: Option<([u8; 32], [u8; 64])>,
        recipients_keys: Option<&[[u8; 32]]>,
        symmetric_key_recipients: Option<&[SymmetricKeyRecipient]>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let chunks = Self::chunk_buffer(data, CHUNK_LENGTH);

        // 1. Generate a random 32-byte payload key.
        let payload_key: [u8; 32] = randombytes_buf(32).try_into().unwrap();

        // 2. Generate a random ephemeral keypair.
        let ephemeral_keypair = crypto_box_keypair();

        let mut recipients = vec![];
        // recipients_keys
        //     .iter()
        //     .enumerate()
        //     .map(|(index, &key)| {

        if let Some(keys) = recipients_keys {
            for (index, key) in keys.iter().enumerate() {
                let recipient_instance = SigncryptedMessageRecipient::create(
                    key,
                    &ephemeral_keypair.1,
                    &payload_key,
                    index as u64,
                )?;
                recipients.push(recipient_instance);
            }
        }
        // .collect::<Result<Vec<_>, _>>()?;

        if let Some(sym_recipients) = symmetric_key_recipients {
            for (index, recipient) in sym_recipients.iter().enumerate() {
                let recipient_instance = SigncryptedMessageRecipient::create_symmetric(
                    recipient.clone(),
                    ephemeral_keypair.0.as_ref(),
                    &payload_key,
                    (recipients_keys.unwrap_or(&[]).len() + index) as u64,
                )?;
                recipients.push(recipient_instance);
            }
        }

        let header = SigncryptedMessageHeader::create(
            ephemeral_keypair.0,
            payload_key.clone(),
            keypair.clone().map(|kp| kp.0.as_ref().to_vec()),
            recipients,
        )?;

        let mut payloads = Vec::new();

        for (i, chunk) in chunks.iter().enumerate() {
            let final_chunk = i == chunks.len() - 1;
            let payload = SigncryptedMessagePayload::create(
                &header,
                &payload_key,
                keypair.as_ref().map(|kp| &kp.1),
                chunk,
                i as u64,
                final_chunk,
            )?;

            payloads.push(payload);
        }

        let mut result = header.encoded()?;
        for payload in payloads.clone() {
            result.extend_from_slice(&payload.encode()?);
        }

        Ok(result)
    }

    fn chunk_buffer(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        data.chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    pub fn designcrypt(
        signcrypted: &[u8],
        keypair_or_symmetric_key_recipient: Either<&[u8; 32], &SymmetricKeyRecipient>,
        sender: Option<&[u8]>,
    ) -> Result<DesigncryptResult, Box<dyn Error>> {
        let mut deserializer = Deserializer::new(signcrypted);

        let header = SigncryptedMessageHeader::decode(&signcrypted, Some(false))
            .map_err(|e| format!("Failed to decode header: {}", e))?;

        let header_length = header.encoded()?.len();

        // Slice the payloads from the signcrypted message
        let payloads_data = &signcrypted[header_length..];

        // ... rest of the code ...

        // let mut output = Vec::new();

        // Deserialize the payloads
        // let mut deserializer = Deserializer::new(payloads_data);
        let payload = SigncryptedMessagePayload::decode(EncodedData::Packed(payloads_data), false)?;
        let payload_key_and_recipient = match keypair_or_symmetric_key_recipient {
            Either::Left(secret_key) => header
                .decrypt_payload_key_with_curve25519_keypair(secret_key)
                .map_err(|e| {
                    format!(
                        "Failed to decrypt payload key with curve25519 keypair: {}",
                        e
                    )
                })?,
            Either::Right(recipient) => header.decrypt_payload_key_with_symmetric_key(
                &recipient.key,
                Some(&recipient.identifier),
            ),
        };

        let (payload_key, recipient) =
            payload_key_and_recipient.ok_or("Not an intended recipient")?;
        let sender_public_key = header
            .decrypt_sender(&payload_key)
            .map_err(|e| format!("Failed to decrypt sender public key: {}", e))?;
        let decrypted_payload =
            payload.decrypt(&header, sender_public_key.as_ref(), &payload_key, 0)?;
        // while let Some(item) = Deserialize::deserialize(&mut deserializer).ok() {

        // ... payload validation and decryption ...

        // output.extend_from_slice(&payload.decrypt(
        //     &header,
        //     sender_public_key.as_ref().map(|spk| spk.as_slice()),
        //     &payload_key,
        //     i as u64,
        // )?);
        // }

        // Deserialize the payloads
        // let mut items: Vec<SigncryptedMessagePayload> = Vec::new();
        // let result = SigncryptedMessagePayload::decode(
        //     EncodedData::Unpacked(signcrypted.to_vec(), true),
        //     true,
        // );
        // match result {
        //     Ok(item) => {
        //         items.push(item);
        //     }
        //     Err(e) => {
        //         log::error!("Deserialization failed: {:?}", e);
        //     }
        // }

        // log::info!("Deserialized {} items", items.len());
        // log::info!("Deserialized {:?}", items);
        // if items.is_empty() {
        //     log::warn!("No items were deserialized from the input");
        // }

        if let Some(expected_sender) = sender {
            if sender_public_key
                .as_ref()
                .map(|spk| spk != expected_sender)
                .unwrap_or(true)
            {
                return Err("Sender public key doesn't match".into());
            }
        }

        let mut output = Vec::new();
        // let mut items: Vec<EncodedData> = Vec::new();

        // log::info!("deserialize");
        // while let Some(item) = Deserialize::deserialize(&mut deserializer).ok() {
        //     log::info!("item: {:?}", item);
        //     items.push(item);
        // }

        // if items.is_empty() {
        //     return Err("No signcrypted payloads, message truncated?".into());
        // }

        // for (i, payload) in items.iter().enumerate() {
        // let payload = SigncryptedMessagePayload::decode(
        //     EncodedData::Unpacked(message.clone()., true),
        //     true,
        // )?;

        // let final_payload = i == items.len() - 1;
        // if payload.final_flag && !final_payload {
        //     return Err("Found payload with invalid final flag, message extended?".into());
        // }
        // if !payload.final_flag && final_payload {
        //     return Err("Found payload with invalid final flag, message truncated?".into());
        // }

        output.extend_from_slice(&payload.decrypt(
            &header,
            sender_public_key.as_ref(),
            &payload_key,
            0, // i as u64,
        )?);
        // }

        Ok(DesigncryptResult {
            data: output,
            sender_public_key,
        })
    }
}

pub struct DesigncryptResult {
    pub data: Vec<u8>,
    pub sender_public_key: Option<[u8; 32]>,
}

pub enum Either<L, R> {
    Left(L),
    Right(R),
}

#[cfg(test)]
mod tests {
    use dryoc::classic::crypto_sign::crypto_sign_keypair;

    use super::*;

    #[test]
    fn test_signcryption_with_asymmetric_recipient() {
        env_logger::init();
        // Generate recipient's encryption keypair
        let (recipient_public_key, recipient_secret_key) = crypto_box_keypair();

        // Generate sender's signing keypair
        let (sender_public_key, sender_secret_key) = crypto_sign_keypair();

        // Sample data to signcrypt
        let data = b"Hello, world!";

        // Signcrypt the data
        let signcrypted_data = Signcryption::signcrypt(
            data,
            Some((sender_public_key, sender_secret_key)),
            Some(&[recipient_public_key]),
            None,
        )
        .expect("Signcryption failed");

        // Designcrypt the data using the recipient's secret key
        let result = Signcryption::designcrypt(
            &signcrypted_data,
            Either::Left(&recipient_secret_key),
            Some(sender_public_key.as_ref()),
        )
        .expect("Designcryption failed");

        assert_eq!(result.data, data);
        assert_eq!(result.sender_public_key, Some(sender_public_key));
    }

    #[test]
    fn test_signcryption_with_symmetric_recipient() {
        // Generate sender's signing keypair
        let (sender_public_key, sender_secret_key) = crypto_sign_keypair();

        // Create a symmetric key recipient
        let symmetric_key_recipient = SymmetricKeyRecipient {
            identifier: [1u8; 32].to_vec(),
            key: randombytes_buf(32).try_into().unwrap(),
        };

        // Sample data to signcrypt
        let data = b"Hello, world!";

        // Signcrypt the data
        let signcrypted_data = Signcryption::signcrypt(
            data,
            Some((sender_public_key, sender_secret_key)),
            None,
            Some(&[symmetric_key_recipient.clone()]),
        )
        .expect("Signcryption failed");

        // Designcrypt the data using the recipient's secret key
        let result = Signcryption::designcrypt(
            &signcrypted_data,
            Either::Right(&symmetric_key_recipient),
            Some(sender_public_key.as_ref()),
        )
        .expect("Designcryption failed");

        assert_eq!(result.data, data);
        assert_eq!(result.sender_public_key, Some(sender_public_key));
    }

    #[test]
    fn test_signcryption_and_designcryption_with_large_data() {
        // ... similar test with large data exceeding the chunk size ...
    }

    #[test]
    fn test_designcryption_with_invalid_sender() {
        // ... test designcryption with an invalid sender public key ...
    }

    #[test]
    fn test_designcryption_with_truncated_message() {
        // ... test designcryption with a truncated signcrypted message ...
    }

    // ... more test cases covering different scenarios ...
}
