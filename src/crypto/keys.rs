use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("failed to generate key: {0}")]
    KeyGenError(String),
    #[error("failed to encode key: {0}")]
    EncodeError(String),
    #[error("random generation failed: {0}")]
    RandomError(String),
}

pub struct EcKeyPair {
    pub private_key_der: Vec<u8>,
    pub public_key_der: Vec<u8>,
    pub signing_key: SigningKey,
}

pub fn generate_ec_key_pair() -> Result<EcKeyPair, CryptoError> {
    let signing_key = SigningKey::random(&mut OsRng);

    let private_key_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?
        .as_bytes()
        .to_vec();

    let verifying_key = VerifyingKey::from(&signing_key);
    let public_key_der = verifying_key
        .to_public_key_der()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?
        .as_bytes()
        .to_vec();

    Ok(EcKeyPair {
        private_key_der,
        public_key_der,
        signing_key,
    })
}

pub fn generate_random_wg_pubkey() -> Result<String, CryptoError> {
    use base64::Engine;
    let mut pubkey = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut pubkey)
        .map_err(|e| CryptoError::RandomError(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(pubkey))
}

pub fn generate_random_serial() -> Result<String, CryptoError> {
    let mut serial = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut serial)
        .map_err(|e| CryptoError::RandomError(e.to_string()))?;
    Ok(hex::encode(serial))
}

pub fn time_as_cf_string(time: chrono::DateTime<chrono::Local>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
}

use ring::rand::SecureRandom;

pub fn generate_self_signed_cert(signing_key: &SigningKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use der::{Decode, Encode};
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let subject = Name::default();
    let serial = SerialNumber::new(&[0u8])
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let validity = Validity::from_now(std::time::Duration::from_secs(24 * 60 * 60))
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let verifying_key = VerifyingKey::from(signing_key);
    let public_key_der = verifying_key
        .to_public_key_der()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let spki = SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let signer = EcdsaSigner::new(signing_key.clone());

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        spki,
        &signer,
    ).map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let cert = builder.build::<p256::ecdsa::DerSignature>()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let cert_der = cert.to_der()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?;

    let private_key_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::EncodeError(e.to_string()))?
        .as_bytes()
        .to_vec();

    Ok((cert_der, private_key_der))
}

struct EcdsaSigner {
    signing_key: SigningKey,
}

impl EcdsaSigner {
    fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl signature::Keypair for EcdsaSigner {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey::from(&self.signing_key)
    }
}

impl spki::DynSignatureAlgorithmIdentifier for EcdsaSigner {
    fn signature_algorithm_identifier(&self) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        use der::oid::db::rfc5912::ECDSA_WITH_SHA_256;
        Ok(spki::AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA_256,
            parameters: None,
        })
    }
}

impl signature::Signer<p256::ecdsa::DerSignature> for EcdsaSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<p256::ecdsa::DerSignature, signature::Error> {
        use p256::ecdsa::signature::Signer;
        self.signing_key.try_sign(msg)
    }
}
