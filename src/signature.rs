use crate::{Error, InnerError};

/// A record (or data) signature produced by a keypair
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// A digital signature in the ed25519 cryptosystem
    Ed25519([u8; 64]),

    /// A digital signature in the secp256k1 cryptosystem
    Secp256k1([u8; 64]),
}

impl Signature {
    /// Create from an ed25519 dalek signature
    #[must_use]
    pub fn from_ed25519_dalek(sig: ed25519_dalek::Signature) -> Self {
        Self::Ed25519(sig.to_bytes())
    }

    /// Try to convert into an ed25519 dalek signature
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn try_as_ed25519_dalek(&self) -> Option<ed25519_dalek::Signature> {
        match self {
            Self::Ed25519(bytes) => Some(ed25519_dalek::Signature::from_bytes(bytes)),
            _ => None,
        }
    }

    /// Create from ed25519 signature bytes
    #[must_use]
    pub fn from_ed25519_bytes(sig: [u8; 64]) -> Self {
        Self::Ed25519(sig)
    }

    /// Try to convert to the inner ed25519 signature
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn try_as_ed25519_bytes(&self) -> Option<&[u8; 64]> {
        match self {
            Self::Ed25519(sig) => Some(sig),
            _ => None,
        }
    }

    /// Create from an secp256k1 schnorr signature
    #[must_use]
    pub fn from_secp256k1_sig(sig: secp256k1::schnorr::Signature) -> Self {
        Self::Secp256k1(sig.to_byte_array())
    }

    /// Try to convert into a secp256k1 schnorr signature
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn try_as_secp256k1_sig(&self) -> Option<secp256k1::schnorr::Signature> {
        match self {
            Self::Secp256k1(bytes) => Some(secp256k1::schnorr::Signature::from_byte_array(*bytes)),
            _ => None,
        }
    }

    /// Create from a secp256k1 signature bytes
    #[must_use]
    pub fn from_secp256k1_bytes(sig: [u8; 64]) -> Self {
        Self::Secp256k1(sig)
    }

    /// Try to tonvert to the inner secp256k1 signature
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn try_as_secp256k1_bytes(&self) -> Option<&[u8; 64]> {
        match self {
            Self::Secp256k1(sig) => Some(sig),
            _ => None,
        }
    }
}

/// A public signing key representing a server or user,
/// whether a master key or subkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// To a `ed25519_dalek::VerifyingKey`
    ///
    /// This unpacks the 32 byte data for cryptographic usage
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn to_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).unwrap()
    }

    /// From a `ed25519_dalek::VerifyingKey`
    ///
    /// This packs into 32 byte data
    #[must_use]
    pub fn from_verifying_key(verifying_key: &ed25519_dalek::VerifyingKey) -> PublicKey {
        PublicKey(verifying_key.as_bytes().to_owned())
    }

    /// View inside this `PublicKey` which stores a `&[u8; 32]`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Take bytes as `[u8; 32]`
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Convert a `&[u8; 32]` into a `PublicKey`
    ///
    /// # Errors
    ///
    /// Will return `Err` if the bytes do not represent a `CompressedEdwardsY`
    /// point on the curve (not all bit sequences do)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, Error> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)?;
        Ok(Self::from_verifying_key(&vk))
    }

    /// Convert a `&[u8; 32]` into a `PublicKey`
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `PublicKey`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8; 32]) -> PublicKey {
        PublicKey(bytes.to_owned())
    }

    /// Convert a `PublicKey` into the human printable `mopub0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
        format!("mopub0{}", z32::encode(&self.0))
    }

    /// Import a `PublicKey` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not a `PublicKey`
    pub fn from_printable(s: &str) -> Result<PublicKey, Error> {
        if !s.starts_with("mopub0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[6..])?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| InnerError::KeyLength.into_err())?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_printable())
    }
}

/// A secret signing key
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// To a `ed25519_dalek::SigningKey`
    ///
    /// This unpacks the 32 byte data for cryptographic usage
    #[must_use]
    pub fn to_signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }

    /// From a `ed25519_dalek::SigningKey`
    ///
    /// This packs into 32 byte data
    #[must_use]
    pub fn from_signing_key(signing_key: &ed25519_dalek::SigningKey) -> SecretKey {
        SecretKey(signing_key.to_bytes())
    }

    /// View inside this `SecretKey` which storeas a `&[u8; 32]`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Take bytes as `[u8; 32]`
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Convert a `&[u8; 32]` into a `SecretKey`
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> SecretKey {
        Self(bytes.to_owned())
    }

    /// Generate a `SecretKey`
    ///
    /// For example:
    /// ```
    /// # use mosaic_core::SecretKey;
    /// let mut csprng = rand::rngs::OsRng;
    /// let secret_key = SecretKey::generate(&mut csprng);
    /// ```
    pub fn generate<R: rand_core::CryptoRngCore + ?Sized>(csprng: &mut R) -> SecretKey {
        SecretKey(ed25519_dalek::SigningKey::generate(csprng).to_bytes())
    }

    /// Compute the `PublicKey` that matchies this `SecretKey`
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey::from_verifying_key(&self.to_signing_key().verifying_key())
    }

    /// Convert a `SecretKey` into the human printable `mosec0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
        format!("mosec0{}", z32::encode(&self.0))
    }

    /// Import a `SecretKey` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not a `SecretKey`
    pub fn from_printable(s: &str) -> Result<SecretKey, Error> {
        if !s.starts_with("mosec0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[6..])?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| InnerError::KeyLength.into_err())?;
        Ok(Self::from_bytes(&bytes))
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_printable())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        constant_time_eq::constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for SecretKey {}

/// An encrypted secret signing key
/// whether a master key or subkey.
//
//  Layout:
//    0      - Version byte
//    1      - Log N byte
//    2..18  - Salt
//    18..50 - Secret Key (encrypted)
//    50..54 - Rand4
//    54..58 - Randomized Checkbytes = Rand4 ^ Check Bytes
//
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedSecretKey(Vec<u8>);

impl EncryptedSecretKey {
    const CHECK_BYTES: &[u8] = &[0xb9, 0x60, 0xa1, 0xe2];

    const MAX_LOG_N: u8 = 22;

    /// Encrypt a `SecretKey` into an `EncryptedSecretKey`
    #[allow(clippy::missing_panics_doc)]
    pub fn from_secret_key<R: rand_core::CryptoRngCore + ?Sized>(
        secret_key: &SecretKey,
        password: &str,
        log_n: u8,
        csprng: &mut R,
    ) -> EncryptedSecretKey {
        let mut output = vec![0; 58];
        output[0] = 0x01;
        output[1] = log_n;

        // Fill salt
        let salt = {
            csprng.as_rngcore().fill_bytes(&mut output[2..18]);
            &output[2..18]
        };

        let mut symmetric_key: [u8; 40] = Self::symmetric_key(log_n, password, salt);

        let mut rand4 = vec![0; 4];
        csprng.as_rngcore().fill_bytes(&mut rand4);

        let mut randomized_checkbytes = rand4.clone();
        Self::xor_into_first(&mut randomized_checkbytes, Self::CHECK_BYTES.iter());

        let concatenation = secret_key
            .as_bytes()
            .iter()
            .chain(rand4.iter())
            .chain(randomized_checkbytes.iter());

        // Overwrite the symmetric key with the XOR of the concatenation
        Self::xor_into_first(&mut symmetric_key, concatenation);
        let xor_output = symmetric_key;

        // Copy into the output
        output[18..58].copy_from_slice(&xor_output);

        EncryptedSecretKey(output)
    }

    /// Decrypt an `EncryptedSecretKey` into a `SecretKey`
    ///
    /// # Errors
    ///
    /// Returns an error if the password is wrong, or if the version is unsupported,
    /// or if the scrypt `LOG_N` parameter is computationally excessive.
    #[allow(clippy::missing_panics_doc)]
    pub fn to_secret_key(&self, password: &str) -> Result<SecretKey, Error> {
        let version = self.0[0];
        if version != 0x01 {
            return Err(InnerError::UnsupportedEncryptedSecretKeyVersion(version).into());
        }

        let log_n = self.0[1];
        if log_n > Self::MAX_LOG_N {
            return Err(InnerError::ExcessiveScryptLogNParameter(log_n).into());
        }

        let salt = &self.0[2..18];

        let mut symmetric_key: [u8; 40] = Self::symmetric_key(log_n, password, salt);

        // Overwrite the symmetric key with the XOR
        Self::xor_into_first(&mut symmetric_key, self.0[18..58].iter());
        let mut concatenation = symmetric_key;

        // Break up the concatenation
        let (secret_key, checkarea) = concatenation.split_at_mut(32);
        let (rand4, checkbytes) = checkarea.split_at_mut(4);

        // XOR the randomized checkbytes with the rand4 to get the checkbytes
        Self::xor_into_first(checkbytes, &*rand4);

        // Verify the checkbytes
        if checkbytes != Self::CHECK_BYTES {
            return Err(InnerError::BadPassword.into());
        }

        Ok(SecretKey::from_bytes(secret_key[..32].try_into().unwrap()))
    }

    fn symmetric_key(log_n: u8, password: &str, salt: &[u8]) -> [u8; 40] {
        let params = scrypt::Params::new(log_n, 8, 1, 40).unwrap();
        let mut key = [0; 40];
        scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).unwrap();
        key
    }

    fn xor_into_first<'a, I: IntoIterator<Item = &'a u8>>(first: &mut [u8], second: I) {
        first.iter_mut().zip(second).for_each(|(x1, x2)| *x1 ^= *x2);
    }

    /// Convert an `EncryptedSecretKey` into the human printable `mocryptsec0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
        format!("mocryptsec0{}", z32::encode(&self.0))
    }

    /// Import an `EncryptedSecretKey` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not an `EncryptedSecretKey`, or is the wrong
    /// length of data, or is not version 1
    pub fn from_printable(s: &str) -> Result<EncryptedSecretKey, Error> {
        if !s.starts_with("mocryptsec0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[11..])?;
        if bytes.len() != 50 {
            return Err(InnerError::BadEncryptedSecretKey.into());
        }
        if bytes[0] != 0x01 {
            return Err(InnerError::UnsupportedEncryptedSecretKeyVersion(bytes[0]).into());
        }
        if bytes[1] > Self::MAX_LOG_N {
            return Err(InnerError::ExcessiveScryptLogNParameter(bytes[1]).into());
        }
        Ok(EncryptedSecretKey(bytes))
    }
}

impl std::fmt::Display for EncryptedSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_printable())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_generate() {
        use crate::SecretKey;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;

        let secret_key = SecretKey::generate(&mut csprng);
        let public_key = secret_key.public();

        println!("public: {public_key}");
        println!("secret: {secret_key}");
    }

    #[test]
    fn test_encrypted_secret_key() {
        use crate::{EncryptedSecretKey, SecretKey};
        use rand::rngs::OsRng;

        let mut csprng = OsRng;

        let secret_key = SecretKey::generate(&mut csprng);
        let encrypted_secret_key =
            EncryptedSecretKey::from_secret_key(&secret_key, "testing123", 18, &mut csprng);

        println!("{encrypted_secret_key}");

        let secret_key2 = encrypted_secret_key.to_secret_key("testing123").unwrap();
        assert_eq!(secret_key, secret_key2);

        assert!(encrypted_secret_key.to_secret_key("wrongpassword").is_err());
    }
}
