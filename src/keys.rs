use crate::{DalekSigningKey, DalekVerifyingKey};
use crate::{Error, InnerError};

/// A public signing key representing a server or user,
/// whether a master key or subkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// To a `DalekVerifyingKey`
    ///
    /// This unpacks the 32 byte data for cryptographic usage
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn to_verifying_key(&self) -> DalekVerifyingKey {
        DalekVerifyingKey::from_bytes(&self.0).unwrap()
    }

    /// From a `DalekVerifyingKey`
    ///
    /// This packs into 32 byte data
    #[must_use]
    pub fn from_verifying_key(verifying_key: &DalekVerifyingKey) -> PublicKey {
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
        let vk = DalekVerifyingKey::from_bytes(bytes)?;
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
    pub fn printable(&self) -> String {
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
        write!(f, "{}", self.printable())
    }
}

/// A secret signing key
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// To a `DalekSigningKey`
    ///
    /// This unpacks the 32 byte data for cryptographic usage
    #[must_use]
    pub fn to_signing_key(&self) -> DalekSigningKey {
        DalekSigningKey::from_bytes(&self.0)
    }

    /// From a `DalekSigningKey`
    ///
    /// This packs into 32 byte data
    #[must_use]
    pub fn from_signing_key(signing_key: &DalekSigningKey) -> SecretKey {
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
        SecretKey(DalekSigningKey::generate(csprng).to_bytes())
    }

    /// Compute the `PublicKey` that matchies this `SecretKey`
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey::from_verifying_key(&self.to_signing_key().verifying_key())
    }

    /// Convert a `SecretKey` into the human printable `mosec0` form.
    #[must_use]
    pub fn printable(&self) -> String {
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
        write!(f, "{}", self.printable())
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedSecretKey(Vec<u8>);

impl EncryptedSecretKey {
    /// Encrypt a `SecretKey` into an `EncryptedSecretKey`
    #[allow(clippy::missing_panics_doc)]
    pub fn from_secret_key<R: rand_core::CryptoRngCore + ?Sized>(
        secret_key: &SecretKey,
        password: &str,
        log_n: u8,
        csprng: &mut R,
    ) -> Result<EncryptedSecretKey, Error> {
        let mut output = vec![0; 50];
        output[0] = 0x01;
        output[1] = log_n;

        // Fill salt
        let salt = {
            csprng.as_rngcore().fill_bytes(&mut output[2..18]);
            &output[2..18]
        };

        // Deterministically generate the symmetric key
        let mut symmetric_key: [u8; 32] = {
            let params = scrypt::Params::new(log_n, 8, 1, 32)?;
            let mut key = [0; 32];
            scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).unwrap();
            key
        };

        // Overwrite the symmetric key with the XOR
        symmetric_key
            .iter_mut()
            .zip(secret_key.as_bytes().iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        let xor_output = symmetric_key;

        // Copy into the output
        output[18..50].copy_from_slice(&xor_output);

        Ok(EncryptedSecretKey(output))
    }

    /// Decrypt an `EncryptedSecretKey` into a `SecretKey`
    pub fn to_secret_key(&self, password: &str) -> Result<SecretKey, Error> {
        if self.0.len() != 50 {
            return Err(InnerError::BadEncryptedSecretKey.into());
        }
        if self.0[0] != 0x01 {
            return Err(InnerError::UnsupportedEncryptedSecretKeyVersion(self.0[0]).into());
        }
        let log_n = self.0[1];
        let salt = &self.0[2..18];

        // Deterministically generate the symmetric key
        let mut symmetric_key: [u8; 32] = {
            let params = scrypt::Params::new(log_n, 8, 1, 32)?;
            let mut key = [0; 32];
            scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).unwrap();
            key
        };

        // Overwrite the symmetric key with the XOR
        symmetric_key
            .iter_mut()
            .zip(self.0[18..50].iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        let bytes = symmetric_key;

        Ok(SecretKey::from_bytes(&bytes))
    }

    /// Convert an `EncryptedSecretKey` into the human printable `mocryptsec0` form.
    #[must_use]
    pub fn printable(&self) -> String {
        format!("mocryptsec0{}", z32::encode(&self.0))
    }

    /// Import an `EncryptedSecretKey` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not an `EncryptedSecretKey`
    pub fn from_printable(s: &str) -> Result<EncryptedSecretKey, Error> {
        if !s.starts_with("mocryptsec0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[11..])?;
        Ok(EncryptedSecretKey(bytes))
    }
}

impl std::fmt::Display for EncryptedSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
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
            EncryptedSecretKey::from_secret_key(&secret_key, "testing123", 18, &mut csprng)
                .unwrap();

        println!("{}", encrypted_secret_key);

        let secret_key2 = encrypted_secret_key.to_secret_key("testing123").unwrap();
        assert_eq!(secret_key, secret_key2);

        let wrong_secret_key = encrypted_secret_key.to_secret_key("wrongpassword").unwrap();
        assert_ne!(secret_key, wrong_secret_key);
    }
}
