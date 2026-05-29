use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Clone, Debug)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn for_tests() -> Self {
        Self { m_cost: 8, t_cost: 1, p_cost: 1 }
    }

    pub fn recommended() -> Self {
        Self { m_cost: 65536, t_cost: 3, p_cost: 1 }
    }
}

pub fn derive_key(
    password: &str,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<[u8; 32], argon2::Error> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| argon2::Error::MemoryTooLittle)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_returns_32_bytes() {
        let salt = [0u8; 32];
        let key = derive_key("hunter2", &salt, &KdfParams::for_tests()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [1u8; 32];
        let key1 = derive_key("password", &salt, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("password", &salt, &KdfParams::for_tests()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_differs_for_different_passwords() {
        let salt = [2u8; 32];
        let key1 = derive_key("password1", &salt, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("password2", &salt, &KdfParams::for_tests()).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_differs_for_different_salts() {
        let salt1 = [3u8; 32];
        let salt2 = [4u8; 32];
        let key1 = derive_key("same_password", &salt1, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("same_password", &salt2, &KdfParams::for_tests()).unwrap();
        assert_ne!(key1, key2);
    }
}
