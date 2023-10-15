use std::collections::HashMap;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum PasswordError {
    #[error("user list is empty")]
    EmptyUserList,
    #[error("invalid password hash: {0}")]
    InvalidPasswordHash(argon2::password_hash::Error),
    #[error("could not compute password hash: {0}")]
    HashingFailed(argon2::password_hash::Error),
}

pub fn verify_password(
    users: HashMap<String, String>,
    username: &str,
    password: &str,
) -> Result<bool, PasswordError> {
    if users.is_empty() {
        return Err(PasswordError::EmptyUserList);
    }

    let entry = users.get_key_value(username).unwrap_or(users.iter().next().unwrap());
    let hash = PasswordHash::new(entry.1).map_err(PasswordError::InvalidPasswordHash)?;
    match Argon2::default().verify_password(password.as_bytes(), &hash) {
        Ok(()) => Ok(entry.0 == username),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(err) => Err(PasswordError::InvalidPasswordHash(err)),
    }
}

pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(PasswordError::HashingFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_ok() {
        let actual = hash_password("p@ssw0rd");
        assert!(actual.is_ok());
    }

    #[test]
    fn test_verify_password_ok() {
        let users: HashMap<String, String> =
            [("user".into(), hash_password("p@ssw0rd").unwrap())].into();
        let expected = Ok(true);
        let actual = verify_password(users, "user", "p@ssw0rd");
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_verify_password_wrong_password() {
        let users: HashMap<String, String> =
            [("user".into(), hash_password("p@ssw0rd").unwrap())].into();
        let expected = Ok(false);
        let actual = verify_password(users, "user", "wrong-p@ssw0rd");
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_verify_password_wrong_username() {
        let users: HashMap<String, String> =
            [("user".into(), hash_password("p@ssw0rd").unwrap())].into();
        let expected = Ok(false);
        let actual = verify_password(users, "wrong-user", "p@ssw0rd");
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_verify_password_invalid_hash() {
        let users = [("user".into(), "invalid".into())].into();
        let actual = verify_password(users, "user", "p@ssw0rd");
        assert!(matches!(actual, Err(PasswordError::InvalidPasswordHash(_))));
    }
}
