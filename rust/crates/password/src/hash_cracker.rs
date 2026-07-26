use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::hash_id::identify_hash_best;

#[derive(Debug, Clone, Default)]
pub struct CrackResult {
    pub hash: String,
    pub password: Option<String>,
    pub hash_type: String,
}

pub trait HashVerifier {
    fn verify(&self, password: &str, hash: &str) -> bool;
    fn name(&self) -> &'static str;
}

pub struct Md5Verifier;
impl HashVerifier for Md5Verifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        use md5::Digest;
        let digest = md5::Md5::digest(password.as_bytes());
        format!("{:x}", digest) == hash.to_lowercase()
    }
    fn name(&self) -> &'static str { "MD5" }
}

pub struct Sha1Verifier;
impl HashVerifier for Sha1Verifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        use sha1::Digest;
        let result = sha1::Sha1::digest(password.as_bytes());
        format!("{:x}", result) == hash.to_lowercase()
    }
    fn name(&self) -> &'static str { "SHA1" }
}

pub struct Sha256Verifier;
impl HashVerifier for Sha256Verifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        use sha2::Digest;
        let result = sha2::Sha256::digest(password.as_bytes());
        format!("{:x}", result) == hash.to_lowercase()
    }
    fn name(&self) -> &'static str { "SHA2-256" }
}

pub struct Sha512Verifier;
impl HashVerifier for Sha512Verifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        use sha2::Digest;
        let result = sha2::Sha512::digest(password.as_bytes());
        format!("{:x}", result) == hash.to_lowercase()
    }
    fn name(&self) -> &'static str { "SHA2-512" }
}

pub struct BcryptVerifier;
impl HashVerifier for BcryptVerifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        bcrypt::verify(password, hash).unwrap_or(false)
    }
    fn name(&self) -> &'static str { "bcrypt" }
}

pub struct Argon2Verifier;
impl HashVerifier for Argon2Verifier {
    fn verify(&self, password: &str, hash: &str) -> bool {
        use argon2::PasswordHash;
        use password_hash::PasswordVerifier;
        let parsed = match PasswordHash::new(hash) {
            Ok(p) => p,
            Err(_) => return false,
        };
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    }
    fn name(&self) -> &'static str { "Argon2" }
}

use argon2::Argon2;

fn get_verifier(hash_type: &str) -> Option<Box<dyn HashVerifier>> {
    match hash_type {
        "MD5" | "md5" => Some(Box::new(Md5Verifier)),
        "SHA1" | "sha1" => Some(Box::new(Sha1Verifier)),
        "SHA2-256" | "SHA256" | "sha256" => Some(Box::new(Sha256Verifier)),
        "SHA2-512" | "SHA512" | "sha512" => Some(Box::new(Sha512Verifier)),
        "bcrypt" | "Bcrypt" => Some(Box::new(BcryptVerifier)),
        "Argon2" | "argon2" | "Argon2id" | "Argon2i" | "Argon2d" => Some(Box::new(Argon2Verifier)),
        _ => {
            let cat = match hash_type {
                t if t.contains("MD5") || t.contains("md5") => Some("MD5"),
                t if t.contains("SHA1") || t.contains("sha1") => Some("SHA1"),
                t if t.contains("SHA2-256") || t.contains("SHA256") => Some("SHA2-256"),
                t if t.contains("SHA2-512") || t.contains("SHA512") => Some("SHA2-512"),
                t if t.contains("bcrypt") || t.contains("Bcrypt") => Some("bcrypt"),
                t if t.contains("Argon2") || t.contains("argon2") => Some("Argon2"),
                _ => None,
            };
            cat.and_then(get_verifier)
        }
    }
}

pub fn crack_hash(hash: &str, wordlist: &[String]) -> CrackResult {
    let hash_info = identify_hash_best(hash);
    let hash_type = hash_info.map(|h| h.name).unwrap_or("unknown");
    let verifier = get_verifier(hash_type);

    match verifier {
        Some(v) => {
            for password in wordlist {
                if v.verify(password, hash) {
                    return CrackResult {
                        hash: hash.to_string(),
                        password: Some(password.clone()),
                        hash_type: v.name().to_string(),
                    };
                }
            }
            CrackResult {
                hash: hash.to_string(),
                password: None,
                hash_type: hash_type.to_string(),
            }
        }
        None => CrackResult {
            hash: hash.to_string(),
            password: None,
            hash_type: hash_type.to_string(),
        },
    }
}

pub fn crack_hash_auto(hash: &str, wordlist: &[String]) -> CrackResult {
    crack_hash(hash, wordlist)
}

pub fn crack_hashes(hashes: &[String], wordlist: &[String]) -> Vec<CrackResult> {
    hashes.iter().map(|h| crack_hash(h, wordlist)).collect()
}

pub fn crack_hashes_parallel(hashes: &[String], wordlist: &[String]) -> Vec<CrackResult> {
    crack_hashes(hashes, wordlist)
}

pub fn load_wordlist(path: &str) -> Result<Vec<String>, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open wordlist: {}", e))?;
    let reader = BufReader::new(file);
    let mut words = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Read error: {}", e))?;
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            words.push(trimmed);
        }
    }
    Ok(words)
}

pub fn generate_rule_based(base_words: Vec<String>, rules: &[&str]) -> Vec<String> {
    let mut results = Vec::new();
    for word in &base_words {
        for rule in rules {
            match *rule {
                "lower" => results.push(word.to_lowercase()),
                "upper" => results.push(word.to_uppercase()),
                "capitalize" => {
                    let mut c = word.chars();
                    let capitalized = c.next().map(|f| f.to_uppercase().to_string() + c.as_str()).unwrap_or_default();
                    results.push(capitalized);
                }
                "leet" => {
                    let leet = word.replace('e', "3").replace('a', "@").replace('o', "0")
                        .replace('i', "1").replace('s', "$").replace('t', "7");
                    results.push(leet);
                }
                "reverse" => results.push(word.chars().rev().collect()),
                "append1" => results.push(format!("{}1", word)),
                "append123" => results.push(format!("{}123", word)),
                "append2020" => results.push(format!("{}2020", word)),
                "append2021" => results.push(format!("{}2021", word)),
                "append2022" => results.push(format!("{}2022", word)),
                "append2023" => results.push(format!("{}2023", word)),
                "append2024" => results.push(format!("{}2024", word)),
                "append2025" => results.push(format!("{}2025", word)),
                "append2026" => results.push(format!("{}2026", word)),
                "append!" => results.push(format!("{}!", word)),
                "append@" => results.push(format!("{}@", word)),
                "append#" => results.push(format!("{}#", word)),
                "prepend1" => results.push(format!("1{}", word)),
                "prepend!" => results.push(format!("!{}", word)),
                "double" => results.push(format!("{}{}", word, word)),
                _ => {}
            }
        }
    }
    results
}

pub struct HashType;
impl HashType {
    pub fn for_hash(hash: &str) -> Option<&'static str> {
        identify_hash_best(hash).map(|h| h.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_verifier() {
        let v = Md5Verifier;
        assert!(v.verify("hello", "5d41402abc4b2a76b9719d911017c592"));
        assert!(!v.verify("wrong", "5d41402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn test_sha1_verifier() {
        let v = Sha1Verifier;
        assert!(v.verify("hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"));
    }

    #[test]
    fn test_sha256_verifier() {
        let v = Sha256Verifier;
        assert!(v.verify("hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
    }

    #[test]
    fn test_sha512_verifier() {
        let v = Sha512Verifier;
        assert!(v.verify("hello", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"));
    }

    #[test]
    fn test_bcrypt_verifier() {
        let v = BcryptVerifier;
        let hash = bcrypt::hash("password", 4).unwrap();
        assert!(v.verify("password", &hash));
        assert!(!v.verify("wrong", &hash));
    }

    #[test]
    fn test_argon2_verifier() {
        use argon2::PasswordHasher;
        use password_hash::SaltString;
        let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
        let hash = Argon2::default()
            .hash_password(b"password", &salt)
            .unwrap()
            .to_string();
        let v = Argon2Verifier;
        assert!(v.verify("password", &hash));
        assert!(!v.verify("wrong", &hash));
    }

    #[test]
    fn test_crack_hash_found() {
        let wordlist = vec!["hello".to_string(), "world".to_string()];
        let result = crack_hash("5d41402abc4b2a76b9719d911017c592", &wordlist);
        assert_eq!(result.password, Some("hello".to_string()));
        assert_eq!(result.hash_type, "MD5");
    }

    #[test]
    fn test_crack_hash_not_found() {
        let wordlist = vec!["notfound".to_string()];
        let result = crack_hash("5d41402abc4b2a76b9719d911017c592", &wordlist);
        assert!(result.password.is_none());
    }

    #[test]
    fn test_rule_based_generation() {
        let base = vec!["hello".to_string()];
        let rules = vec!["upper", "capitalize", "append1"];
        let results = generate_rule_based(base, &rules);
        assert!(results.contains(&"HELLO".to_string()));
        assert!(results.contains(&"Hello".to_string()));
        assert!(results.contains(&"hello1".to_string()));
    }

    #[test]
    fn test_crack_hashes_multiple() {
        let hashes = vec![
            "5d41402abc4b2a76b9719d911017c592".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];
        let wordlist = vec!["hello".to_string(), "test".to_string()];
        let results = crack_hashes(&hashes, &wordlist);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].password, Some("hello".to_string()));
        assert!(results[1].password.is_none());
    }
}
