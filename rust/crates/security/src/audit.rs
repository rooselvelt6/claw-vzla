//! Audit logging with hash chain for integrity verification,
//! Ed25519 block signing, SIEM export, and tamper detection.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 10000;
const BLOCK_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    ApiKeySet,
    ApiKeyCleared,
    ConfigEncrypt,
    ConfigDecrypt,
    SessionStart,
    SessionEnd,
    ToolExecute,
    FileRead,
    FileWrite,
    FileDelete,
    ToolCallStart,
    ToolCallEnd,
    PermissionGrant,
    PermissionDeny,
    ForensicCapture,
    ConfigChange,
    ProviderSwitch,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::ApiKeySet => write!(f, "API_KEY_SET"),
            AuditAction::ApiKeyCleared => write!(f, "API_KEY_CLEARED"),
            AuditAction::ConfigEncrypt => write!(f, "CONFIG_ENCRYPT"),
            AuditAction::ConfigDecrypt => write!(f, "CONFIG_DECRYPT"),
            AuditAction::SessionStart => write!(f, "SESSION_START"),
            AuditAction::SessionEnd => write!(f, "SESSION_END"),
            AuditAction::ToolExecute => write!(f, "TOOL_EXECUTE"),
            AuditAction::FileRead => write!(f, "FILE_READ"),
            AuditAction::FileWrite => write!(f, "FILE_WRITE"),
            AuditAction::FileDelete => write!(f, "FILE_DELETE"),
            AuditAction::ToolCallStart => write!(f, "TOOL_CALL_START"),
            AuditAction::ToolCallEnd => write!(f, "TOOL_CALL_END"),
            AuditAction::PermissionGrant => write!(f, "PERMISSION_GRANT"),
            AuditAction::PermissionDeny => write!(f, "PERMISSION_DENY"),
            AuditAction::ForensicCapture => write!(f, "FORENSIC_CAPTURE"),
            AuditAction::ConfigChange => write!(f, "CONFIG_CHANGE"),
            AuditAction::ProviderSwitch => write!(f, "PROVIDER_SWITCH"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: AuditAction,
    pub target: Option<String>,
    pub entry_hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(action: AuditAction, target: Option<String>, prev_hash: [u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry_hash = Self::compute_hash(timestamp, &action, target.as_deref(), prev_hash);

        Self {
            timestamp,
            action,
            target,
            entry_hash,
        }
    }

    fn compute_hash(
        timestamp: u64,
        action: &AuditAction,
        target: Option<&str>,
        prev: [u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(action.to_string().as_bytes());
        if let Some(t) = target {
            hasher.update(t.as_bytes());
        }
        hasher.finalize().into()
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.entry_hash)
    }

    pub fn to_ecs_json(&self) -> Value {
        serde_json::json!({
            "@timestamp": self.timestamp,
            "event": {
                "kind": "event",
                "category": ["database"],
                "type": ["change"],
                "action": self.action.to_string(),
                "outcome": "success"
            },
            "observer": {
                "type": "audit",
                "vendor": "opencode"
            },
            "audit": {
                "entry_hash": self.hash_hex(),
                "target": self.target
            }
        })
    }

    pub fn to_splunk_hec(&self) -> Value {
        serde_json::json!({
            "event": {
                "action": self.action.to_string(),
                "target": self.target,
                "entry_hash": self.hash_hex()
            },
            "sourcetype": "opencode:audit",
            "source": "opencode-audit",
            "host": "opencode",
            "time": self.timestamp
        })
    }

    pub fn to_opentelemetry(&self) -> Value {
        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": { "stringValue": "opencode" }
                    }]
                },
                "scopeSpans": [{
                    "scope": {
                        "name": "opencode.audit"
                    },
                    "spans": [{
                        "traceId": hex::encode(&self.entry_hash[..16]),
                        "spanId": hex::encode(&self.entry_hash[16..]),
                        "name": self.action.to_string(),
                        "kind": 3,
                        "startTimeUnixNano": self.timestamp * 1_000_000_000,
                        "attributes": [
                            { "key": "audit.target", "value": { "stringValue": self.target.clone().unwrap_or_default() } },
                            { "key": "audit.hash", "value": { "stringValue": self.hash_hex() } }
                        ]
                    }]
                }]
            }]
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlock {
    pub block_number: u64,
    pub start_index: usize,
    pub end_index: usize,
    pub entries: Vec<AuditEntry>,
    pub block_hash: [u8; 32],
    pub signature_hex: String,
    pub public_key_hex: String,
}

impl SignedBlock {
    pub fn sign(
        block_number: u64,
        entries: Vec<AuditEntry>,
        signing_key: &SigningKey,
    ) -> Self {
        let block_hash = Self::compute_block_hash(&entries);
        let signature = signing_key.sign(&block_hash);
        let verifying_key = signing_key.verifying_key();

        Self {
            block_number,
            start_index: block_number as usize * BLOCK_SIZE,
            end_index: block_number as usize * BLOCK_SIZE + entries.len(),
            entries,
            block_hash,
            signature_hex: hex::encode(signature.to_bytes()),
            public_key_hex: hex::encode(verifying_key.to_bytes()),
        }
    }

    pub fn verify(&self, public_key: &VerifyingKey) -> bool {
        let computed_hash = Self::compute_block_hash(&self.entries);
        if computed_hash != self.block_hash {
            return false;
        }
        let signature_bytes = match hex::decode(&self.signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&signature_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        public_key.verify(&self.block_hash, &signature).is_ok()
    }

    fn compute_block_hash(entries: &[AuditEntry]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.entry_hash);
        }
        hasher.finalize().into()
    }
}

pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    previous_hash: [u8; 32],
    last_signed_block: u64,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_ENTRIES),
            previous_hash: [0u8; 32],
            last_signed_block: 0,
        }
    }

    pub fn log(&mut self, action: AuditAction, target: Option<String>) {
        let entry = AuditEntry::new(action, target, self.previous_hash);
        self.previous_hash = entry.entry_hash;

        self.entries.push_back(entry);

        if self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
    }

    pub fn sign_block(&self, signing_key: &SigningKey) -> Option<SignedBlock> {
        let total = self.entries.len();
        let start = self.last_signed_block as usize * BLOCK_SIZE;
        if start >= total {
            return None;
        }
        let end = (start + BLOCK_SIZE).min(total);
        let block_entries: Vec<AuditEntry> =
            self.entries.iter().skip(start).take(end - start).cloned().collect();
        if block_entries.is_empty() {
            return None;
        }
        Some(SignedBlock::sign(self.last_signed_block, block_entries, signing_key))
    }

    pub fn sign_all_blocks(&self, signing_key: &SigningKey) -> Vec<SignedBlock> {
        let total = self.entries.len();
        let num_blocks = total.div_ceil(BLOCK_SIZE);
        let mut blocks = Vec::with_capacity(num_blocks);
        for block_idx in 0..num_blocks {
            let start = block_idx * BLOCK_SIZE;
            let end = (start + BLOCK_SIZE).min(total);
            let block_entries: Vec<AuditEntry> =
                self.entries.iter().skip(start).take(end - start).cloned().collect();
            blocks.push(SignedBlock::sign(block_idx as u64, block_entries, signing_key));
        }
        blocks
    }

    pub fn verify(&self) -> bool {
        let mut prev = [0u8; 32];

        for entry in self.entries.iter() {
            let computed = AuditEntry::compute_hash(
                entry.timestamp,
                &entry.action,
                entry.target.as_deref(),
                prev,
            );
            if entry.entry_hash != computed {
                return false;
            }
            prev = entry.entry_hash;
        }

        true
    }

    pub fn verify_chain_integrity(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let mut prev = [0u8; 32];

        for (i, entry) in self.entries.iter().enumerate() {
            let computed = AuditEntry::compute_hash(
                entry.timestamp,
                &entry.action,
                entry.target.as_deref(),
                prev,
            );
            if entry.entry_hash != computed {
                errors.push(format!("Entry {}: hash mismatch", i));
            }
            prev = entry.entry_hash;
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn verify_blocks(&self, blocks: &[SignedBlock], public_key: &VerifyingKey) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for block in blocks {
            if !block.verify(public_key) {
                errors.push(format!("Block {}: signature verification failed", block.block_number));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn previous_hash(&self) -> [u8; 32] {
        self.previous_hash
    }

    pub fn last_signed_block(&self) -> u64 {
        self.last_signed_block
    }

    pub fn export_ecs(&self) -> Vec<Value> {
        self.entries.iter().map(|e| e.to_ecs_json()).collect()
    }

    pub fn export_splunk_hec(&self) -> Vec<Value> {
        self.entries.iter().map(|e| e.to_splunk_hec()).collect()
    }

    pub fn export_opentelemetry(&self) -> Value {
        let spans: Vec<Value> = self.entries.iter().map(|e| e.to_opentelemetry()).collect();
        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": { "stringValue": "opencode" }
                    }]
                },
                "scopeSpans": [{
                    "scope": { "name": "opencode.audit" },
                    "spans": spans
                }]
            }]
        })
    }

    pub fn export_json(&self) -> Value {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "action": e.action.to_string(),
                    "target": e.target,
                    "hash": e.hash_hex()
                })
            })
            .collect();
        serde_json::json!({ "entries": entries, "count": self.len() })
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_audit_keypair() -> (SigningKey, VerifyingKey) {
    let mut secret_bytes = [0u8; 32];
    use rand::Rng;
    rand::rng().fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_basic() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("session-123".to_string()));
        log.log(AuditAction::ToolExecute, Some("read".to_string()));
        assert_eq!(log.len(), 2);
        assert!(log.verify());
    }

    #[test]
    fn test_audit_empty_verify() {
        let log = AuditLog::new();
        assert!(log.verify());
    }

    #[test]
    fn test_audit_tamper_detection() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        log.log(AuditAction::ToolExecute, Some("t1".to_string()));

        assert!(log.verify());

        if let Some(entry) = log.entries.iter_mut().last() {
            entry.entry_hash = [0u8; 32];
        }

        assert!(!log.verify());
    }

    #[test]
    fn test_chain_integrity_ok() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        log.log(AuditAction::ToolExecute, Some("read".to_string()));
        assert!(log.verify_chain_integrity().is_ok());
    }

    #[test]
    fn test_chain_integrity_fail() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        if let Some(entry) = log.entries.iter_mut().last() {
            entry.entry_hash = [1u8; 32];
        }
        assert!(log.verify_chain_integrity().is_err());
    }

    #[test]
    fn test_generate_keypair() {
        let (sk, vk) = generate_audit_keypair();
        assert_eq!(sk.verifying_key(), vk);
    }

    #[test]
    fn test_sign_and_verify_block() {
        let (sk, vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.log(AuditAction::ToolExecute, Some(format!("tool-{i}")));
        }

        let block = log.sign_block(&sk);
        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.block_number, 0);
        assert!(block.verify(&vk));
    }

    #[test]
    fn test_sign_block_malformed_fails_verify() {
        let (sk, vk) = generate_audit_keypair();
        let (_, wrong_vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));

        let block = log.sign_block(&sk).unwrap();
        assert!(block.verify(&vk));
        assert!(!block.verify(&wrong_vk));
    }

    #[test]
    fn test_sign_all_blocks() {
        let (sk, vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        for i in 0..250 {
            log.log(AuditAction::ToolExecute, Some(format!("tool-{i}")));
        }

        let blocks = log.sign_all_blocks(&sk);
        assert_eq!(blocks.len(), 3);
        for block in &blocks {
            assert!(block.verify(&vk));
        }
    }

    #[test]
    fn test_verify_blocks_valid() {
        let (sk, vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        for i in 0..50 {
            log.log(AuditAction::ToolExecute, Some(format!("tool-{i}")));
        }

        let blocks = log.sign_all_blocks(&sk);
        assert!(log.verify_blocks(&blocks, &vk).is_ok());
    }

    #[test]
    fn test_verify_blocks_invalid_key() {
        let (sk, _) = generate_audit_keypair();
        let (_, wrong_vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));

        let blocks = log.sign_all_blocks(&sk);
        assert!(log.verify_blocks(&blocks, &wrong_vk).is_err());
    }

    #[test]
    fn test_entry_hash_hex() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        let entry = log.entries().last().unwrap();
        let hex_hash = entry.hash_hex();
        assert_eq!(hex_hash.len(), 64);
    }

    #[test]
    fn test_export_ecs() {
        let mut log = AuditLog::new();
        log.log(AuditAction::ToolExecute, Some("read".to_string()));
        let ecs = log.export_ecs();
        assert_eq!(ecs.len(), 1);
        assert!(ecs[0].get("@timestamp").is_some());
        assert!(ecs[0].get("event").is_some());
    }

    #[test]
    fn test_export_splunk_hec() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        let hec = log.export_splunk_hec();
        assert_eq!(hec.len(), 1);
        assert_eq!(hec[0]["sourcetype"], "opencode:audit");
    }

    #[test]
    fn test_export_opentelemetry() {
        let mut log = AuditLog::new();
        log.log(AuditAction::ToolExecute, Some("read".to_string()));
        let otel = log.export_opentelemetry();
        assert!(otel.get("resourceSpans").is_some());
    }

    #[test]
    fn test_export_json() {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        let json = log.export_json();
        assert!(json.get("entries").is_some());
        assert_eq!(json["count"], 1);
    }

    #[test]
    fn test_sign_empty_log() {
        let (sk, _vk) = generate_audit_keypair();
        let log = AuditLog::new();
        assert!(log.sign_block(&sk).is_none());
    }

    #[test]
    fn test_audit_new_actions() {
        let mut log = AuditLog::new();
        log.log(AuditAction::ToolCallStart, Some("read".to_string()));
        log.log(AuditAction::ToolCallEnd, Some("read".to_string()));
        log.log(AuditAction::PermissionGrant, Some("allow".to_string()));
        log.log(AuditAction::PermissionDeny, Some("block".to_string()));
        log.log(AuditAction::ForensicCapture, Some("full".to_string()));
        log.log(AuditAction::ConfigChange, Some("setting".to_string()));
        log.log(AuditAction::ProviderSwitch, Some("anthropic".to_string()));
        assert_eq!(log.len(), 7);
        assert!(log.verify());
    }

    #[test]
    fn test_block_hash_mismatch() {
        let (sk, vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        let mut block = log.sign_block(&sk).unwrap();
        block.block_hash = [0u8; 32];
        assert!(!block.verify(&vk));
    }

    #[test]
    fn test_signature_tampered() {
        let (sk, vk) = generate_audit_keypair();
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("s1".to_string()));
        let mut block = log.sign_block(&sk).unwrap();
        block.signature_hex = hex::encode([0u8; 64]);
        assert!(!block.verify(&vk));
    }
}
