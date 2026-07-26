use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub caller_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    pub call_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub execution_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub caller_id: String,
    pub permissions: Vec<String>,
    pub expires_at: String,
    pub rate_limit_per_min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitState {
    pub calls_this_minute: u32,
    pub window_start: String,
    pub blocked_until: Option<String>,
}

pub struct McpToolServer {
    tools: Arc<RwLock<HashMap<String, McpTool>>>,
    tokens: Arc<RwLock<HashMap<String, AuthToken>>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitState>>>,
    call_log: Arc<RwLock<Vec<McpToolCall>>>,
    max_calls_per_minute: u32,
}

impl Default for McpToolServer {
    fn default() -> Self {
        Self::new()
    }
}

impl McpToolServer {
    pub fn new() -> Self {
        let mut tools_map = HashMap::new();

        let default_tools = vec![
            McpTool {
                name: "kraken_scan".to_string(),
                description: "Scan a target for vulnerabilities".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP or CIDR"},
                        "scan_type": {"type": "string", "enum": ["quick", "full", "stealth"], "default": "quick"},
                        "ports": {"type": "string", "description": "Port range (e.g. 1-1000)"}
                    },
                    "required": ["target"]
                }),
                category: "scanning".to_string(),
            },
            McpTool {
                name: "kraken_analyze".to_string(),
                description: "Analyze a file or binary for security issues".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                        "analysis_type": {"type": "string", "enum": ["binary", "firmware", "memory"], "default": "binary"}
                    },
                    "required": ["path"]
                }),
                category: "analysis".to_string(),
            },
            McpTool {
                name: "kraken_exploit".to_string(),
                description: "Generate exploit code for a vulnerability".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE identifier"},
                        "target_os": {"type": "string", "description": "Target operating system"},
                        "payload_type": {"type": "string", "enum": ["shellcode", "reverse_shell", "meterpreter"], "default": "shellcode"}
                    },
                    "required": ["cve_id"]
                }),
                category: "exploitation".to_string(),
            },
            McpTool {
                name: "kraken_report".to_string(),
                description: "Generate a security report".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Report title"},
                        "target": {"type": "string", "description": "Target of the assessment"},
                        "format": {"type": "string", "enum": ["json", "html", "markdown"], "default": "json"}
                    },
                    "required": ["title"]
                }),
                category: "reporting".to_string(),
            },
            McpTool {
                name: "kraken_recon".to_string(),
                description: "Perform reconnaissance on a target".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target domain or IP"},
                        "recon_type": {"type": "string", "enum": ["dns", "whois", "subdomains", "full"], "default": "full"}
                    },
                    "required": ["target"]
                }),
                category: "reconnaissance".to_string(),
            },
        ];

        for tool in default_tools {
            tools_map.insert(tool.name.clone(), tool);
        }

        McpToolServer {
            tools: Arc::new(RwLock::new(tools_map)),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            call_log: Arc::new(RwLock::new(Vec::new())),
            max_calls_per_minute: 60,
        }
    }

    pub async fn register_tool(&self, tool: McpTool) {
        let mut tools = self.tools.write().await;
        tools.insert(tool.name.clone(), tool);
    }

    pub async fn list_tools(&self) -> Vec<McpTool> {
        let tools = self.tools.read().await;
        tools.values().cloned().collect()
    }

    pub async fn get_tool(&self, name: &str) -> Option<McpTool> {
        let tools = self.tools.read().await;
        tools.get(name).cloned()
    }

    pub async fn create_token(
        &self,
        caller_id: &str,
        permissions: Vec<String>,
        rate_limit: Option<u32>,
    ) -> AuthToken {
        let token = format!(
            "kraken_{}",
            hex::encode(rand::rng().random::<[u8; 16]>())
        );
        let auth_token = AuthToken {
            token: token.clone(),
            caller_id: caller_id.to_string(),
            permissions,
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
            rate_limit_per_min: rate_limit.unwrap_or(self.max_calls_per_minute),
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(token.clone(), auth_token.clone());
        auth_token
    }

    pub async fn validate_token(&self, token: &str) -> Option<AuthToken> {
        let tokens = self.tokens.read().await;
        if let Some(auth_token) = tokens.get(token) {
            if chrono::DateTime::parse_from_rfc3339(&auth_token.expires_at).is_ok() {
                return Some(auth_token.clone());
            }
        }
        None
    }

    pub async fn check_rate_limit(&self, token: &str) -> Result<(), String> {
        let tokens = self.tokens.read().await;
        let auth_token = tokens
            .get(token)
            .ok_or_else(|| "Invalid token".to_string())?;
        let rate_limit = auth_token.rate_limit_per_min;
        let caller_id = auth_token.clone().caller_id;
        drop(tokens);

        let mut rate_limits = self.rate_limits.write().await;
        let now = chrono::Utc::now().to_rfc3339();

        let state = rate_limits
            .entry(caller_id.clone())
            .or_insert_with(|| RateLimitState {
                calls_this_minute: 0,
                window_start: now.clone(),
                blocked_until: None,
            });

        if let Some(ref blocked) = state.blocked_until {
            if blocked > &now {
                return Err(format!("Rate limited. Try again after {}", blocked));
            }
            state.blocked_until = None;
            state.calls_this_minute = 0;
        }

        if state.calls_this_minute >= rate_limit {
            state.blocked_until = Some(
                (chrono::Utc::now() + chrono::Duration::minutes(1))
                    .to_rfc3339(),
            );
            return Err("Rate limit exceeded".to_string());
        }

        state.calls_this_minute += 1;
        Ok(())
    }

    pub async fn call_tool(&self, call: McpToolCall) -> McpToolResult {
        let start = std::time::Instant::now();

        let tool = match self.get_tool(&call.tool_name).await {
            Some(t) => t,
            None => {
                return McpToolResult {
                    call_id: call.id,
                    success: false,
                    output: serde_json::json!({"error": "Tool not found"}),
                    error: Some(format!("Tool '{}' not found", call.tool_name)),
                    execution_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        let output = match tool.category.as_str() {
            "scanning" => {
                let target = call.arguments.get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let scan_type = call.arguments.get("scan_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("quick");
                serde_json::json!({
                    "status": "queued",
                    "target": target,
                    "scan_type": scan_type,
                    "message": "Scan initiated via MCP tool"
                })
            }
            "analysis" => {
                let path = call.arguments.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                serde_json::json!({
                    "status": "analyzing",
                    "path": path,
                    "message": "Analysis initiated via MCP tool"
                })
            }
            "exploitation" => {
                let cve = call.arguments.get("cve_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                serde_json::json!({
                    "status": "generating",
                    "cve_id": cve,
                    "message": "Exploit generation initiated via MCP tool"
                })
            }
            "reporting" => {
                let title = call.arguments.get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled Report");
                serde_json::json!({
                    "status": "generating",
                    "title": title,
                    "message": "Report generation initiated via MCP tool"
                })
            }
            "reconnaissance" => {
                let target = call.arguments.get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                serde_json::json!({
                    "status": "recon_initiated",
                    "target": target,
                    "message": "Reconnaissance initiated via MCP tool"
                })
            }
            _ => serde_json::json!({
                "status": "unknown_category",
                "tool": tool.name,
                "message": "Tool category handler not implemented"
            }),
        };

        let mut call_log = self.call_log.write().await;
        call_log.push(call.clone());

        McpToolResult {
            call_id: call.id,
            success: true,
            output,
            error: None,
            execution_ms: start.elapsed().as_millis() as u64,
        }
    }

    pub async fn revoke_token(&self, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token).is_some()
    }

    pub async fn get_call_log(&self, limit: Option<usize>) -> Vec<McpToolCall> {
        let log = self.call_log.read().await;
        let limit = limit.unwrap_or(log.len());
        log.iter().rev().take(limit).cloned().collect()
    }

    pub fn render_tools_list(tools: &[McpTool]) -> String {
        let mut output = String::from("MCP Tools Available\n");
        output.push_str("═══════════════════\n\n");

        let mut by_category: HashMap<&str, Vec<&McpTool>> = HashMap::new();
        for tool in tools {
            by_category
                .entry(tool.category.as_str())
                .or_default()
                .push(tool);
        }

        for (cat, cat_tools) in &by_category {
            output.push_str(&format!("{}\n", cat.to_uppercase()));
            for tool in cat_tools {
                output.push_str(&format!(
                    "  {:<25} {}\n",
                    tool.name, tool.description
                ));
            }
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_tools_list() {
        let server = McpToolServer::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let list = rt.block_on(server.list_tools());
        let output = McpToolServer::render_tools_list(&list);
        assert!(output.contains("kraken_scan"));
        assert!(output.contains("kraken_analyze"));
        assert!(output.contains("kraken_exploit"));
    }

    #[tokio::test]
    async fn test_register_and_list_tools() {
        let server = McpToolServer::new();
        let tool = McpTool {
            name: "custom_tool".to_string(),
            description: "A custom tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            category: "custom".to_string(),
        };
        server.register_tool(tool).await;
        let tools = server.list_tools().await;
        assert!(tools.iter().any(|t| t.name == "custom_tool"));
    }

    #[tokio::test]
    async fn test_token_lifecycle() {
        let server = McpToolServer::new();
        let token = server
            .create_token("agent-1", vec!["scan".to_string()], None)
            .await;
        assert!(server.validate_token(&token.token).await.is_some());
        assert!(server.revoke_token(&token.token).await);
        assert!(server.validate_token(&token.token).await.is_none());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let server = McpToolServer::new();
        let token = server
            .create_token("agent-2", vec!["scan".to_string()], Some(2))
            .await;
        assert!(server.check_rate_limit(&token.token).await.is_ok());
        assert!(server.check_rate_limit(&token.token).await.is_ok());
        let result = server.check_rate_limit(&token.token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_tool() {
        let server = McpToolServer::new();
        let call = McpToolCall {
            id: "call-1".to_string(),
            tool_name: "kraken_scan".to_string(),
            arguments: serde_json::json!({"target": "192.168.1.0/24", "scan_type": "quick"}),
            caller_id: "test".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let result = server.call_tool(call).await;
        assert!(result.success);
        assert_eq!(result.call_id, "call-1");
    }

    #[tokio::test]
    async fn test_call_nonexistent_tool() {
        let server = McpToolServer::new();
        let call = McpToolCall {
            id: "call-2".to_string(),
            tool_name: "nonexistent_tool".to_string(),
            arguments: serde_json::json!({}),
            caller_id: "test".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let result = server.call_tool(call).await;
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_call_log() {
        let server = McpToolServer::new();
        for i in 0..3 {
            let call = McpToolCall {
                id: format!("call-{}", i),
                tool_name: "kraken_scan".to_string(),
                arguments: serde_json::json!({"target": "test"}),
                caller_id: "test".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            server.call_tool(call).await;
        }
        let log = server.get_call_log(Some(2)).await;
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_get_tool() {
        let server = McpToolServer::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tool = rt.block_on(server.get_tool("kraken_scan"));
        assert!(tool.is_some());
        let tool2 = rt.block_on(server.get_tool("kraken_analyze"));
        assert!(tool2.is_some());
    }
}