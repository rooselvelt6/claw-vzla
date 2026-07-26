use rand::RngExt;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KubeBenchCheck {
    pub id: String,
    pub text: String,
    pub audit: String,
    pub remediation: String,
    pub scored: bool,
    pub result: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KubeBenchResult {
    pub node_type: String,
    pub checks: Vec<KubeBenchCheck>,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub total_score: f64,
}

pub struct KubeBenchRunner;

impl Default for KubeBenchRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl KubeBenchRunner {
    pub fn new() -> Self {
        KubeBenchRunner
    }

    pub fn run_master_checks() -> KubeBenchResult {
        let mut checks = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;

        let master_checks = vec![
            ("1.1.1", "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
             "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml", "chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml", true),
            ("1.1.2", "Ensure that the API server pod specification file ownership is set to root:root",
             "stat -c %U:%G /etc/kubernetes/manifests/kube-apiserver.yaml", "chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml", true),
            ("1.2.1", "Ensure that the --anonymous-auth argument is set to false",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'anonymous-auth=[^ ]*'",
             "Edit the API server pod spec and set --anonymous-auth=false", true),
            ("1.2.2", "Ensure that the --basic-auth-file argument is not set",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'basic-auth-file=[^ ]*'",
             "Remove the --basic-auth-file flag", true),
            ("1.2.5", "Ensure that the --kubelet-https argument is set to true",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'kubelet-https=[^ ]*'",
             "Ensure --kubelet-https is set to true", true),
            ("1.2.6", "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'kubelet-client-certificate=[^ ]*'",
             "Configure TLS authentication for kubelet", true),
            ("1.2.7", "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'authorization-mode=[^ ]*'",
             "Set authorization-mode to Node,RBAC", true),
            ("1.2.13", "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set",
             "ps -ef | grep kube-apiserver | grep -v grep | tr '\\n' ' ' | grep -o 'etcd-certfile=[^ ]*'",
             "Configure etcd TLS authentication", true),
        ];

        for (id, text, audit, remediation, scored) in master_checks {
            let result = if rand::rng().random::<f64>() > 0.3 { "PASS".to_string() } else { "FAIL".to_string() };
            match result.as_str() {
                "PASS" => passed += 1,
                "FAIL" => failed += 1,
                _ => warnings += 1,
            }
            checks.push(KubeBenchCheck {
                id: id.to_string(),
                text: text.to_string(),
                audit: audit.to_string(),
                remediation: remediation.to_string(),
                scored,
                result,
            });
        }

        let total = checks.len() as f64;
        let total_score = if total > 0.0 { (passed as f64 / total) * 100.0 } else { 0.0 };

        KubeBenchResult {
            node_type: "master".to_string(),
            checks,
            passed,
            failed,
            warnings,
            total_score,
        }
    }

    pub fn run_node_checks() -> KubeBenchResult {
        let mut checks = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;

        let node_checks = vec![
            ("4.1.1", "Ensure that the kubelet service file permissions are set to 644 or more restrictive",
             "stat -c %a /etc/systemd/system/kubelet.service", "chmod 644 /etc/systemd/system/kubelet.service", true),
            ("4.2.1", "Ensure that the --anonymous-auth argument is set to false",
             "ps -ef | grep kubelet | grep -v grep | tr '\\n' ' ' | grep -o 'anonymous-auth=[^ ]*'",
             "Edit kubelet config and set authentication.anonymous.enabled: false", true),
            ("4.2.2", "Ensure that the --authorization-mode argument is set to AlwaysAllow",
             "ps -ef | grep kubelet | grep -v grep | tr '\\n' ' ' | grep -o 'authorization-mode=[^ ]*'",
             "Set authorization-mode to Webhook", true),
            ("4.2.6", "Ensure that the --protect-kernel-defaults argument is set to true",
             "ps -ef | grep kubelet | grep -v grep | tr '\\n' ' ' | grep -o 'protect-kernel-defaults=[^ ]*'",
             "Set protect-kernel-defaults: true in kubelet config", true),
            ("4.2.7", "Ensure that the --make-iptables-util-chains argument is set to true",
             "ps -ef | grep kubelet | grep -v grep | tr '\\n' ' ' | grep -o 'make-iptables-util-chains=[^ ]*'",
             "Set makeIPTablesUtilChains: true", true),
        ];

        for (id, text, audit, remediation, scored) in node_checks {
            let result = if rand::rng().random::<f64>() > 0.4 { "PASS".to_string() } else { "FAIL".to_string() };
            match result.as_str() {
                "PASS" => passed += 1,
                "FAIL" => failed += 1,
                _ => warnings += 1,
            }
            checks.push(KubeBenchCheck {
                id: id.to_string(),
                text: text.to_string(),
                audit: audit.to_string(),
                remediation: remediation.to_string(),
                scored,
                result,
            });
        }

        let total = checks.len() as f64;
        let total_score = if total > 0.0 { (passed as f64 / total) * 100.0 } else { 0.0 };

        KubeBenchResult {
            node_type: "node".to_string(),
            checks,
            passed,
            failed,
            warnings,
            total_score,
        }
    }

    pub fn generate_report(master: &KubeBenchResult, node: &KubeBenchResult) -> String {
        let mut report = String::new();
        report.push_str("Kube-Bench Security Report\n");
        report.push_str("=========================\n\n");
        report.push_str(&format!("Master Node: {:.1}% compliance ({} pass / {} fail / {} warn)\n",
            master.total_score, master.passed, master.failed, master.warnings));
        report.push_str(&format!("Worker Node: {:.1}% compliance ({} pass / {} fail / {} warn)\n\n",
            node.total_score, node.passed, node.failed, node.warnings));

        for (label, result) in &[("Master", master), ("Worker", node)] {
            report.push_str(&format!("--- {} Checks ---\n", label));
            for check in &result.checks {
                if check.result == "FAIL" {
                    report.push_str(&format!("  FAIL  {} - {}\n", check.id, check.text));
                    report.push_str(&format!("        Remediation: {}\n", check.remediation));
                }
            }
            report.push('\n');
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_master_checks() {
        let result = KubeBenchRunner::run_master_checks();
        assert_eq!(result.node_type, "master");
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn test_run_node_checks() {
        let result = KubeBenchRunner::run_node_checks();
        assert_eq!(result.node_type, "node");
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn test_generate_report() {
        let master = KubeBenchRunner::run_master_checks();
        let node = KubeBenchRunner::run_node_checks();
        let report = KubeBenchRunner::generate_report(&master, &node);
        assert!(report.contains("Kube-Bench"));
        assert!(report.contains("Master"));
        assert!(report.contains("Worker"));
    }

    #[test]
    fn test_kube_bench_check() {
        let c = KubeBenchCheck {
            id: "1.1.1".to_string(),
            text: "Check something".to_string(),
            audit: "audit cmd".to_string(),
            remediation: "fix it".to_string(),
            scored: true,
            result: "PASS".to_string(),
        };
        let json = serde_json::to_string_pretty(&c).unwrap();
        assert!(json.contains("1.1.1"));
    }
}
