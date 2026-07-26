# Kraken

> Plataforma de ciberseguridad ofensiva todo-en-uno en Rust. Un solo binario que reemplaza ~40 herramientas de Kali Linux, potenciado por 8 LLMs frontier y análisis de kernel Mythos-level.

```
cargo install kraken
```

---

## Visión

Kraken es una plataforma de ciberseguridad ofensiva que integra reconocimiento, escaneo, explotación, post-explotación, forenses e inteligencia artificial en un solo binario compilado en Rust. Utiliza LLMs frontier (incluyendo Kimi K3 con ventana de 1M tokens) para análisis semántico de código, generación de hipótesis de vulnerabilidad y coordinación autónoma de agentes.

---

## Arquitectura

```
kraken/
├── runtime/          # Core: sesiones, permisos, prompt, MCP, conversación
├── api/              # 8 providers LLM (Anthropic, OpenAI, DeepSeek, Kimi K3, ...)
├── security/         # Cifrado AES-256-GCM, vault de credenciales, auditoría
├── vulnscan/         # Motor de escaneo + pipeline de vulnerabilidades
│   ├── exploit/      # Shellcode multi-arch, ROP chains, inyectores
│   ├── kernel/       # 14 checkers AST, parsers KASAN/KCSAN/KMSAN
│   ├── context_pipeline/  # 1M context pipeline, chunking por relevancia
│   └── program_slice/     # Call graph builder, extracción de slices
├── forensics/        # 10 módulos: PCAP, memoria, disco, YARA, timeline
├── osint/            # DNS, WHOIS, email, ASN, Shodan, darkweb, 75+ redes
├── network/          # Port scanning, DNS, servicio discovery, masscan
├── c2/               # Command & Control: HTTP/DNS/WebSocket beaconing
├── mobile/           # Análisis APK, Frida scripts, bypass SSL/root
├── cloudsec/         # Auditoría AWS/GCP/Azure, Kubernetes, Docker
├── wireless/         # WiFi, Bluetooth, deauthentication, evil twin
├── postexploit/      # Credential hunting, escalación, persistencia
├── reverse/          # Ingeniería inversa: disassembly, entropía
├── supplychain/      # Análisis OSV, typosquat, dependency risk
├── localmodels/      # ML local: classifier, sequence analysis, ensemble
├── kraken-infra/     # Sandbox real: Seccomp BPF, Landlock LSM, namespaces
├── plugins/          # Sistema de plugins extensible
├── telemetry/        # Telemetría y métricas
├── optimization/     # Algoritmos PSO, ACO, simulated annealing, GA
├── rusty-claude-cli/ # Binario principal (target: kraken)
└── ...               # 43 crates en total
```

---

## Comandos

### CLI Principal

```bash
kraken vulnscan --dir .              # Escaneo de vulnerabilidades
kraken osint --domain example.com   # OSINT completo
kraken campaign --target 10.0.0/24  # Campaña autónoma
kraken exploit --generate           # Generación de exploits
kraken doctor                       # Diagnosticar entorno
kraken sandbox                      # Estado del sandbox
kraken plugins list                 # Listar plugins
kraken skills list                  # Listar skills
```

### REPL Interactivo (100+ slash commands)

```bash
# Escaneo y análisis
/hunt                    # Pipeline multi-etapa: recon → scan → chain → hipótesis
/shodan                  # Buscar en Shodan dispositivos y servicios
/bughunter               # Inspeccionar código en busca de bugs
/security-review         # Revisión de seguridad del codebase

# Explotación
/exploit                  # Generar exploit para una vulnerabilidad
/shellcode                # Generar shellcode multi-arch
/rop-chain                # Construir ROP chain para un binario

# Inteligencia
/ultraplan                # Planificación profunda multi-paso
/reasoning                # Modo de razonamiento extendido
/parallel                 # Ejecutar comandos en sub-agentes paralelos

# Gestión
/commit                   # Generar mensaje de commit
/pr                       # Crear pull request
/review                   # Code review
/perf                     # Análisis de rendimiento
```

---

## Capacidades Detalladas

### Vulnerability Scanning

| Feature | Detalle |
|---------|---------|
| **SQL Injection** | Detección en templates, ORM raw queries, parámetros URL |
| **XSS** | Stored, reflected, DOM-based en templates y JavaScript |
| **Command Injection** | `os.execute`, `system()`, backticks, pipe operators |
| **Secrets** | API keys, tokens, private keys, high entropy strings |
| **IaC Security** | Terraform, Docker, Kubernetes, CloudFormation (14 checkers AST) |
| **Kernel Analysis** | Tree-sitter AST patterns, 14 checkers: stack overflow, UAF, double free, OOB, integer overflow, type confusion, ioctl, kmalloc, double fetch, procfs, sysfs, etc. |
| **Sanitizers** | Parsers para KASAN, KCSAN, KMSAN — classificación automática de bug types |
| **Hypothesis Engine** | Genera hipótesis de vulnerabilidad a partir de findings (UAF, race conditions, logic bypasses, crypto weakness, injection, privesc) |

### Exploitation Engine

| Architecture | Shellcode | Reverse Shell | Bind Shell | XOR Decoder |
|-------------|-----------|---------------|------------|-------------|
| Linux x64 | ✅ execve `/bin/sh` | ✅ connect-back | ✅ listen | ✅ |
| Linux x86 | ✅ execve `/bin/sh` | ✅ connect-back | ✅ listen | ✅ |
| Linux ARM | ✅ execve | ✅ connect-back | ✅ listen | ✅ |
| Linux ARM64 | ✅ execve | ✅ connect-back | ✅ listen | ✅ |
| Windows x64 | ✅ WinExec | ✅ reverse TCP | ✅ bind TCP | — |
| Windows x86 | — | ✅ reverse TCP | ✅ bind TCP | — |
| macOS x64/ARM64 | ✅ execve | — | — | — |

- **ROP Chain Builder**: Templates para x64 y x86 con gadgets reales
- **Payload Encoders**: Hex, C array, Python, XOR, alphanumeric
- **Injectors**: ELF, PE, MachO — inyección de shellcode en binarios
- **Metasploit Modules**: Generación de módulos .rb auto-configurados
- **Kernel Exploits**: commit_creds ROP, modprobe_path, Dirty Pipe, PhysmapSpray

### Inteligencia Artificial (Fase 2)

| Componente | Detalle |
|-----------|---------|
| **8 LLM Providers** | Anthropic, OpenAI, DeepSeek, Ollama, DashScope, Kimi K3 (1M context), OpenRouter, Big Pickle |
| **1M Context Pipeline** | Chunking de codebase por relevancia, risk-ranked, selective context, context cache |
| **Program-Slice Analysis** | Call graph builder (BFS transitive callees/callers), slice extractor, risk-ranked slices |
| **Multi-Agent** | MetaAgent coordinator, 3 sub-agents (Static Analysis, LLM Semantic, Exploit Generation), cross-validation de findings |
| **LLM Analyst** | Clasificación automática de vulnerabilidades (SQLi, XSS, memory corruption, kernel CWEs) |

### Forensics (10 módulos)

PCAP analysis, memory forensics, disk imaging, browser history, email parsing, registry analysis, timeline reconstruction, YARA rules, file carving, entropy analysis.

### OSINT

DNS enumeration, WHOIS, email harvesting, ASN lookup, Shodan integration, crt.sh, 75+ redes sociales, dark web monitoring, Google dorking.

### Network

Port scanning (masscan integration), DNS spoofing, ARP spoofing, service discovery, WiFi audit, Bluetooth LE, deauthentication.

### Post-Exploitation

Credential hunting (Linux/Windows), privilege escalation paths, persistence mechanisms, lateral movement, pivoting.

### Cloud Security

AWS S3/IAM/EC2 auditing, GCP, Azure, Kubernetes security contexts, Dockerfile analysis.

---

## Stats

| Métrica | Valor |
|---------|-------|
| **Crates** | 43 |
| **Líneas de código** | ~210,000 |
| **Tests** | 513+ (427 unit + 74 integration + 12 meta_agent) |
| **Doc-tests** | 74 |
| **Unsafe** | 0 |
| **LLM providers** | 8 |
| **Shellcode architectures** | 6 (Linux x64/x86/ARM/ARM64, Windows x64/x86, macOS) |
| **Slash commands** | 143 |
| **Kernel AST checkers** | 14 |
| **Sanitizer parsers** | 3 (KASAN, KCSAN, KMSAN) |

---

## Plataformas

- **Linux**: x86_64, ARM, ARM64 (primary)
- **macOS**: x86_64, ARM64 (Apple Silicon)
- **Windows**: x86_64, x86
- **FreeBSD**: x86_64
- **Raspberry Pi**: ARM, ARM64

---

## Build desde source

### Linux (Ubuntu/Debian)

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
OPENSSL_DIR=/usr \
OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu \
OPENSSL_INCLUDE_DIR=/usr/include \
cargo build --release
```

### macOS

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release
```

### Requisitos

- Rust 1.75+ (stable)
- OpenSSL development headers
- `pkg-config` (Linux)

---

## Roadmap v4.0 — Auditoría Arquitectónica

| Fase | Estado | Detalle |
|------|--------|---------|
| **F0: Build clean** | ✅ | `cargo check --workspace` compila limpio |
| **F6: rand migration** | ✅ | rand 0.8→0.10, 12 crates hardcoded, 30 archivos migrados |
| **F10: Real sandbox** | ✅ | Seccomp BPF, Landlock LSM, namespaces, rlimits integrados en kraken-infra |
| **F11: Deprecations** | ✅ | SHA-256 KDF deprecated, `KdfAlgorithm::Sha256` deprecated |
| **F12: Flaky test** | ✅ | Test aicampaign determinizado (factor random eliminado) |
| **F8: OnceLock globals** | ⏭️ | 6 globals confinados a tools/src/lib.rs — bajo impacto, pendiente |
| **F5: Decompose main.rs** | ⏳ | main.rs (13.7K líneas) → 5 sub-crates |
| **F7: Clippy suppressions** | ⏳ | 18 `#[allow(clippy)]` en main.rs — requiere F5 |

---

## Licencia

MIT
