# ██ OMNI

**Autonomous Red Team AI Agent with Kernel-Level Governance.**

OMNI is not just another wrapper around an LLM. It is an autonomous offensive
security framework built in Python, with a rich interactive TUI and a governance
kernel in front of every action. It runs complex penetration-testing
engagements while respecting the signed scope, the rules of engagement and
operational security.

## ⚡ The "Why"

LLMs are chaotic. Giving an LLM unrestricted access to a shell is a recipe for
disaster. OMNI puts a **ToolGateway** in front of every action:

1. **Scope validation (HMAC):** a command against a target outside the signed
   engagement scope never executes.
2. **Durable approvals:** high-risk tools require an explicit human decision
   (`y/n/e/?`), recorded in the audit trail; `--trust-mode` auto-approves them
   except `DESTRUCTIVE` tools.
3. **Governed egress (SEC-01, opt-in):** with
   `NEXUS_SHELL_ISOLATION=egress`, the shell runs in a `bwrap` network namespace
   whose only exit is a scope-aware SOCKS5 proxy. Anything that ignores the
   proxy has no network at all (fail closed).
4. **Plugin trust (SEC-05):** third-party `nexus.tools` plugins are never
   imported until the operator approves them; the approval pins the SHA-256 of
   every file in the distribution, so any change revokes the trust.

## ✨ Features

- **88 herramientas** (built-in tools): Nmap, Subfinder and httpx for recon; Metasploit,
  SQLmap, Nuclei and ffuf for exploitation; Impacket, NetExec, BloodHound and
  Sliver for Active Directory, post-exploitation and C2; hashcat, Hydra and
  session management; plus a durable knowledge blackboard and report
  generation.
- **Bounded orders:** say *"scan ports 80 and 443"* and OMNI executes the tool
  directly with no engagement plan. Say *"compromise the DC"* and it creates a
  multi-phase plan with evidence-gated TODOs.
- **Durable ReAct loop:** every action, observation, approval and plan
  transition is persisted and hash-chained, so a run is auditable and can be
  resumed.
- **Premium TUI:** `prompt_toolkit` + `rich`, a red-rail operator block,
  collapsible reasoning, one-line tool calls, expandable evidence cards, a
  real port table and clickable `Ver N líneas más` / `Ver menos` footers.
- **Multi-model:** OpenAI, Anthropic, Gemini, DeepSeek, Groq, local Ollama and
  an offline deterministic Fake provider.
- **Reports:** Markdown, HTML and JSON, written to `<cwd>/reports` and
  registered as content-addressed artifacts with their SHA-256.

## 📸 Showcase

A bounded scan, rendered without a plan and with the evidence folded into a
card (open it to see the port table):

```text
▌ [01:20 PM]
▌ Escanea los puertos 80 y 443 de scanme.nmap.org usando nmap.

  ▸ Razonamiento
> Ejecutando nmap en scanme.nmap.org...
  ✓ nmap: 1 puertos abiertos (80) · hosts up: 1 · 4.44s · Ver 12 líneas más

╭──────────────────────────────────────────────────────────────────╮
│ Resultado                                                        │
│                                                                  │
│ ## Servicios                                                     │
│                                                                  │
│ | Puerto | Servicio | Estado |                                   │
│ | --- | --- | --- |                                              │
│ | 80 | http | open |                                             │
│                                                                  │
│ - estado: completed · iteraciones: 3                             │
╰──────────────────────────────────────────────────────────────────╯
```

## 🚀 Quickstart

OMNI requires Python 3.12+ on Linux or macOS.

```bash
# Clone the repository
git clone git@github.com:garyjr7/omni-agentcs.git
cd omni-agentcs

# Install in an isolated environment (pipx if available, otherwise a venv)
bash install.sh

# Store your provider key (it is not echoed)
omni auth login

# First run: environment check, provider, and a signed engagement
omni

# Or create one non-interactively (24 h by default)
omni --new-engagement my_lab --scope "10.0.0.1/24, scanme.nmap.org"

# Launch the TUI for that engagement
omni --engagement eng-my_lab
```

`omni --doctor` verifies the offensive environment (binaries, services,
Metasploit RPC, Sliver, dictionaries) before a run. `omni --setup --install`
shows the install plan; it only executes with `--yes`.

## 🛡️ Security Model

- **Scope:** engagements are signed with HMAC and every tool call is validated
  against their domains/CIDRs and validity window.
- **Approvals:** durable, single-use, atomic and audited; `DESTRUCTIVE` tools
  never auto-approve.
- **SEC-01:** governed egress with `bwrap` + SOCKS5 (opt-in). Raw-socket scans
  (`nmap -sS`, UDP) are not routed through a SOCKS5 proxy by design and are
  reported as such.
- **SEC-05:** plugin entry points are hash-pinned and only imported after
  operator approval.
- **Sandboxing:** local shell execution runs under `bwrap` when available, with
  a private HOME and a pinned filesystem view.

## 📚 Documentation

The full operational reference — configuration, XDG paths, every tool, the
planner, the report contract, the TUI, the security boundaries and the test
suite — is in [docs/README-detailed.md](docs/README-detailed.md).

## License

Released under the **Apache License 2.0**. You may use, modify and distribute
it, including commercially, provided you keep the copyright and license notices
and comply with the patent clause. The full text in [LICENSE](LICENSE) is the
only source of truth; attribution notices live in [NOTICE](NOTICE).

## Disclaimer

OMNI is designed for authorized security testing and educational purposes only.
The author (BajioWare) assumes no liability for any misuse or damage caused by
this tool. Users are solely responsible for complying with all applicable laws
and obtaining proper authorization before conducting any security assessments.

See [DISCLAIMER.md](DISCLAIMER.md) for the canonical text.

---

*Built for professionals. Use responsibly and only against authorized targets.*
