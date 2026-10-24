# AVS — Abora Vulnerability Scanner

Early Rust CLI prototype for heuristic source scanning. Findings are **potential issues**, not confirmed vulnerabilities. No CVE matching is implemented yet.

## Build

```bash
cargo build --release
```

## Usage

```bash
cargo run -- scan ./Abora-OS
cargo run -- scan . --format json > avs-report.json
cargo run -- scan . --format sarif > avs-report.sarif
cargo run -- report avs-report.json
cargo run -- --version
```

Supported file extensions: sh, bash, nix, py, rs, toml, yaml, yml, env, conf. `.git`, `target`, `node_modules`, and `.direnv` directories are skipped. Scanner does not follow symlinks.

## Roadmap

- Add tests and structured rules with language-aware parsing
- Support ignore rules, suppression, and baseline comparisons
- Integrate OSV/NVD and Nix dependency analysis for real CVEs
- GitHub Actions integration, stable SARIF output, and release gates
- Audit Abora installer permissions and system configuration in a VM

## Security

Do not treat heuristic matches as verified vulnerabilities. Report suspected vulnerabilities privately to the maintainers rather than opening public issues with exploit details.

## License

GPL-3.0-only.
