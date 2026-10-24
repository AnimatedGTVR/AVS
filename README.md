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


## Install the `avs` command

From the cloned AVS repository, run:

```bash
cargo install --path . --force
```

Make sure `~/.cargo/bin` is in your `PATH` (restart your shell if necessary). Then launch the interactive scanner with:

```bash
avs
```

Or run directly:

```bash
avs scan "$HOME/Work/Abora-OS" --cve --output avs-report.json
avs report avs-report.json
```

Running `avs` without arguments now prompts for a local folder and whether to query OSV for Rust crate vulnerabilities. It does not modify scanned source files. Reports may include sensitive file paths, so review before sharing.

See [AVS 0.2 documentation](README-AVS-0.2.md) for supported AVS finding codes and current Nix/CVE limitations.
