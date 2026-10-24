# AVS 0.2-alpha — Abora Vulnerability Scanner

Read-only recursive security and code-quality scanner written in Rust, with the official Abora OS fastfetch ASCII logo.

## Build and run

```bash
cargo run --
cargo run -- scan "$HOME/Work/Abora-OS" --output avs-report.json
cargo run -- scan "$HOME/Work/Abora-OS" --cve --output avs-report.json
cargo run -- scan "$HOME/Work/Abora-OS" --format sarif --output avs-report.sarif
cargo run -- report avs-report.json
```

AVS accepts any local path. It scans readable UTF-8 text files recursively; binary files, symlinks, and files over 2 MB are skipped. By default hidden paths, .git, target, node_modules, .direnv, .venv, vendor, and result are skipped. Use `--hidden` to include hidden paths except excluded directories. Scanning is read-only except writing the report file.

## Finding codes

- AVS-SEC-001/002: Remote script piped into a shell
- AVS-SEC-003: World-writable permissions
- AVS-SEC-004: Possible hardcoded secret
- AVS-SEC-005: Shell eval of variable input
- AVS-NIX-001/002: Privileged or insecure Nix settings
- AVS-NIX-003/004: External Nix fetch or unusual flake lock metadata
- AVS-QUAL-001: TODO/FIXME/HACK maintenance marker
- AVS-CVE-001: OSV advisory for a crates.io package

## Limitations

Heuristic matches require manual review. No fixes are applied. `--cve` sends crates.io package names and versions from Cargo.lock to OSV, requires network access, and may be slow or rate-limited. It does **not** yet match Nix packages to CVEs. Nix rules and flake.lock checks are configuration checks, not confirmed vulnerabilities. The CLI does not presently provide an interactive Claude Code-like conversation; it uses a branded terminal interface and explicit commands.

## Security

Do not upload scan reports containing sensitive source paths or potential secrets without reviewing them. No project source code is sent to OSV. See LICENSE for GPL-3.0 licensing.
