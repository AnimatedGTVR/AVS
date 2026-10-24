# AVS — Abora Vulnerability Scanner

AVS v0.3.0-alpha is a read-only Rust security and quality scanner for Abora OS. Findings are **potential issues**, not confirmed vulnerabilities. Optional OSV queries check crates.io dependencies in Cargo.lock; Nix package CVE matching is not implemented yet.

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

## Remember your Abora OS folder

Run this once:

```bash
avs config set-project "$HOME/Work/Abora-OS"
```

AVS stores the folder in `$XDG_CONFIG_HOME/avs/config.json`, or `~/.config/avs/config.json` if `XDG_CONFIG_HOME` is unset. Subsequent `avs` runs use the saved folder automatically, and `avs scan` uses it when no path is supplied. Explicit paths with `avs scan /another/folder` do not overwrite the saved default.

```bash
avs config show
avs config clear
```

## AVS v0.3: color interface and scan scopes

```bash
avs                          # interactive: remembered project, scope selector, OSV prompt
avs scan --scope iso         # analyze source inputs declared in Abora Nix configurations
avs scan --scope repository  # scan the full repository (excluding vendor and build caches)
avs scan --scope iso --cve   # also query OSV for crates.io packages in included Cargo.lock
avs scan --scope iso --format sarif --output iso-report.sarif
NO_COLOR=1 avs              # disable colored output
```

Interactive mode defaults to **ISO source inputs** for an Abora checkout containing `nix/profiles/live.nix`, and **repository** for other projects. Noninteractive `avs scan` now automatically selects ISO source-input scope for recognized Abora checkouts; other projects use repository scope. Use `--scope repository` to override.

**ISO scope is an approximation, not proof of ISO contents.** It scans literal relative source references in `nix/profiles/live.nix` and `nix/modules/installed-base.nix`, plus Nix build configuration files. It does not evaluate dynamic Nix expressions or the final system closure. Build and inspect the real ISO to verify shipping files. Paths included through entire directories (for example `docs/`) may contain documentation examples.

The terminal uses color only on an interactive TTY, respects `NO_COLOR`, and leaves JSON/SARIF machine output free of ANSI codes. Report JSON includes a `scope` field.
