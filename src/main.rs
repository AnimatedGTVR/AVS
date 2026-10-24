use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use serde::Serialize;
use std::{fs, path::PathBuf, process::ExitCode};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "avs", version, about = "Abora Vulnerability Scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    Report {
        #[arg(default_value = "avs-report.json")]
        file: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format { Text, Json, Sarif }

#[derive(Serialize)]
struct Finding {
    id: String,
    severity: &'static str,
    path: String,
    line: usize,
    description: &'static str,
}

fn scan(path: &PathBuf) -> Vec<Finding> {
    let rules = [
        ("AVS-001", "HIGH", r"(?i)\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", "Remote script piped directly into a shell"),
        ("AVS-002", "HIGH", r"(?i)\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", "Remote script piped directly into a shell"),
        ("AVS-003", "MEDIUM", r"\bchmod\s+777\b", "World-writable permissions"),
        ("AVS-004", "HIGH", r#"(?i)\b(?:password|api_key|secret)\s*[:=]\s*['"][^'"\s]{8,}['"]"#, "Possible hardcoded secret (requires review)"),
        ("AVS-005", "HIGH", r#"\beval\s+"?\$"#, "Potential shell evaluation of variable content"),
    ];
    let compiled: Vec<_> = rules.iter().map(|r| Regex::new(r.2).expect("valid rule")).collect();
    let mut findings = Vec::new();
    for entry in WalkDir::new(path).follow_links(false).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() { continue; }
        let p = entry.path();
        if p.components().any(|c| matches!(c.as_os_str().to_str(), Some(".git" | "target" | "node_modules" | ".direnv"))) { continue; }
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !["sh", "bash", "nix", "py", "rs", "toml", "yaml", "yml", "env", "conf"].contains(&ext) { continue; }
        let Ok(bytes) = fs::read(p) else { continue; };
        if bytes.len() > 2_000_000 || bytes.contains(&0) { continue; }
        let Ok(content) = String::from_utf8(bytes) else { continue; };
        for (line_number, line) in content.lines().enumerate() {
            for (rule, pattern) in rules.iter().zip(&compiled) {
                if pattern.is_match(line) {
                    findings.push(Finding { id: rule.0.into(), severity: rule.1, path: p.display().to_string(), line: line_number + 1, description: rule.3 });
                }
            }
        }
    }
    findings
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { path, format } => {
            if !path.exists() { eprintln!("Path does not exist: {}", path.display()); return ExitCode::from(2); }
            let findings = scan(&path);
            match format {
                Format::Text => {
                    for f in &findings { println!("[{}] {} {}:{} — {}", f.severity, f.id, f.path, f.line, f.description); }
                    println!("{} potential finding(s). Review manually; these are heuristic matches.", findings.len());
                }
                Format::Json => println!("{}", serde_json::to_string_pretty(&findings).unwrap()),
                Format::Sarif => {
                    let results: Vec<_> = findings.iter().map(|f| serde_json::json!({
                        "ruleId": f.id, "level": if f.severity == "HIGH" { "error" } else { "warning" },
                        "message": { "text": f.description },
                        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.path }, "region": { "startLine": f.line } } }]
                    })).collect();
                    let report = serde_json::json!({"version":"2.1.0", "$schema":"https://json.schemastore.org/sarif-2.1.0.json", "runs":[{"tool":{"driver":{"name":"AVS", "version":"0.1.0-alpha"}},"results":results}]});
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
            }
            ExitCode::SUCCESS
        }
        Command::Report { file } => {
            match fs::read_to_string(&file) {
                Ok(data) => match serde_json::from_str::<serde_json::Value>(&data) {
                    Ok(v) => { println!("{}", serde_json::to_string_pretty(&v).unwrap()); ExitCode::SUCCESS },
                    Err(e) => { eprintln!("Invalid JSON report: {e}"); ExitCode::from(2) }
                },
                Err(e) => { eprintln!("Cannot read report: {e}"); ExitCode::from(2) }
            }
        }
    }
}