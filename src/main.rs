use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, io::{self, Write}, path::{Path, PathBuf}, process::ExitCode};
use walkdir::WalkDir;

const LOGO: &str = include_str!("../assets/abora-fastfetch.txt");

#[derive(Parser)]
#[command(name="avs", version, about="Abora Vulnerability Scanner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Scan a local project recursively (read-only)
    Scan {
        #[arg(default_value=".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t=Format::Text)]
        format: Format,
        #[arg(long, default_value="avs-report.json")]
        output: PathBuf,
        /// Query OSV for Rust crates in Cargo.lock (requires network)
        #[arg(long)]
        cve: bool,
        /// Include hidden files (except .git)
        #[arg(long)]
        hidden: bool,
    },
    /// Print a previously saved AVS JSON report
    Report { #[arg(default_value="avs-report.json")] file: PathBuf },
}
#[derive(Clone, Copy, ValueEnum)]
enum Format { Text, Json, Sarif }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    code: String,
    severity: String,
    category: String,
    file: String,
    line: usize,
    message: String,
    recommendation: String,
    #[serde(skip_serializing_if="Option::is_none")]
    cve: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Report {
    scanner: String,
    version: String,
    target: String,
    files_scanned: usize,
    warnings: Vec<String>,
    findings: Vec<Finding>,
}
fn finding(code:&str, severity:&str, category:&str, file:&Path, line:usize, message:&str, recommendation:&str) -> Finding {
    Finding { code:code.into(), severity:severity.into(), category:category.into(), file:file.display().to_string(), line, message:message.into(), recommendation:recommendation.into(), cve:None }
}
fn scan(root:&Path, hidden:bool, cve:bool) -> Report {
    let rules = [
        ("AVS-SEC-001","HIGH","Security",r"\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b","Remote download piped into shell","Download, inspect, and verify checksums before executing"),
        ("AVS-SEC-002","HIGH","Security",r"\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b","Remote download piped into shell","Avoid piping untrusted downloads into shell"),
        ("AVS-SEC-003","MEDIUM","Security",r"\bchmod\s+777\b","World-writable permissions","Use least-privilege permissions"),
        ("AVS-SEC-004","HIGH","Security",r#"(?i)\b(?:password|api_key|secret)\s*[:=]\s*['"][^'"\s]{8,}['"]"#,"Possible hardcoded secret","Review manually and rotate any real exposed credentials"),
        ("AVS-SEC-005","HIGH","Security",r#"\beval\s+"?\$"#,"Variable expanded via shell eval","Avoid eval on variable-controlled input"),
        ("AVS-NIX-001","HIGH","Nix",r"\b(?:security\.sudo\.wheelNeedsPassword\s*=\s*false|users\.users\.\w+\.isNormalUser\s*=\s*false)\b","Potentially unsafe Nix configuration","Review privileged access and user configuration"),
        ("AVS-NIX-002","HIGH","Nix",r"\b(?:permittedInsecurePackages|allowInsecure)\b","Nix insecure package allowance","Remove or document insecure package exceptions"),
        ("AVS-NIX-003","MEDIUM","Nix",r"\b(?:fetchTarball|fetchurl)\b","External Nix fetch","Ensure sources are pinned and verified with hashes"),
        ("AVS-QUAL-001","LOW","Quality",r"\b(?:TODO|FIXME|HACK)\b","Outstanding maintenance marker","Review and track in issue backlog"),
    ];
    let compiled:Vec<Regex>=rules.iter().map(|r| Regex::new(r.3).unwrap()).collect();
    let mut report=Report { scanner:"AVS".into(), version:env!("CARGO_PKG_VERSION").into(), target:root.display().to_string(), files_scanned:0, warnings:vec![], findings:vec![] };
    let walker=WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
        let name=e.file_name().to_string_lossy();
        if e.depth()==0 { return true; }
        if [".git","target","node_modules",".direnv",".venv","vendor","result"].contains(&name.as_ref()) { return false; }
        hidden || !name.starts_with('.')
    });
    let mut locks=vec![];
    for entry in walker {
        let entry=match entry { Ok(e)=>e, Err(e)=>{report.warnings.push(e.to_string());continue} };
        if !entry.file_type().is_file() { continue; }
        let path=entry.path();
        if path.file_name().and_then(|s|s.to_str())==Some("Cargo.lock") { locks.push(path.to_path_buf()); }
        // Only inspect likely textual sources; avoid treating screenshots and wallpapers as scan failures.
        if let Some(ext)=path.extension().and_then(|e|e.to_str()) {
            if ["png","jpg","jpeg","webp","gif","ico","svgz","pdf","zip","tar","gz","xz","zst","mp3","ogg","mp4","woff","woff2","ttf","otf","so","a","o","bin","iso"].contains(&ext.to_ascii_lowercase().as_str()) {continue;}
        }
        let metadata=match entry.metadata(){Ok(m)=>m,Err(e)=>{report.warnings.push(format!("{}: {e}",path.display()));continue}};
        if metadata.len()>2_000_000 {report.warnings.push(format!("Skipped oversized file: {}",path.display()));continue;}
        let bytes=match fs::read(path){Ok(v)=>v,Err(e)=>{report.warnings.push(format!("{}: {e}",path.display()));continue}};
        if bytes.contains(&0) {continue;}
        let content=match String::from_utf8(bytes){Ok(s)=>s,Err(_)=>continue};
        report.files_scanned+=1;
        let nix=path.extension().and_then(|x|x.to_str())==Some("nix");
        for (i,line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            let comment = trimmed.starts_with("#") || trimmed.starts_with("//");
            // Ignore scanner rule definitions to avoid AVS flagging its own patterns.
            if path.file_name().and_then(|x| x.to_str()) == Some("main.rs") && line.contains("(\"AVS-") { continue; }
            for (rule,re) in rules.iter().zip(compiled.iter()) {
                if rule.0.starts_with("AVS-NIX") && !nix {continue;}
                if rule.0.starts_with("AVS-QUAL") && !["rs","sh","bash","nix","py","c","cpp","h","cs","go","js","ts"].contains(&path.extension().and_then(|x|x.to_str()).unwrap_or("")) {continue;}
                if comment && (rule.0.starts_with("AVS-SEC") || rule.0.starts_with("AVS-QUAL")) {continue;}
                if re.is_match(line) {
                    report.findings.push(finding(rule.0,rule.1,rule.2,path,i+1,rule.4,rule.5));
                }
            }
        }
        if path.file_name().and_then(|x|x.to_str())==Some("flake.lock") {
            if let Ok(value)=serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(nodes)=value.get("nodes").and_then(|v|v.as_object()) {
                    for (name,node) in nodes {
                        if node.get("locked").and_then(|l|l.get("rev")).is_none() && node.get("locked").is_some() {
                            report.findings.push(finding("AVS-NIX-004","INFO","Nix",path,1,&format!("Flake input {name} has no Git revision (may be another lock type)"),"Inspect input lock metadata"));
                        }
                    }
                }
            } else {report.warnings.push(format!("Invalid flake.lock JSON: {}",path.display()));}
        }
    }
    if cve {
        let mut seen=HashSet::new();
        for lock in locks {
            let Ok(raw)=fs::read_to_string(&lock) else {continue};
            let Ok(parsed)=raw.parse::<toml::Value>() else {report.warnings.push(format!("Cannot parse {}",lock.display()));continue};
            if let Some(packages)=parsed.get("package").and_then(|v|v.as_array()) {
                for pkg in packages {
                    let (Some(name),Some(version))=(pkg.get("name").and_then(|v|v.as_str()),pkg.get("version").and_then(|v|v.as_str())) else {continue};
                    if !pkg.get("source").and_then(|v|v.as_str()).unwrap_or("").starts_with("registry+") {continue;}
                    if !seen.insert((name.to_string(),version.to_string())) {continue;}
                    let request=serde_json::json!({"package":{"name":name,"ecosystem":"crates.io"},"version":version});
                    let response=ureq::post("https://api.osv.dev/v1/query").timeout(std::time::Duration::from_secs(12)).send_json(request);
                    match response {
                        Ok(r)=>{
                            let Ok(v)=r.into_json::<serde_json::Value>() else {continue};
                            for vuln in v.get("vulns").and_then(|v|v.as_array()).into_iter().flatten() {
                                let id=vuln.get("id").and_then(|v|v.as_str()).unwrap_or("OSV-unknown");
                                let cve_id=vuln.get("aliases").and_then(|v|v.as_array()).and_then(|a|a.iter().filter_map(|x|x.as_str()).find(|x|x.starts_with("CVE-")));
                                let mut f=finding("AVS-CVE-001","HIGH","Dependency",&lock,1,&format!("{name} {version}: {id}"),"Review OSV advisory, upgrade dependency, and validate affected version");
                                f.cve=cve_id.map(str::to_string);
                                report.findings.push(f);
                            }
                        }
                        Err(e)=>report.warnings.push(format!("OSV lookup failed for {name} {version}: {e}")),
                    }
                }
            }
        }
        report.warnings.push("CVE checks currently cover crates.io dependencies in Cargo.lock only; Nix packages are NOT matched to CVEs yet.".into());
    }
    report
}
fn sarif(report:&Report)->serde_json::Value {
    let results:Vec<_>=report.findings.iter().map(|f|serde_json::json!({
        "ruleId":f.code,"level":match f.severity.as_str(){"HIGH"|"CRITICAL"=>"error","MEDIUM"=>"warning",_=>"note"},
        "message":{"text":format!("{} — {}",f.message,f.recommendation)},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.file},"region":{"startLine":f.line.max(1)}}}]
    })).collect();
    serde_json::json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"AVS","version":report.version}},"results":results}]})
}
fn main()->ExitCode {
    let cli=Cli::parse();
    match cli.command {
        None => {
            println!("{LOGO}\n  AVS  |  Abora Vulnerability Scanner\n  v{}  •  Read-only security & quality analysis\n",env!("CARGO_PKG_VERSION"));
            print!("  Project folder [.] : ");
            if io::stdout().flush().is_err() { return ExitCode::from(2); }
            let mut input=String::new();
            if io::stdin().read_line(&mut input).is_err() {return ExitCode::from(2);}
            let chosen=input.trim();
            let path=if chosen.is_empty(){PathBuf::from(".")}else{
                let expanded=if chosen=="~" {std::env::var("HOME").unwrap_or_else(|_|chosen.to_string())}
                else if let Some(rest)=chosen.strip_prefix("~/") {format!("{}/{}",std::env::var("HOME").unwrap_or_else(|_|"~".into()),rest)}
                else {chosen.to_string()};
                PathBuf::from(expanded)
            };
            if !path.exists(){eprintln!("Target not found: {}",path.display());return ExitCode::from(2);}
            print!("  Check crates.io CVEs using OSV? [y/N] : ");
            if io::stdout().flush().is_err(){return ExitCode::from(2);}
            let mut answer=String::new();
            if io::stdin().read_line(&mut answer).is_err(){return ExitCode::from(2);}
            let report=scan(&path,false,matches!(answer.trim().to_lowercase().as_str(),"y"|"yes"));
            println!("\n  Scanned {} files • {} findings • {} warnings",report.files_scanned,report.findings.len(),report.warnings.len());
            for f in &report.findings {println!("  {} [{}] {}:{} — {}",f.code,f.severity,f.file,f.line,f.message);}
            for w in &report.warnings {eprintln!("  Warning: {w}");}
            match serde_json::to_string_pretty(&report) {
                Ok(json)=>match fs::write("avs-report.json",json){
                    Ok(())=>println!("\n  Report saved: avs-report.json"),
                    Err(e)=>{eprintln!("Cannot save report: {e}");return ExitCode::from(2);}
                },
                Err(e)=>{eprintln!("Cannot serialize report: {e}");return ExitCode::from(2);}
            }
            ExitCode::SUCCESS
        },
        Some(Command::Scan{path,format,output,cve,hidden})=>{
            if !path.exists(){eprintln!("Target not found: {}",path.display());return ExitCode::from(2);}
            let report=scan(&path,hidden,cve);
            let rendered=match format {
                Format::Text=>{
                    eprintln!("AVS • scanned {} text files; {} findings; {} warnings",report.files_scanned,report.findings.len(),report.warnings.len());
                    for f in &report.findings {println!("{} [{}] {}:{} — {}",f.code,f.severity,f.file,f.line,f.message);}
                    for w in &report.warnings {eprintln!("Warning: {w}");}
                    serde_json::to_string_pretty(&report).unwrap()
                },
                Format::Json=>serde_json::to_string_pretty(&report).unwrap(),
                Format::Sarif=>serde_json::to_string_pretty(&sarif(&report)).unwrap(),
            };
            if !matches!(format,Format::Text) {println!("{rendered}");}
            if let Err(e)=fs::write(&output,rendered){eprintln!("Could not save {}: {e}",output.display());return ExitCode::from(2);}
            eprintln!("Report saved: {}",output.display());
            ExitCode::SUCCESS
        },
        Some(Command::Report{file})=>match fs::read_to_string(&file) {
            Ok(raw)=>match serde_json::from_str::<Report>(&raw){
                Ok(r)=>{println!("AVS report: {} files, {} findings",r.files_scanned,r.findings.len());for f in r.findings{println!("{} [{}] {}:{} — {}",f.code,f.severity,f.file,f.line,f.message);}ExitCode::SUCCESS},
                Err(e)=>{eprintln!("Invalid AVS report: {e}");ExitCode::from(2)}
            },
            Err(e)=>{eprintln!("Cannot read report: {e}");ExitCode::from(2)}
        }
    }
}
