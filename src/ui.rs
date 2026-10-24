//! AVS colored terminal presentation; JSON/SARIF output stays plain.
use std::io::{self, IsTerminal};
use crate::{Finding, Report, LOGO};

pub fn enabled() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}
fn ink(text: &str, color: &str) -> String {
    if enabled() {format!("\x1b[{color}m{text}\x1b[0m")} else {text.into()}
}
fn severity_color(sev: &str) -> &'static str {
    match sev { "CRITICAL"|"HIGH"=>"1;31", "MEDIUM"=>"1;33", "LOW"=>"1;36", _=>"2;37" }
}
pub fn heading(scope: &str, path: &str) {
    println!("{}",ink("  ╭────────────────────────────────────────────────────────╮","36"));
    println!("  │  {}  {}",ink("AVS / Abora Vulnerability Scanner","1;36"),ink(env!("CARGO_PKG_VERSION"),"2;37"));
    println!("{}",ink("  ╰────────────────────────────────────────────────────────╯","36"));
    println!("  {}  {}",ink("Project","1;37"),path);
    println!("  {}    {}",ink("Scope","1;37"),scope);
}
pub fn welcome() {
    if enabled() { println!("{}",ink(LOGO,"36")); } else {println!("{LOGO}");}
    println!("{}  {}",ink("AVS","1;36"),ink("Abora Vulnerability Scanner","1;37"));
    println!("{}  {}",ink("v0.3","2;37"),ink("Source analysis · Nix build inputs · OSV advisories","2;37"));
    println!();
}
pub fn summary(report: &Report) {
    let high = report.findings.iter().filter(|f|f.severity=="HIGH"||f.severity=="CRITICAL").count();
    let medium = report.findings.iter().filter(|f|f.severity=="MEDIUM").count();
    let info = report.findings.len()-high-medium;
    println!();
    println!("  {}",ink("SCAN COMPLETE","1;36"));
    println!("  {}  {} files   {} findings   {} warnings",
        ink("•","36"),report.files_scanned,report.findings.len(),report.warnings.len());
    println!("  {} elevated   {} medium   {} low / informational",
        ink(&high.to_string(),"1;31"),ink(&medium.to_string(),"1;33"),ink(&info.to_string(),"36"));
    if report.findings.is_empty() {
        println!("  {}",ink("No heuristic findings. This is not a security certification.","33"));
    }
}
pub fn findings(findings: &[Finding]) {
    if findings.is_empty() {return;}
    println!("\n  {}",ink("FINDINGS","1;37"));
    for f in findings {
        println!("  {}  {}  {}",
            ink(&f.code,"1;36"),ink(&format!("[{}]",f.severity),severity_color(&f.severity)),f.message);
        println!("      {}:{}",ink(&f.file,"2;37"),f.line);
        println!("      {} {}",ink("Fix / Review:","2;37"),f.recommendation);
    }
}
pub fn warnings(warnings:&[String]) {
    for w in warnings {eprintln!("  {} {w}",ink("!","1;33"));}
}
pub fn saved(path:&str) {
    println!("\n  {} {}",ink("Saved report →","1;32"),path);
}
