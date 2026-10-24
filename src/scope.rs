//! Conservative Abora ISO-source approximation, not the evaluated Nix closure.
//! Resolve literal source paths in live.nix / installed-base.nix and scan Nix definitions.
use regex::Regex;
use std::{collections::HashSet, fs, path::{Path, PathBuf}};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope { Repository, Iso }

pub struct IsoInputs {
    roots: Vec<PathBuf>,
    pub warnings: Vec<String>,
}
impl IsoInputs {
    pub fn collect(root: &Path) -> Self {
        let mut warnings = vec![
            "AVS-SCOPE-001: ISO scope approximates explicit Abora Nix source references; it is NOT a verified built ISO or complete evaluated Nix closure.".into()
        ];
        let mut paths = HashSet::new();
        // These are build definitions reviewed even though they are not themselves
        // necessarily present as regular files on the live filesystem.
        for name in ["flake.nix","flake.lock","nix/profiles/live.nix",
                     "nix/modules/installed-base.nix"] {
            let p = root.join(name);
            if p.exists() { paths.insert(p); }
        }
        // Syntax covers literal relative Nix paths used as source/src or
        // directly assigned to variables. Dynamic expressions need evaluation.
        let pattern = Regex::new(r"(?m)(?:\bsource\b|\bsrc\b|=)\s*=\s*(\.\./[A-Za-z0-9_./+-]+)").unwrap();
        for name in ["nix/profiles/live.nix","nix/modules/installed-base.nix"] {
            let definition = root.join(name);
            let Ok(body) = fs::read_to_string(&definition) else {
                warnings.push(format!("AVS-SCOPE-002: Missing {}, ISO mapping unavailable",definition.display()));
                continue;
            };
            let parent = definition.parent().unwrap_or(root);
            for line in body.lines() {
                if line.trim_start().starts_with('#') {continue;}
                for cap in pattern.captures_iter(line) {
                    let Some(m) = cap.get(1) else {continue};
                    let referenced = parent.join(m.as_str());
                    // Canonicalize to normalize ../../ and prevent lexical escapes.
                    if let Ok(p) = fs::canonicalize(&referenced) {
                        if p.starts_with(root) {
                            paths.insert(p);
                        }
                    }
                }
            }
        }
        // NixOS module definitions are security-sensitive build inputs; include
        // their source tree as build configuration, not as a claim of ISO payload.
        let nix = root.join("nix");
        if nix.exists() {paths.insert(nix);}
        if paths.len() < 5 {
            warnings.push("AVS-SCOPE-003: Few build inputs resolved; review paths and run a real Nix closure audit.".into());
        }
        Self { roots: paths.into_iter().collect(), warnings }
    }
    pub fn includes(&self, path: &Path) -> bool {
        self.roots.iter().any(|p| path == p || path.starts_with(p))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn picks_explicit_paths_and_rejects_tests() {
        let dir = std::env::temp_dir().join(format!("avs-scope-test-{}",std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("nix/profiles")).unwrap();
        fs::create_dir_all(dir.join("scripts/apps/tests")).unwrap();
        fs::write(dir.join("nix/profiles/live.nix"),
            r#"environment.etc."abora/apps.sh".source = ../../scripts/apps.sh;"#).unwrap();
        fs::write(dir.join("scripts/apps.sh"), "#!/bin/sh\n").unwrap();
        fs::write(dir.join("scripts/apps/tests/test.sh"), "eval \"$x\"").unwrap();
        let root = fs::canonicalize(&dir).unwrap();
        let iso=IsoInputs::collect(&root);
        assert!(iso.includes(&root.join("scripts/apps.sh")));
        assert!(!iso.includes(&root.join("scripts/apps/tests/test.sh")));
        fs::remove_dir_all(&dir).unwrap();
    }
}
