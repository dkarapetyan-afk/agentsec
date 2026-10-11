use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    Codex,
    Grok,
    Gemini,
    Antigravity,
    Claude,
    Cursor,
    Aider,
    All,
}

pub struct SkillLocations {
    pub codex: PathBuf,
    pub shared: PathBuf,
    pub grok: PathBuf,
    pub gemini: PathBuf,
    pub antigravity: PathBuf,
    pub claude: PathBuf,
    pub cursor: PathBuf,
    pub aider: PathBuf,
}

impl SkillLocations {
    pub fn from_environment() -> Result<Self> {
        let home = directories::BaseDirs::new()
            .context("Cannot locate user configuration directory")?
            .home_dir()
            .to_path_buf();
        let override_dir = |name: &str, fallback: PathBuf| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or(fallback)
        };
        Ok(Self {
            codex: override_dir("CODEX_HOME", home.join(".codex")).join("skills/agentsec"),
            shared: home.join(".agents/skills/agentsec"),
            grok: override_dir("GROK_HOME", home.join(".grok")).join("skills/agentsec"),
            gemini: home.join(".gemini/skills/agentsec"),
            antigravity: override_dir("GEMINI_CONFIG_DIR", home.join(".gemini/config"))
                .join("skills/agentsec"),
            claude: override_dir("CLAUDE_HOME", home.join(".claude")).join("skills/agentsec"),
            cursor: override_dir("CURSOR_HOME", home.join(".cursor")).join("skills/agentsec"),
            aider: override_dir("AIDER_HOME", home.join(".aider")).join("skills/agentsec"),
        })
    }

    pub fn all_known_targets(&self) -> Vec<(&'static str, &Path)> {
        vec![
            ("Codex", &self.codex),
            ("Grok", &self.grok),
            ("Gemini CLI", &self.gemini),
            ("Gemini / Antigravity", &self.antigravity),
            ("Claude", &self.claude),
            ("Cursor", &self.cursor),
            ("Aider", &self.aider),
            ("Shared agent discovery", &self.shared),
        ]
    }
}

// Embed the canonical bundle so `setup` works without a source checkout.
const FILES: &[(&str, &str)] = &[
    (
        "SKILL.md",
        include_str!("../.agents/skills/agentsec/SKILL.md"),
    ),
    (
        "references/cli_reference.md",
        include_str!("../.agents/skills/agentsec/references/cli_reference.md"),
    ),
    (
        "references/mcp_tools.md",
        include_str!("../.agents/skills/agentsec/references/mcp_tools.md"),
    ),
    (
        "references/best_practices.md",
        include_str!("../.agents/skills/agentsec/references/best_practices.md"),
    ),
    (
        "references/architecture.md",
        include_str!("../.agents/skills/agentsec/references/architecture.md"),
    ),
    (
        "scripts/check_daemon.sh",
        include_str!("../.agents/skills/agentsec/scripts/check_daemon.sh"),
    ),
    (
        "scripts/get_secret.sh",
        include_str!("../.agents/skills/agentsec/scripts/get_secret.sh"),
    ),
    (
        "scripts/run_with_secrets.sh",
        include_str!("../.agents/skills/agentsec/scripts/run_with_secrets.sh"),
    ),
    (
        "scripts/scan_leaks.sh",
        include_str!("../.agents/skills/agentsec/scripts/scan_leaks.sh"),
    ),
    (
        "scripts/set_secret.sh",
        include_str!("../.agents/skills/agentsec/scripts/set_secret.sh"),
    ),
    (
        "examples/bash_usage.sh",
        include_str!("../.agents/skills/agentsec/examples/bash_usage.sh"),
    ),
    (
        "examples/node_usage.js",
        include_str!("../.agents/skills/agentsec/examples/node_usage.js"),
    ),
    (
        "examples/python_usage.py",
        include_str!("../.agents/skills/agentsec/examples/python_usage.py"),
    ),
];

pub fn check_skill_installed(root: &Path) -> bool {
    root.join("SKILL.md").exists()
}

pub fn resolve_targets(
    locations: &SkillLocations,
    agent_spec: &str,
    target: Option<&Path>,
) -> Vec<(String, PathBuf)> {
    if let Some(custom) = target {
        let label = if agent_spec.is_empty()
            || agent_spec.eq_ignore_ascii_case("all")
            || agent_spec.eq_ignore_ascii_case("custom")
        {
            "Custom target directory".to_string()
        } else {
            format!("Custom target ({})", agent_spec)
        };
        return vec![(label, custom.to_path_buf())];
    }

    let home = directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    match agent_spec.to_lowercase().as_str() {
        "all" => vec![
            ("Codex".into(), locations.codex.clone()),
            ("Grok".into(), locations.grok.clone()),
            ("Gemini CLI".into(), locations.gemini.clone()),
            ("Gemini / Antigravity".into(), locations.antigravity.clone()),
            ("Claude".into(), locations.claude.clone()),
            ("Cursor".into(), locations.cursor.clone()),
            ("Aider".into(), locations.aider.clone()),
            ("Shared agent discovery".into(), locations.shared.clone()),
        ],
        "codex" => vec![
            ("Codex".into(), locations.codex.clone()),
            ("Shared agent discovery".into(), locations.shared.clone()),
        ],
        "grok" => vec![("Grok".into(), locations.grok.clone())],
        "gemini" => vec![
            ("Gemini CLI".into(), locations.gemini.clone()),
            ("Gemini / Antigravity".into(), locations.antigravity.clone()),
            ("Shared agent discovery".into(), locations.shared.clone()),
        ],
        "antigravity" => vec![("Gemini / Antigravity".into(), locations.antigravity.clone())],
        "claude" | "claude-code" => vec![("Claude".into(), locations.claude.clone())],
        "cursor" => vec![("Cursor".into(), locations.cursor.clone())],
        "aider" => vec![("Aider".into(), locations.aider.clone())],
        custom => {
            let sanitized = custom.trim_start_matches('.');
            let dir = home.join(format!(".{}/skills/agentsec", sanitized));
            vec![(format!("Agent '{}'", sanitized), dir)]
        }
    }
}

pub fn install_to_targets(
    targets: &[(String, PathBuf)],
    dry_run: bool,
) -> Result<Vec<(String, PathBuf)>> {
    let mut installed = vec![];
    for (label, root) in targets {
        if !dry_run {
            for (relative, contents) in FILES {
                let target = root.join(relative);
                if std::fs::read_to_string(&target).ok().as_deref() == Some(contents) {
                    continue;
                }
                std::fs::create_dir_all(target.parent().unwrap())
                    .with_context(|| format!("Cannot create {} skill directory", label))?;
                if target.exists() {
                    let backup = target.with_file_name(format!(
                        "{}.previous",
                        target.file_name().unwrap().to_string_lossy()
                    ));
                    std::fs::copy(&target, backup)
                        .with_context(|| format!("Cannot back up {} skill file", label))?;
                }
                std::fs::write(&target, contents)
                    .with_context(|| format!("Cannot install {} skill file", label))?;
                #[cfg(unix)]
                if relative.starts_with("scripts/") || relative.starts_with("examples/") {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
                }
            }
        }
        installed.push((label.clone(), root.clone()));
    }
    Ok(installed)
}

pub fn install(
    locations: &SkillLocations,
    agent: Agent,
    dry_run: bool,
) -> Result<Vec<&'static str>> {
    let mut targets: Vec<(&'static str, &Path)> = vec![];
    if matches!(agent, Agent::All | Agent::Codex) {
        targets.push(("Codex", &locations.codex));
    }
    if matches!(agent, Agent::All | Agent::Grok) {
        targets.push(("Grok", &locations.grok));
    }
    if matches!(agent, Agent::All | Agent::Gemini) {
        targets.push(("Gemini CLI", &locations.gemini));
        targets.push(("Gemini / Antigravity", &locations.antigravity));
    }
    if matches!(agent, Agent::Antigravity) {
        targets.push(("Gemini / Antigravity", &locations.antigravity));
    }
    if matches!(agent, Agent::All | Agent::Claude) {
        targets.push(("Claude", &locations.claude));
    }
    if matches!(agent, Agent::All | Agent::Cursor) {
        targets.push(("Cursor", &locations.cursor));
    }
    if matches!(agent, Agent::All | Agent::Aider) {
        targets.push(("Aider", &locations.aider));
    }
    // Shared discovery supports both Codex and Gemini CLI. Respect an existing symlink.
    if matches!(agent, Agent::All | Agent::Codex | Agent::Gemini) {
        targets.push(("Shared agent discovery", &locations.shared));
    }
    let mut installed = vec![];
    for (label, root) in targets {
        if !dry_run {
            for (relative, contents) in FILES {
                let target = root.join(relative);
                if std::fs::read_to_string(&target).ok().as_deref() == Some(contents) {
                    continue;
                }
                std::fs::create_dir_all(target.parent().unwrap())
                    .with_context(|| format!("Cannot create {} skill directory", label))?;
                if target.exists() {
                    let backup = target.with_file_name(format!(
                        "{}.previous",
                        target.file_name().unwrap().to_string_lossy()
                    ));
                    std::fs::copy(&target, backup)
                        .with_context(|| format!("Cannot back up {} skill file", label))?;
                }
                std::fs::write(&target, contents)
                    .with_context(|| format!("Cannot install {} skill file", label))?;
                #[cfg(unix)]
                if relative.starts_with("scripts/") || relative.starts_with("examples/") {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
                }
            }
        }
        installed.push(label);
    }
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_agent_target_resolution() {
        let temp = std::env::temp_dir().join(format!("agentsec-custom-{}", rand::random::<u64>()));
        let locations = SkillLocations {
            codex: temp.join("codex"),
            shared: temp.join("shared"),
            grok: temp.join("grok"),
            gemini: temp.join("gemini"),
            antigravity: temp.join("antigravity"),
            claude: temp.join("claude"),
            cursor: temp.join("cursor"),
            aider: temp.join("aider"),
        };
        let custom_dir = temp.join("my-agent/skills");
        let targets = resolve_targets(&locations, "custom-agent", Some(&custom_dir));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1, custom_dir);

        let dynamic = resolve_targets(&locations, "windsurf", None);
        assert_eq!(dynamic.len(), 1);
        assert!(dynamic[0].1.to_string_lossy().contains(".windsurf"));
        std::fs::remove_dir_all(temp).ok();
    }

    #[test]
    fn setup_is_idempotent_and_preserves_custom_files() {
        let temp = std::env::temp_dir().join(format!("agentsec-setup-{}", rand::random::<u64>()));
        std::fs::create_dir(&temp).unwrap();
        let locations = SkillLocations {
            codex: temp.join("codex"),
            shared: temp.join("shared"),
            grok: temp.join("grok"),
            gemini: temp.join("gemini"),
            antigravity: temp.join("antigravity"),
            claude: temp.join("claude"),
            cursor: temp.join("cursor"),
            aider: temp.join("aider"),
        };
        install(&locations, Agent::All, true).unwrap();
        assert!(!locations.codex.exists());
        install(&locations, Agent::All, false).unwrap();
        std::fs::write(locations.codex.join("custom.txt"), "keep").unwrap();
        std::fs::write(locations.codex.join("SKILL.md"), "custom instructions").unwrap();
        install(&locations, Agent::All, false).unwrap();
        install(&locations, Agent::All, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(locations.codex.join("SKILL.md.previous")).unwrap(),
            "custom instructions"
        );
        assert_eq!(
            std::fs::read_to_string(locations.codex.join("custom.txt")).unwrap(),
            "keep"
        );
        for root in [
            &locations.codex,
            &locations.shared,
            &locations.grok,
            &locations.gemini,
            &locations.antigravity,
            &locations.claude,
            &locations.cursor,
            &locations.aider,
        ] {
            assert_eq!(
                std::fs::read_to_string(root.join("SKILL.md")).unwrap(),
                FILES[0].1
            );
        }
        std::fs::remove_dir_all(temp).unwrap();
    }
}
