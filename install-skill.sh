#!/usr/bin/env bash
# Install the canonical bundle without replacing unrelated agent resources.
set -euo pipefail
TASK_SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.agents/skills/agentsec"
TASK_AGENT="${1:-all}"
case "$TASK_AGENT" in all|codex|grok|gemini) ;; *) echo "Usage: $0 [all|codex|grok|gemini]" >&2; exit 2;; esac
test -f "$TASK_SOURCE_ROOT/SKILL.md" || { echo "Canonical skill bundle is missing." >&2; exit 1; }
install_tree() {
    local task_target="$1" task_label="$2" task_file task_relative
    while IFS= read -r -d '' task_file; do
        task_relative="${task_file#"$TASK_SOURCE_ROOT/"}"
        mkdir -p "$(dirname "$task_target/$task_relative")"
        if [ -f "$task_target/$task_relative" ] && cmp -s "$task_file" "$task_target/$task_relative"; then
            continue
        fi
        if [ -f "$task_target/$task_relative" ]; then
            cp -p "$task_target/$task_relative" "$task_target/$task_relative.previous"
        fi
        cp -p "$task_file" "$task_target/$task_relative"
        case "$task_relative" in scripts/*|examples/*) chmod +x "$task_target/$task_relative";; esac
    done < <(find "$TASK_SOURCE_ROOT" -type f ! -name '*.previous' -print0)
    echo "Updated agentsec skill for $task_label."
}
if [ "$TASK_AGENT" = all ] || [ "$TASK_AGENT" = codex ]; then
    install_tree "${CODEX_HOME:-$HOME/.codex}/skills/agentsec" "Codex"
fi
if [ "$TASK_AGENT" = all ] || [ "$TASK_AGENT" = grok ]; then
    install_tree "${GROK_HOME:-$HOME/.grok}/skills/agentsec" "Grok"
fi
if [ "$TASK_AGENT" = all ] || [ "$TASK_AGENT" = gemini ]; then
    install_tree "$HOME/.gemini/skills/agentsec" "Gemini CLI"
    install_tree "${GEMINI_CONFIG_DIR:-$HOME/.gemini/config}/skills/agentsec" "Antigravity"
fi
if [ "$TASK_AGENT" != grok ]; then
    install_tree "$HOME/.agents/skills/agentsec" "shared agent discovery"
fi
echo "Reload agent skills. Existing MCP configuration has not been changed."
