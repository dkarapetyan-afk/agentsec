#!/usr/bin/env bash
# Run: agentsec run --clean-env --only API_KEY -- bash examples/bash_usage.sh
set -euo pipefail
if [ -n "${API_KEY:-}" ]; then
    echo "API_KEY is available in process memory."
else
    echo "API_KEY is missing." >&2
    exit 1
fi
# Use "$API_KEY" in the operation requiring it; never echo its value.
