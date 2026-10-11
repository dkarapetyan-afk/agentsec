#!/usr/bin/env python3
"""Run: agentsec run --clean-env --only API_KEY,DATA_DIR -- python3 examples/python_usage.py."""
import os

api_key = os.environ.get("API_KEY")
data_dir = os.environ.get("DATA_DIR", "./data")
if not api_key:
    raise RuntimeError("API_KEY is missing")
print("Required credential is available; storage location resolved.")
# Use api_key and data_dir in the operation requiring them. Do not print either value.
