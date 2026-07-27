"""Sample vulnerable usage of PyYAML FullLoader for end-to-end fixtures."""

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/config")
def load_config():
    raw = request.data.decode("utf-8")
    # Vulnerable: untrusted YAML via full_load
    data = yaml.full_load(raw)
    return {"ok": True, "keys": list(data.keys()) if isinstance(data, dict) else []}


def parse_user_yaml(payload: str):
    return yaml.load(payload, Loader=yaml.FullLoader)
