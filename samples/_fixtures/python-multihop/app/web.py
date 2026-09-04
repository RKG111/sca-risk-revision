"""Entry point: untrusted YAML arrives here and is handed down two more hops."""

from flask import Flask, request

from app.service import handle_upload

app = Flask(__name__)


@app.post("/upload")
def upload():
    payload = request.get_data(as_text=True)
    return handle_upload(payload)
