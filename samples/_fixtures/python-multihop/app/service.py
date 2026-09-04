"""Middle hop: normalises the payload and forwards it to the parser."""

from app.parser import parse_document


def handle_upload(raw):
    normalized = raw.strip()
    return parse_document(normalized)
