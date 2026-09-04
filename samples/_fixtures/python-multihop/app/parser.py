"""Final hop: the vulnerable sink, three functions away from the request."""

import yaml


def parse_document(text):
    return yaml.full_load(text)


def parse_safely(text):
    return yaml.safe_load(text)
