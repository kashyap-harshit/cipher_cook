import hashlib


def md5_of_string(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()