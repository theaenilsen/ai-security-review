import hashlib


def cache_key(url):
    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()
