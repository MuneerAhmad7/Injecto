import random, string

def marker(length: int = 6) -> str:
    """Return random alphanumeric marker used to detect echoed output."""
    return "".join(random.choices(string.ascii_letters, k=length))
