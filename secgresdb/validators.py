"""
Secondary validators for regex pattern matches.

A regex hit is a candidate, not a confirmed finding. These functions apply a
cheap, deterministic second check (checksum, range, structure) to cut down
false positives on numeric-ish patterns like credit cards and IP addresses.
Referenced by name from config/sensitive_patterns.json's "validator" field.
"""
import re


def luhn_checksum(value: str) -> bool:
    """Validate a credit-card-like number against the Luhn checksum."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 12:
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def valid_ipv4(value: str) -> bool:
    """Reject regex hits like 999.999.999.999 that aren't real IPv4 addresses."""
    match = re.search(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", value)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def valid_iban(value: str) -> bool:
    """
    ISO 7064 mod-97-10 checksum used by all real IBANs. Without this, the
    IBAN regex (2 letters + 2 digits + 10-30 alnum) also matches things like
    vehicle VINs by pure chance - a random string passes this checksum with
    probability ~1/97, so it reliably tells real IBANs from lookalikes.
    """
    s = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def valid_luhn_or_none(value: str) -> bool:
    """Alias kept for readability when wiring up patterns.json."""
    return luhn_checksum(value)


VALIDATORS = {
    "luhn_checksum": luhn_checksum,
    "valid_ipv4": valid_ipv4,
    "valid_iban": valid_iban,
}


def get_validator(name: str):
    """Look up a validator callable by name; returns None if not registered."""
    if not name:
        return None
    return VALIDATORS.get(name)
