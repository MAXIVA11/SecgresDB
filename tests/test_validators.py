from secgresdb.validators import luhn_checksum, valid_ipv4, valid_iban, get_validator


def test_luhn_checksum_accepts_valid_visa():
    assert luhn_checksum("4532015112830366")


def test_luhn_checksum_rejects_random_digits():
    assert not luhn_checksum("1234567812345678")


def test_luhn_checksum_ignores_separators():
    assert luhn_checksum("4532-0151-1283-0366")


def test_luhn_checksum_rejects_too_short():
    assert not luhn_checksum("1234")


def test_valid_ipv4_accepts_normal_address():
    assert valid_ipv4("192.168.1.1")


def test_valid_ipv4_rejects_out_of_range_octet():
    assert not valid_ipv4("999.999.999.999")


def test_valid_ipv4_rejects_non_ip_text():
    assert not valid_ipv4("hello world")


def test_valid_iban_accepts_known_good_iban():
    assert valid_iban("GB82 WEST 1234 5698 7654 32")


def test_valid_iban_rejects_altered_checksum():
    assert not valid_iban("GB82 WEST 1234 5698 7654 33")


def test_valid_iban_rejects_vin_lookalike():
    # 17-char VIN that happens to satisfy the loose "2 letters + 2 digits + alnum" shape
    assert not valid_iban("AB12CM82633A123456")


def test_get_validator_returns_none_for_unknown_name():
    assert get_validator("does_not_exist") is None
    assert get_validator(None) is None


def test_get_validator_resolves_known_name():
    assert get_validator("luhn_checksum") is luhn_checksum
