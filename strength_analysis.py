# Section 1: Password Strength Analysis
from math import log2
from shared import passwords


def load_common_passwords(filename: str) -> set[str]:
    with open(filename, "r", encoding="utf-8") as file:
        return {line.strip() for line in file}


COMMON_PASSWORDS = load_common_passwords("xato-net-10-million-passwords.txt")


def check_password_strength(password_input: str) -> None:
    score = util_length_check(password_input) + util_variety_check(password_input)
    entropy = len(password_input) * log2(util_pool_size(password_input))

    if password_input in COMMON_PASSWORDS:
        print(
            f'Password "{password_input}" is compromised, but has a score of 0 and entropy of {entropy}'
        )

    print(
        f'Password "{password_input}" has a score of {score} and entropy of {entropy}'
    )


for password in passwords:
    check_password_strength(password)


def util_length_check(password_input: str) -> int:
    """Return points based on password length."""
    return 2 if len(password_input) >= 12 else 1 if len(password_input) >= 8 else 0


def util_variety_check(password_input: str) -> int:
    """Return points based on password character variety."""
    return sum(
        [
            any(c.islower() for c in password_input),
            any(c.isupper() for c in password_input),
            any(c.isdigit() for c in password_input),
            any(not c.isalnum() for c in password_input),
        ]
    )


def util_pool_size(password_input: str) -> int:
    """Return the size of the character pool used in the password."""
    pool_size = 0
    if any(c.islower() for c in password_input):
        pool_size += 26
    if any(c.isupper() for c in password_input):
        pool_size += 26
    if any(c.isdigit() for c in password_input):
        pool_size += 10
    if any(not c.isalnum() for c in password_input):
        pool_size += 32
    return pool_size
