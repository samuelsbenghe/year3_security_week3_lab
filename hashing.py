from shared import passwords
import hashlib
import bcrypt


def basic_hashing(password: str) -> list[str]:
    """Return a basic hash of the password."""
    # MD5, SHA256
    md5_digest = hashlib.md5(password.encode()).hexdigest()
    sha256_digest = hashlib.sha256(password.encode()).hexdigest()
    return [str(md5_digest), str(sha256_digest)]


for password in passwords:
    print("Part 1: MD5 and SHA256 Hashing")
    print(
        f'Password "{password}" has an MD5 digest of {basic_hashing(password)[0]} and a SHA256 digest of {basic_hashing(password)[1]}'
    )


print("Part 2: Bcrypt Hashing")

random_salt = bcrypt.gensalt(rounds=14)


def bcrypt_hashing(password: str) -> bytes:
    """Return a bcrypt hash of the password."""
    return bcrypt.hashpw(password.encode(), random_salt)


hashed_password = bcrypt_hashing("1234")

print(f"Random bcrypt salt: {random_salt}")

user_password = input("Enter the password to check: ")

if bcrypt.checkpw(user_password.encode(), hashed_password):
    print("Password is correct!")
else:
    print("Password is incorrect!")
