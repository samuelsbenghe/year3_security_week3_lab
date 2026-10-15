import hashlib
import bcrypt

user_password = "user123password"
rounds = 14

print("Same password hashed twice, no salt, no pepper")

hash1 = hashlib.sha256(user_password.encode()).hexdigest()
hash2 = hashlib.sha256(user_password.encode()).hexdigest()

print(f"First hash: {hash1}")
print(f"Second hash: {hash2}")

print("\n")

print("Same password hashed twice, with salt, no pepper")

hash1 = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt(rounds=rounds))
hash2 = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt(rounds=rounds))

print(f"First hash: {hash1}")
print(f"Second hash: {hash2}")

print("\n")

print("Same password hashed twice, with salt, with pepper")

pepper = "#pQAm7v9TVsfWUuU"

hash1 = bcrypt.hashpw((user_password + pepper).encode(), bcrypt.gensalt(rounds=rounds))
hash2 = bcrypt.hashpw((user_password + pepper).encode(), bcrypt.gensalt(rounds=rounds))

print(f"First hash: {hash1}")
print(f"Second hash: {hash2}")
