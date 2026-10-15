import pyotp
import bcrypt
import qrcode
import os
import csv

# secret pepper, but not so secret for this demonstration
pepper = "zrszk2v$8M87%nm@"

# CSV file
CSV_FILE = "users.csv"
FIELDNAMES = ["username", "password", "otp_secret"]


# basic login. TOTP keys stored in a json file for learning purposes. i wouldn't do it in a real app.
if __name__ == "__main__":
    print("Working directory:", os.getcwd())
    # basic cli that asks to register or login
    print("Sam's basic authentication system")
    print("1. Register")
    print("2. Login")
    choice = input("Enter your choice: ")
    if choice == "1":
        username = input("Enter your username: ")
        # check if username already exists
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["username"] == username:
                    print(
                        "Username already exists. Please choose a different username."
                    )
                    exit()
        password = input("Enter your password: ")
        # random totp
        user_otp_secret = pyotp.random_base32()
        user_totp = pyotp.TOTP(user_otp_secret)
        # generate qr code for the user to scan
        qr = qrcode.QRCode()
        qr.add_data(
            user_totp.provisioning_uri(name=username, issuer_name="Sam's Auth System")  # type: ignore
        )
        qr.make(fit=True)
        qr.print_ascii()
        print("Scan the QR code")
        # Ask for currept OTP to finish registration
        otp_input = input("Enter the current OTP from your authenticator app: ")
        while not user_totp.verify(otp_input):
            print("Invalid OTP. Please try again.")
            otp_input = input("Enter the current OTP from your authenticator app: ")
        password_hash = bcrypt.hashpw(
            (password + pepper).encode(), bcrypt.gensalt(rounds=14)
        ).decode("utf-8")

        # Create the CSV file with headers if it doesn't exist
        file_exists = os.path.exists(CSV_FILE)

        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

            if not file_exists or os.path.getsize(CSV_FILE) == 0:
                writer.writeheader()

            writer.writerow(
                {
                    "username": username,
                    "password": password_hash,
                    "otp_secret": user_otp_secret,
                }
            )

        print("Registration successful!")
    if choice == "2":
        username = input("Enter your username: ")
        stored_password_hash = None
        stored_otp_secret = None
        # check if user exists
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["username"] == username:
                    stored_password_hash = row["password"]
                    stored_otp_secret = row["otp_secret"]
                    break
        if stored_password_hash is None:
            print("Username does not exist.")
            exit()
        password = input("Enter your password: ")
        # check password
        if not bcrypt.checkpw(
            (password + pepper).encode(), stored_password_hash.encode()
        ):
            print("Incorrect password.")
            exit()
        # check OTP
        otp_input = input("Enter the current OTP from your authenticator app: ")
        while not pyotp.TOTP(stored_otp_secret).verify(otp_input):  # type: ignore
            print("Invalid OTP. Please try again.")
            otp_input = input("Enter the current OTP from your authenticator app: ")
        print("Login successful!")
