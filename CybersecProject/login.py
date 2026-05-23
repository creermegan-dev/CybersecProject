import sqlite3
import hashlib

# Step 1: Define the pepper (same as in register.py)
PEPPER = "SuperSecretPepper123!"

# Step 2: Ask user for login details
username = input("Enter your username: ")
password = input("Enter your password: ")

# Step 3: Connect to database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Step 4: Look up user
cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
row = cursor.fetchone()

if row:
    stored_hash, salt = row
    # Step 5: Hash entered password with salt + pepper
    combined = password + salt + PEPPER
    hashed_password = hashlib.sha256(combined.encode()).hexdigest()

    # Step 6: Compare with stored hash
    if hashed_password == stored_hash:
        print("Login successful!")
    else:
        print("Invalid password.")
else:
    print("Username not found.")

conn.close()