#print("Cybersecurity Project is ready!")
#import sqlite3

## Step 1: Define the pepper (hidden secret)
#PEPPER = "SuperSecretPepper123!"  # keep hidden in code

## Step 2: Connect to database (creates file if not exists)
#conn = sqlite3.connect("users.db")
#cursor = conn.cursor()

## Step 3: Create users table
#cursor.execute("""
#CREATE TABLE IF NOT EXISTS users (
 #   username TEXT PRIMARY KEY,
  #  hashed_password TEXT NOT NULL,
   # salt TEXT NOT NULL
#)
#""")

#conn.commit()
#conn.close()

#print("Database setup complete with pepper ready!")

import sqlite3
import hashlib
import secrets

from auth import validate_password

# Step 1: Define the pepper (hidden secret)
PEPPER = "SuperSecretPepper123!"

# Step 2: Connect to database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Step 3: Create users table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL
)
""")

# Step 4: Ask user for username and password
username = input("Enter a username: ")
password = input("Enter a password: ")

valid, errors = validate_password(password)
if not valid:
    for error in errors:
        print(error)
    conn.close()
    raise SystemExit(1)

# Step 5: Generate a random salt
salt = secrets.token_hex(16)

# Step 6: Hash password + salt + pepper
combined = password + salt + PEPPER
hashed_password = hashlib.sha256(combined.encode()).hexdigest()

# Step 7: Save to database
try:
    cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                   (username, hashed_password, salt))
    conn.commit()
    print("User registered successfully!")
except sqlite3.IntegrityError:
    print("Username already exists. Try another one.")

conn.close()