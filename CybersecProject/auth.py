import hashlib
import os
import re
import secrets

import pymysql

PEPPER = "SuperSecretPepper123!"  # Server-side secret — never stored in the database
PASSWORD_MIN_LENGTH = 12


def _password_criteria(password: str) -> dict[str, bool]:
    """Password strength meter checks (project requirements)."""
    return {
        "length": len(password) >= PASSWORD_MIN_LENGTH,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }


def password_criteria_passed(password: str) -> int:
    return sum(_password_criteria(password).values())


def _mysql_config() -> dict:
    return {
        "host": os.environ.get("MYSQLHOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQLPORT", "3306")),
        "user": os.environ.get("MYSQLUSER", "root"),
        "password": os.environ.get("MYSQLPASSWORD", ""),
        "database": os.environ.get("MYSQLDATABASE", "cybersecproject"),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
    }


def get_connection():
    return pymysql.connect(**_mysql_config())

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    hashed_password VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL
                )
                """
            )
        conn.commit()
    finally:
        conn.close()


def _hash_password(password: str, salt: str) -> str:
    combined = password + salt + PEPPER
    return hashlib.sha256(combined.encode()).hexdigest()


def validate_password(password: str) -> tuple[bool, list[str]]:
    criteria = _password_criteria(password)
    errors = []
    if not criteria["length"]:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long.")
    if not criteria["lowercase"]:
        errors.append("Password must include at least one lowercase letter.")
    if not criteria["uppercase"]:
        errors.append("Password must include at least one uppercase letter.")
    if not criteria["digit"]:
        errors.append("Password must include at least one number.")
    if not criteria["symbol"]:
        errors.append("Password must include at least one special character.")
    return len(errors) == 0, errors


def password_strength(password: str) -> str:
    """Weak / Medium / Strong — matches project examples (password, Password123, Cyber@2026Secure)."""
    passed = password_criteria_passed(password)
    if passed <= 2:
        return "weak"
    if passed <= 4:
        return "medium"
    return "strong"


def register_user(
    username: str, password: str, confirm_password: str
) -> tuple[bool, str]:
    if not username or not password or not confirm_password:
        return False, "All fields are required."

    if password != confirm_password:
        return False, "Passwords do not match."

    valid, errors = validate_password(password)
    if not valid:
        return False, errors[0]

    salt = secrets.token_hex(16)
    hashed_password = _hash_password(password, salt)

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, hashed_password, salt) VALUES (%s, %s, %s)",
                (username, hashed_password, salt),
            )
        conn.commit()
        return True, "You have successfully registered!"
    except pymysql.IntegrityError:
        return False, "Username already exists. Try another one."
    except pymysql.Error as e:
        return False, f"Database error: {e}. Is XAMPP MySQL running?"
    finally:
        conn.close()


def verify_user(username: str, password: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required."

    try:
        conn = get_connection()
    except pymysql.Error as e:
        return False, f"Database error: {e}. Is XAMPP MySQL running?"

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username, hashed_password, salt FROM users WHERE username = %s",
                (username,),
            )
            row = cursor.fetchone()
    except pymysql.Error as e:
        return False, f"Database error: {e}. Is XAMPP MySQL running?"
    finally:
        conn.close()

    if not row:
        return False, "Invalid username or password. Please try again."

    if _hash_password(password, row["salt"]) == row["hashed_password"]:
        return True, row["username"]

    return False, "Invalid username or password. Please try again."
