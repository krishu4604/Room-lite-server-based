"""Optional: generate a password hash without echoing the password."""
import getpass
from werkzeug.security import generate_password_hash

password = getpass.getpass("Owner password (at least 16 characters): ")
if len(password) < 16:
    raise SystemExit("Use at least 16 characters.")
if password != getpass.getpass("Confirm password: "):
    raise SystemExit("Passwords do not match.")
print(generate_password_hash(password))
