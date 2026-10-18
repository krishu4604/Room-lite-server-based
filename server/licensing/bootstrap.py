"""First-start initialization on a persistent volume; never rotates existing keys."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def prepare():
    root = Path(os.environ.get("ROOMLITE_LICENSE_DATA", "/data/roomlite")).resolve()
    password = os.environ.get("ROOMLITE_ADMIN_PASSWORD", "")
    hashed = os.environ.get("ROOMLITE_ADMIN_PASSWORD_HASH", "")
    if len(password) < 16 and not hashed.startswith(("scrypt:", "pbkdf2:")):
        raise RuntimeError("Set ROOMLITE_ADMIN_PASSWORD (at least 16 characters) or ROOMLITE_ADMIN_PASSWORD_HASH before starting.")
    if os.environ.get("MONGODB_URI"):
        if len(os.environ.get("ROOMLITE_MASTER_SECRET", "")) < 32:
            raise RuntimeError("Set a stable ROOMLITE_MASTER_SECRET of at least 32 characters for Atlas key encryption.")
        return None  # Atlas mode never writes private files to an ephemeral disk.
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    signing = root / "signing.pem"
    accounts = root / "accounts.key"
    if signing.exists() != accounts.exists():
        raise RuntimeError("Private keys are incomplete. Restore the missing key from backup; initialization will not overwrite existing keys.")
    if not signing.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with signing.open("xb") as out:
            out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with accounts.open("xb") as out:
            out.write(AESGCM.generate_key(bit_length=256))
    # Store a stable private cookie signing key separately from subscription signing.
    session_key = root / "admin-session.key"
    if not os.environ.get("ROOMLITE_ADMIN_SESSION_SECRET"):
        if not session_key.exists():
            with session_key.open("x", encoding="ascii") as out:
                out.write(secrets.token_urlsafe(48))
        os.environ["ROOMLITE_ADMIN_SESSION_SECRET"] = session_key.read_text(encoding="ascii")
    if len(os.environ["ROOMLITE_ADMIN_SESSION_SECRET"]) < 32:
        raise RuntimeError("Administrator session secret must have at least 32 characters.")
    if os.name != "nt":
        for private_file in (signing, accounts, session_key):
            if private_file.exists():
                private_file.chmod(0o600)
    os.environ["ROOMLITE_LICENSE_DATA"] = str(root)
    return root


def application():
    from licensing.service import create_app
    return create_app(prepare())


if __name__ == "__main__":
    prepare()
    if "--local" in sys.argv:
        os.environ["ROOMLITE_ADMIN_LOCAL_HTTP"] = "1"
        from licensing.service import create_app
        create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5011")), debug=False)
    else:
        # A single worker owns jobs; bootstrap is also run in that worker's app factory.
        os.execvp("gunicorn", ["gunicorn", "licensing.bootstrap:application()", "--bind", "0.0.0.0:" + os.environ.get("PORT", "8080"), "--workers", "1", "--threads", "8", "--timeout", "60"])
