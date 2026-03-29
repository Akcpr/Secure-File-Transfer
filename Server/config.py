"""
Server configuration.
Secrets are read from environment variables so they are never hardcoded in source.
Copy .env.example to .env and set your own values before running the server.
"""

import os
import hashlib

# ---------------------------------------------------------------------------
# Master password hash
# Used to authorise the creation of admin accounts.
# Set the MASTER_HASH env var to the SHA-256 hex-digest of your master password.
# Generate with:
#   python -c "import hashlib; print(hashlib.sha256(b'YOUR_PASSWORD').hexdigest())"
# ---------------------------------------------------------------------------
MASTER_HASH = os.environ.get('MASTER_HASH')
if not MASTER_HASH:
    raise EnvironmentError(
        "MASTER_HASH environment variable is not set. "
        "Generate one with: python -c \"import hashlib; print(hashlib.sha256(b'YOUR_PASSWORD').hexdigest())\" "
        "then set it in your .env file."
    )
