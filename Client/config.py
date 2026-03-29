"""
Client configuration.
Secrets are read from environment variables so they are never hardcoded in source.
Copy .env.example to .env and set your own values before running the client.
"""

import os

# ---------------------------------------------------------------------------
# Password pepper
# Mixed into every password hash alongside the per-user salt.
# Must be the same value across all clients connecting to the same server.
# Set the PASSWORD_PEPPER env var to your own secret string.
# ---------------------------------------------------------------------------
PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER')
if not PASSWORD_PEPPER:
    raise EnvironmentError(
        "PASSWORD_PEPPER environment variable is not set. "
        "Set it to a random secret string in your .env file."
    )
