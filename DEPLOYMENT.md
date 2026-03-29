# Deployment Notes

This project defaults to `localhost` / `127.0.0.1` for local development on Windows.
Follow the steps below when deploying on a real network (e.g., Kali Linux lab environment).

---

## 1 — Update the SSL certificate SAN

In [Server/generate_certificates.py](Server/generate_certificates.py), change the `san_extensions` line
inside `generate_certificate()`:

```python
# localhost (default — development only)
san_extensions = "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Real network — replace with your server's hostname and IP
san_extensions = "subjectAltName=DNS:your-server-hostname,IP:192.168.x.x"
```

Also update the `CN` field in `subject_information` to match your hostname.

## 2 — Update the client HOST

In [Client/client.py](Client/client.py), change:

```python
HOST = 'localhost'
```

to your server's IP address or hostname:

```python
HOST = '192.168.x.x'
```

## 3 — Regenerate certificates

After making the changes above, re-run the certificate generator from the `Server/` directory:

```bash
python generate_certificates.py
```

Redistribute the new `certificate.pem` to all clients via the certificate server.

## 4 — Firewall / ports

Ensure the following ports are open on the server host:

| Port | Service |
|------|---------|
| 9999 | Main file transfer server (TCP) |
| 8000 | Certificate distribution HTTP server |
