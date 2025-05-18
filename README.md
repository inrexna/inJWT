
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

# 🔐 inJWT
```JWT Generator, Brute-force, Decoder & Verifier Tool | Open Source Version```
A powerful and flexible CLI tool to generate, decode, verify, and brute-force JSON Web Tokens (JWT). Built for CTF, research, and educational purposes by **InREXnA**.

---

## 🚀 Features

1. Generate JWT with algorithms `none`, `HS256`, or `RS256`
2. Decode header and payload of JWT tokens
3. Verify JWT HS256 signature using secret
4. Verify JWT RS256 signature using public key
5. Brute-force HS256 signature using a wordlist (with progress bar)
6. Save token or output results to a file
7. Lightweight and pure Python (uses `pyjwt` and `tqdm` only)

---

## 📦 Requirements

- Python 3.6+
- Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Installation

```bash
git clone https://github.com/inrexna/inJWT.git
cd inJWT
python3 inJWT.py --help
```

---

## ⚙️ Usage Examples

### 1. Generate Token with `none` Algorithm

```bash
python3 inJWT.py --generate --alg none --username admin --role admin
```

Example output:

```
📦 Token created:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
```

### 2. Generate Token with `HS256` Algorithm

```bash
python3 inJWT.py --generate --alg HS256 --secret supersecret --username test --role user
```

### 3. Decode JWT Token

```bash
python3 inJWT.py --decode <your_jwt_token>
```

### 4. Verify HS256 Token Signature

```bash
python3 inJWT.py --verify <your_jwt_token> --secret supersecret
```

### 5. Brute-force HS256 Token Signature

```bash
python3 inJWT.py --brute <jwt_token> --wordlist wordlist_JWT_10M.txt
```

### 6. Generate RS256 Token

```bash
python3 inJWT.py --generate --alg RS256 --private private.pem --username admin --role admin
```

### 7. Verify RS256 Token Signature

```bash
python3 inJWT.py --verify <jwt_token> --alg RS256 --public public.pem
```

### 8. Save Output to File

```bash
python3 inJWT.py --generate --alg HS256 --secret supersecret --output mytoken.txt
```

---

## 🧾 Full Argument Reference

| Argument        | Description                                      |
|----------------|--------------------------------------------------|
| `--generate`    | Generate new JWT                                 |
| `--decode`      | Decode a JWT token                               |
| `--verify`      | Verify JWT token (HS256 or RS256)                |
| `--brute`       | Brute-force JWT HS256 secret                     |
| `--wordlist`    | Wordlist file for brute-force                    |
| `--secret`      | Secret for HS256                                 |
| `--pubkey`      | Public key file for RS256 verification           |
| `--private`     | Private key file for RS256 token generation      |
| `--username`    | Username value (default: admin)                  |
| `--role`        | Role value (default: admin)                      |
| `--alg`         | Algorithm to use: `none`, `HS256`, `RS256`       |
| `--output`      | Save output/token to a file                      |

---

## 📝 Notes

- For RS256, ensure your `private.pem` and `public.pem` files are valid PEM format.
- For brute-forcing, you can use common lists like `rockyou.txt` or the `wordlist_JWT_10M` that I provided.
- Intended for educational use, CTF, and security testing. Do not misuse.

---

## Author

by **InREXnA**  
GitHub: [https://github.com/inrexna](https://github.com/inrexna)

License: [MIT](LICENSE)

### 🔑 RSA Key Usage (RS256)

To use RS256, you need to provide RSA private and public key files. You can generate them using `openssl`.

#### ✅ Generate RSA Key Pair:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private.pem -out public.pem
```

#### 🔐 Use the Private Key to Generate RS256 JWT

```bash
python3 inJWT.py --generate --alg RS256 --private private.pem --username admin --role admin
```

#### 🔍 Verify RS256 JWT with Public Key

```bash
python3 inJWT.py --verify --token <jwt_token> --alg RS256 --public public.pem
```
