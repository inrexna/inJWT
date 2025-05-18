#!/usr/bin/env python3

import base64
import json
import hmac
import hashlib
import argparse
import sys
from typing import Tuple
from tqdm import tqdm
import jwt
from jwt import exceptions

# Base64url encode dictionary
def base64url_encode(data: dict) -> str:
    json_bytes = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(json_bytes).decode().rstrip('=')

# Base64url decode string to dictionary
def base64url_decode(data: str) -> dict:
    try:
        padding = '=' * ((4 - len(data) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(data + padding))
    except Exception as e:
        raise ValueError(f"Invalid base64url data: {e}")

# Sign HS256 token
def sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip('=')

# Create JWT
def create_jwt(header: dict, payload: dict, alg='none', secret='', private_key_path='') -> str:
    header_b64 = base64url_encode(header)
    payload_b64 = base64url_encode(payload)

    if alg == 'none':
        return f"{header_b64}.{payload_b64}."
    elif alg.lower() == 'hs256':
        signature = sign_hs256(header_b64, payload_b64, secret)
        return f"{header_b64}.{payload_b64}.{signature}"
    elif alg.lower() == 'rs256':
        try:
            if not private_key_path:
                raise ValueError("RS256 requires --private key file.")
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
            return jwt.encode(payload, private_key_data, algorithm="RS256", headers=header)
        except FileNotFoundError:
            print(f"❌ Private key file not found: {private_key_path}")
            sys.exit(1)
        except exceptions.InvalidKeyError as e:
            print(f"❌ Invalid private key format: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error generating RS256 token: {e}")
            sys.exit(1)
    else:
        raise ValueError("Unsupported algorithm. Use 'none', 'HS256', or 'RS256'.")

# Decode JWT
def decode_jwt(token: str) -> Tuple[dict, dict]:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            raise ValueError("Token must have at least header and payload.")
        header = base64url_decode(parts[0])
        payload = base64url_decode(parts[1])
        return header, payload
    except Exception as e:
        print(f"❌ Failed to decode token: {e}")
        return None, None

# Verify HS256 token
def verify_hs256(token: str, secret: str) -> bool:
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        expected_sig = sign_hs256(header_b64, payload_b64, secret)
        return expected_sig == signature_b64
    except Exception:
        return False

# Verify RS256 token
def verify_rs256(token: str, public_key_path: str) -> bool:
    try:
        with open(public_key_path, 'rb') as f:
            public_key = f.read()
        jwt.decode(token, public_key, algorithms=["RS256"])
        return True
    except FileNotFoundError:
        print(f"❌ Public key file not found: {public_key_path}")
    except exceptions.InvalidSignatureError:
        return False
    except Exception as e:
        print(f"❌ Error verifying RS256 token: {e}")
    return False

# Brute force HS256 token
def brute_force(token: str, wordlist_path: str):
    try:
        with open(wordlist_path, 'r') as f:
            secrets = f.read().splitlines()
    except FileNotFoundError:
        print(f"❌ Wordlist file not found: {wordlist_path}")
        sys.exit(1)

    print(f"🔍 Brute forcing... Total passwords: {len(secrets)}")
    for secret in tqdm(secrets, desc="Brute Forcing"):
        if verify_hs256(token, secret):
            print(f"\n✅ Secret found: {secret}")
            return
    print("\n❌ Secret not found in the wordlist.")

# Save output to file
def save_output(data: str, path: str):
    try:
        with open(path, 'w') as f:
            f.write(data)
        print(f"\n💾 Results saved at: {path}")
    except Exception as e:
        print(f"❌ Failed to save file: {e}")

# Main CLI entry
def main():
    banner = """
🔹 JWT CLI Tool by InREXnA | Version 3.0 | Open Source Version
"""
    print(banner)

    parser = argparse.ArgumentParser(description="JWT Generator, Decoder & Brute HS256")
    parser.add_argument('--generate', action='store_true', help="Generate JWT")
    parser.add_argument('--decode', metavar='TOKEN', help="Decode JWT")
    parser.add_argument('--verify', metavar='TOKEN', help="Verify JWT (HS256 or RS256)")
    parser.add_argument('--brute', metavar='TOKEN', help="Brute force HS256 JWT")
    parser.add_argument('--wordlist', metavar='FILE', help="Wordlist path for brute-force")
    parser.add_argument('--username', default='admin', help="Username")
    parser.add_argument('--role', default='admin', help="Role")
    parser.add_argument('--alg', default='none', help="Algorithm: none, HS256, or RS256")
    parser.add_argument('--secret', default='', help="Secret for HS256")
    parser.add_argument('--private', metavar='FILE', help="Private key file for RS256")
    parser.add_argument('--public', metavar='FILE', help="Public key file for RS256 verification")
    parser.add_argument('--output', metavar='FILE', help="Save the results to a file")

    args = parser.parse_args()

    try:
        if args.generate:
            header = {"alg": args.alg, "typ": "JWT"}
            payload = {"username": args.username, "role": args.role}
            token = create_jwt(header, payload, args.alg, args.secret, args.private)
            print(f"\n📦 Token created:\n{token}")
            if args.output:
                save_output(token, args.output)

        elif args.decode:
            header, payload = decode_jwt(args.decode)
            if header and payload:
                result = f"\n📤 Header:\n{json.dumps(header, indent=2)}\n\n📤 Payload:\n{json.dumps(payload, indent=2)}"
                print(result)
                if args.output:
                    save_output(result, args.output)
            else:
                print("❌ Invalid token format.")

        elif args.verify:
            if args.secret:
                valid = verify_hs256(args.verify, args.secret)
            elif args.public:
                valid = verify_rs256(args.verify, args.public)
            else:
                print("❗ Provide --secret (HS256) or --public (RS256).")
                sys.exit(1)

            print("\n✅ Signature valid." if valid else "\n❌ Signature NOT valid.")

        elif args.brute and args.wordlist:
            brute_force(args.brute, args.wordlist)

        else:
            parser.print_help()

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
