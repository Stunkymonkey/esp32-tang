#!/usr/bin/env python3
import requests
import json
import base64
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import argparse

# Configuration
ESP_IP = "" # Will be set via arguments

def parse_args():
    global ESP_IP
    parser = argparse.ArgumentParser(description='Verify ESP32 Tang Server')
    parser.add_argument('url', help='Base URL of the ESP32 Tang server (e.g., http://192.168.4.1)')
    args = parser.parse_args()
    
    ESP_IP = args.url.rstrip('/')
    if not ESP_IP.startswith("http"):
         ESP_IP = "http://" + ESP_IP

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def generate_key(ops, curve_name="P-256"):
    if curve_name == "P-521":
        private_key = ec.generate_private_key(ec.SECP521R1())
        coord_len = 66
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        coord_len = 32
        
    numbers = private_key.private_numbers()
    
    # Export raw bytes
    d = numbers.private_value.to_bytes(coord_len, 'big')
    x = numbers.public_numbers.x.to_bytes(coord_len, 'big')
    y = numbers.public_numbers.y.to_bytes(coord_len, 'big')
    
    kid = base64url_encode(x[:8]) # Simple KID derived from X
    
    print(f"Generated key for {ops} ({curve_name}): {kid}")
    
    return {
        "kid": kid,
        "key_ops": ops,
        "kty": "EC",
        "crv": curve_name,
        "d": base64url_encode(d),
        "x": base64url_encode(x),
        "y": base64url_encode(y),
        "_priv": private_key,
        "_pub": private_key.public_key()
    }

def provision(sign_key, exch_key):
    print(f"\n[1] Provisioning keys to {ESP_IP}...")
    payload = {
        "keys": [
            {k: v for k, v in sign_key.items() if not k.startswith('_')},
            {k: v for k, v in exch_key.items() if not k.startswith('_')}
        ]
    }
    
    try:
        r = requests.post(f"{ESP_IP}/provision", json=payload, timeout=5)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text}")
        if r.status_code != 200:
            sys.exit(1)
    except Exception as e:
        print(f"Failed to connect: {e}")
        sys.exit(1)

def verify_advertisement(sign_key):
    print(f"\n[2] Fetching advertisement from {ESP_IP}/adv...")
    try:
        r = requests.get(f"{ESP_IP}/adv", timeout=5)
        if r.status_code != 200:
            print(f"Error: {r.status_code} - {r.text}")
            sys.exit(1)
            
        jws = r.text
        print(f"Received JWS: {jws[:50]}...")
        
        try:
            # Try parsing as JWS JSON Serialization
            jws_json = r.json()
            header = jws_json['protected']
            payload = jws_json['payload']
            signature_b64 = jws_json['signature']
            signature = base64url_decode(signature_b64)
            print("Parsed JWS JSON Serialization.")
        except:
             # Fallback to Compact Serialization (header.payload.signature)
             print("Falling back to Compact Serialization parsing...")
             parts = jws.split('.')
             if len(parts) != 3:
                 print("Invalid JWS format")
                 sys.exit(1)
             header = parts[0]
             payload = parts[1]
             signature = base64url_decode(parts[2])
        
        signing_input =f"{header}.{payload}".encode('utf-8')
        
        # Verify signature
        try:
            # Determine curve/signature size based on key
            curve_name = sign_key.get("crv", "P-256")
            if curve_name == "P-521":
                coord_len = 66
                hash_alg = hashes.SHA512()
            else:
                coord_len = 32
                hash_alg = hashes.SHA256()
            
            r_int = int.from_bytes(signature[:coord_len], 'big')
            s_int = int.from_bytes(signature[coord_len:], 'big')
            der_sig = encode_dss_signature(r_int, s_int)
            
            sign_key['_pub'].verify(
                 der_sig,
                 signing_input,
                 ec.ECDSA(hash_alg)
            )

            print("Signature VERIFIED!")
        except Exception as e:
            print(f"Signature Verification FAILED: {e}")
            sys.exit(1)
            
        print("Advertisement Payload:")
        print(json.dumps(json.loads(base64url_decode(payload)), indent=2))
        
    except Exception as e:
        print(f"Failed: {e}")
        sys.exit(1)

def perform_exchange(exch_key):
    print(f"\n[3] Performing Exchange on {ESP_IP}/rec/{exch_key['kid']}...")
    
    curve_name = exch_key.get("crv", "P-256")
    if curve_name == "P-521":
        cli_priv = ec.generate_private_key(ec.SECP521R1())
        coord_len = 66
    else:
        cli_priv = ec.generate_private_key(ec.SECP256R1())
        coord_len = 32

    cli_nums = cli_priv.public_key().public_numbers()
    cli_x = cli_nums.x.to_bytes(coord_len, 'big')
    cli_y = cli_nums.y.to_bytes(coord_len, 'big')
    
    payload = {
        "kty": "EC",
        "crv": curve_name,
        "x": base64url_encode(cli_x),
        "y": base64url_encode(cli_y)
    }
    
    try:
        r = requests.post(f"{ESP_IP}/rec/{exch_key['kid']}", json=payload, timeout=5)
        if r.status_code != 200:
            print(f"Exchange failed: {r.status_code} - {r.text}")
            sys.exit(1)
            
        resp = r.json()
        print("Received Server Share:", resp)
        
        # Verify Shared Secret
        srv_x = base64url_decode(resp['x'])
        
        # Calculate expected shared secret locally: ClientPriv * ServerPub
        shared_key = cli_priv.exchange(ec.ECDH(), exch_key['_pub'])
        
        if srv_x == shared_key:
            print("Shared Secret VALIDATED! (X coordinate matches)")
        else:
            # Handle potential padding mismatch
            expected_len = len(shared_key)
            # Pad server X if it came back short (mbedTLS might strip leading zeros)
            srv_x_padded = srv_x.rjust(expected_len, b'\x00')
            
            if srv_x_padded == shared_key:
                 print("Shared Secret VALIDATED! (X coordinate matches after padding fix)")
            else:
                 print(f"Shared Secret MISMATCH!\nExpected: {shared_key.hex()}\nGot:      {srv_x.hex()}")
            
    except Exception as e:
        print(f"Failed: {e}")

def deactivate():
    print(f"\n[4] Deactivating/Reseting Server {ESP_IP}/deactivate...")
    try:
        r = requests.post(f"{ESP_IP}/deactivate", timeout=5)
        if r.status_code == 200:
             print("Server deactivated successfully.")
        else:
             print(f"Deactivation failed: {r.status_code}")
             # If deactivate fails, we can't proceed to next test safely usually
    except Exception as e:
        print(f"Deactivation request failed: {e}")

def run_test_suite(curve_name):
    print(f"\n{'='*20} Testing Curve: {curve_name} {'='*20}")
    
    print("Generating Keys...")
    sign_key = generate_key(["sign", "verify"], curve_name)
    exch_key = generate_key(["deriveKey"], curve_name)

    provision(sign_key, exch_key)
    verify_advertisement(sign_key)
    perform_exchange(exch_key)
    print(f"{'='*20} {curve_name} Test Complete {'='*20}\n")

if __name__ == "__main__":
    parse_args()
    print(f"Targeting: {ESP_IP}")
    
    # Ensure fresh state
    deactivate()
    
    # Run P-256 Test
    run_test_suite("P-256")
    
    # Deactivate (clear keys)
    deactivate()
    
    # Run P-521 Test
    run_test_suite("P-521")
