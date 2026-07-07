import http.server
import socketserver
import json
import os
import sys
import importlib.util
import time
import hashlib
import hmac

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# Prevents colorama RecursionError if it gets imported dynamically
import colorama
colorama.init = lambda *args, **kwargs: None
colorama.deinit = lambda *args, **kwargs: None
colorama.reinit = lambda *args, **kwargs: None

# Helper to dynamically import modules
def get_module(name, path):
    abs_path = os.path.abspath(os.path.join(DIRECTORY, path))
    if not os.path.exists(abs_path):
        return None
    spec = importlib.util.spec_from_file_location(name, abs_path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

# Import core modules
caesar = get_module("caesar", "01_classical/caesar_cipher.py")
vigenere = get_module("vigenere", "01_classical/vigenere_cipher.py")
playfair = get_module("playfair", "01_classical/playfair_cipher.py")
aes_demo = get_module("aes_demo", "02_symmetric/aes_demo.py")
des_demo = get_module("des_demo", "02_symmetric/des_demo.py")
rsa_demo = get_module("rsa_demo", "03_asymmetric/rsa_demo.py")
dh_demo = get_module("dh_demo", "03_asymmetric/diffie_hellman.py")
hash_demo = get_module("hash_demo", "04_hashing/hash_demo.py")
hmac_demo = get_module("hmac_demo", "04_hashing/hmac_demo.py")
sign_demo = get_module("sign_demo", "05_digital_signature/dsa_rsa_sign.py")
freq_demo = get_module("freq_demo", "06_attacks/frequency_analysis.py")
birthday = get_module("birthday", "06_attacks/birthday_attack.py")

class CryptoAPIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_POST(self):
        if self.path.startswith("/api/"):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                data = {}

            response_data = handle_api(self.path, data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_error(404, "File not found")

def handle_api(path, data):
        endpoint = path.replace("/api/", "")
        
        try:
            # 1. CAESAR CIPHER
            if endpoint == "caesar":
                action = data.get("action")
                text = data.get("text", "")
                shift = int(data.get("shift", 3))
                
                if action == "encrypt":
                    return {"success": True, "result": caesar.caesar_encrypt(text, shift)}
                elif action == "decrypt":
                    return {"success": True, "result": caesar.caesar_decrypt(text, shift)}
                elif action == "brute_force":
                    bf = caesar.brute_force_attack(text)
                    return {"success": True, "result": [{"key": k, "decrypted": v} for k, v in bf]}

            # 2. VIGENERE CIPHER
            elif endpoint == "vigenere":
                action = data.get("action")
                text = data.get("text", "")
                key = data.get("key", "KEY")
                
                if action == "encrypt":
                    return {"success": True, "result": vigenere.vigenere_encrypt(text, key)}
                elif action == "decrypt":
                    return {"success": True, "result": vigenere.vigenere_decrypt(text, key)}
                elif action == "analyze":
                    ioc = vigenere.index_of_coincidence(text)
                    kasiski_scores = vigenere.kasiski_test(text)
                    return {
                        "success": True, 
                        "ioc": ioc, 
                        "kasiski": [{"key_len": k, "score": v} for k, v in kasiski_scores.items()]
                    }

            # 3. PLAYFAIR CIPHER
            elif endpoint == "playfair":
                action = data.get("action")
                text = data.get("text", "")
                key = data.get("key", "KEY")
                
                if action == "encrypt":
                    return {"success": True, "result": playfair.playfair_encrypt(text, key)}
                elif action == "decrypt":
                    return {"success": True, "result": playfair.playfair_decrypt(text, key)}
                elif action == "matrix":
                    matrix = playfair.build_key_matrix(key)
                    return {"success": True, "matrix": matrix}

            # 4. SYMMETRIC (AES & DES)
            elif endpoint == "symmetric":
                algo = data.get("algo")
                action = data.get("action")
                text = data.get("text", "")
                password = data.get("password", "")
                
                if algo == "aes_cbc":
                    iv_hex = data.get("iv", "000102030405060708090a0b0c0d0e0f")
                    iv = bytes.fromhex(iv_hex)
                    key = aes_demo.derive_key(password)
                    if action == "encrypt":
                        ciphertext = aes_demo.aes_cbc_encrypt(text.encode(), key, iv)
                        return {"success": True, "result": ciphertext.hex(), "key_hex": key.hex()}
                    elif action == "decrypt":
                        ciphertext = bytes.fromhex(text)
                        decrypted = aes_demo.aes_cbc_decrypt(ciphertext, key, iv)
                        return {"success": True, "result": decrypted.decode('utf-8', errors='replace')}
                
                elif algo == "aes_ctr":
                    nonce = int(data.get("nonce", 0))
                    key = aes_demo.derive_key(password)
                    if action == "encrypt":
                        ciphertext = aes_demo.aes_ctr_encrypt(text.encode(), key, nonce)
                        return {"success": True, "result": ciphertext.hex(), "key_hex": key.hex()}
                    elif action == "decrypt":
                        ciphertext = bytes.fromhex(text)
                        decrypted = aes_demo.aes_ctr_decrypt(ciphertext, key, nonce)
                        return {"success": True, "result": decrypted.decode('utf-8', errors='replace')}
                
                elif algo == "des_compare":
                    des_iv = bytes.fromhex(data.get("iv", "0102030405060708"))
                    key_des = des_demo.derive_key(password, 8)
                    key_3des = des_demo.derive_key(password, 24)
                    
                    t0 = time.perf_counter()
                    c_des = des_demo.des_encrypt(text.encode(), key_des, des_iv)
                    t_des = (time.perf_counter() - t0) * 1000
                    
                    t0 = time.perf_counter()
                    c_3des = des_demo.des3_encrypt(text.encode(), key_3des, des_iv)
                    t_3des = (time.perf_counter() - t0) * 1000
                    
                    return {
                        "success": True,
                        "des_key": key_des.hex(),
                        "des_ciphertext": c_des.hex(),
                        "des_time": t_des,
                        "des3_key": key_3des.hex(),
                        "des3_ciphertext": c_3des.hex(),
                        "des3_time": t_3des
                    }

            # 5. ASYMMETRIC (RSA & Diffie-Hellman)
            elif endpoint == "asymmetric":
                algo = data.get("algo")
                action = data.get("action")
                
                if algo == "rsa":
                    if action == "generate":
                        priv, pub = rsa_demo.generate_rsa_keypair(2048)
                        return {
                            "success": True,
                            "private_key": priv.export_key().decode(),
                            "public_key": pub.export_key().decode()
                        }
                    elif action == "encrypt":
                        pub_pem = data.get("public_key")
                        pub_key = rsa_demo.RSA.import_key(pub_pem)
                        text = data.get("text", "")
                        c_bytes = rsa_demo.rsa_encrypt(text.encode(), pub_key)
                        return {"success": True, "result": c_bytes.hex()}
                    elif action == "decrypt":
                        priv_pem = data.get("private_key")
                        priv_key = rsa_demo.RSA.import_key(priv_pem)
                        ciphertext = bytes.fromhex(data.get("text", ""))
                        dec_bytes = rsa_demo.rsa_decrypt(ciphertext, priv_key)
                        return {"success": True, "result": dec_bytes.decode('utf-8', errors='replace')}
                
                elif algo == "dh":
                    dh_type = data.get("dh_type")
                    if dh_type == "small":
                        p = dh_demo.DH_P_SMALL
                        g = dh_demo.DH_G_SMALL
                    else:
                        p = dh_demo.DH_P_2048
                        g = dh_demo.DH_G
                        
                    alice = dh_demo.DHParty("Alice", p, g)
                    bob = dh_demo.DHParty("Bob", p, g)
                    
                    secret_alice = alice.compute_shared_secret(bob.public_key)
                    secret_bob = bob.compute_shared_secret(alice.public_key)
                    aes_key = alice.derive_aes_key()
                    
                    return {
                        "success": True,
                        "p": str(p),
                        "g": g,
                        "alice_priv": str(alice.private_key),
                        "bob_priv": str(bob.private_key),
                        "alice_pub": str(alice.public_key),
                        "bob_pub": str(bob.public_key),
                        "shared_secret": str(secret_alice),
                        "aes_key": aes_key.hex()
                    }

            # 6. HASH & HMAC
            elif endpoint == "hash":
                action = data.get("action")
                
                if action == "hashes":
                    text = data.get("text", "")
                    results = []
                    for name in hash_demo.HASH_ALGORITHMS.keys():
                        h_val = hash_demo.compute_hash(text.encode(), name)
                        results.append({
                            "algo": name,
                            "bits": len(h_val) * 4,
                            "hash": h_val
                        })
                    return {"success": True, "result": results}
                
                elif action == "avalanche":
                    text1 = data.get("text1", "")
                    text2 = data.get("text2", "")
                    h1 = hash_demo.compute_hash(text1.encode(), "SHA-256")
                    h2 = hash_demo.compute_hash(text2.encode(), "SHA-256")
                    diffs = sum(1 for c1, c2 in zip(h1, h2) if c1 != c2)
                    return {
                        "success": True,
                        "hash1": h1,
                        "hash2": h2,
                        "differences": diffs,
                        "percentage": (diffs / len(h1)) * 100
                    }
            
            elif endpoint == "hmac":
                action = data.get("action")
                text = data.get("text", "")
                key = data.get("key", "")
                
                if action == "generate":
                    sig = hmac_demo.compute_hmac(key.encode(), text.encode())
                    return {"success": True, "result": sig}
                elif action == "verify":
                    signature = data.get("signature", "")
                    is_valid = hmac_demo.verify_hmac(key.encode(), text.encode(), signature)
                    return {"success": True, "valid": is_valid}

            # 7. DIGITAL SIGNATURE
            elif endpoint == "signature":
                action = data.get("action")
                algo = data.get("algo")
                
                if action == "generate_keys":
                    if algo == "RSA-PSS":
                        key_obj = sign_demo.rsa_generate_key(2048)
                        return {
                            "success": True,
                            "private_key": key_obj.export_key().decode(),
                            "public_key": key_obj.publickey().export_key().decode()
                        }
                    else:
                        key_obj = sign_demo.dsa_generate_key(2048)
                        return {
                            "success": True,
                            "private_key": key_obj.export_key().decode(),
                            "public_key": key_obj.publickey().export_key().decode()
                        }
                
                elif action == "sign":
                    priv_pem = data.get("private_key")
                    text = data.get("text", "")
                    if algo == "RSA-PSS":
                        priv_key = sign_demo.RSA.import_key(priv_pem)
                        sig = sign_demo.rsa_sign_pss(text.encode(), priv_key)
                    else:
                        priv_key = sign_demo.DSA.import_key(priv_pem)
                        sig = sign_demo.dsa_sign(text.encode(), priv_key)
                    return {"success": True, "result": sig.hex()}
                
                elif action == "verify":
                    pub_pem = data.get("public_key")
                    text = data.get("text", "")
                    signature = bytes.fromhex(data.get("signature", ""))
                    if algo == "RSA-PSS":
                        pub_key = sign_demo.RSA.import_key(pub_pem)
                        is_ok = sign_demo.rsa_verify_pss(text.encode(), signature, pub_key)
                    else:
                        pub_key = sign_demo.DSA.import_key(pub_pem)
                        is_ok = sign_demo.dsa_verify(text.encode(), signature, pub_key)
                    return {"success": True, "valid": is_ok}

            # 8. ATTACKS
            elif endpoint == "attacks":
                attack = data.get("attack")
                
                if attack == "frequency":
                    text = data.get("text", "")
                    freq = freq_demo.count_frequency(text)
                    best_k, best_plain, best_score = freq_demo.frequency_attack_caesar(text)
                    
                    letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                    freq_list = [{"letter": l, "ciphertext": freq.get(l, 0.0) * 100, "english": freq_demo.ENGLISH_FREQ.get(l, 0.0) * 100} for l in letters]
                    
                    return {
                        "success": True,
                        "frequencies": freq_list,
                        "best_key": best_k,
                        "best_plaintext": best_plain,
                        "best_score": best_score
                    }
                
                elif attack == "birthday_calc":
                    people = int(data.get("people", 23))
                    prob = birthday.birthday_probability(people) * 100
                    return {"success": True, "probability": prob}
                
                elif attack == "birthday_collision":
                    bits = int(data.get("bits", 12))
                    expected = birthday.birthday_expected_collisions(bits)
                    res = birthday.find_collision_short_hash(bits)
                    return {
                        "success": True,
                        "expected": expected,
                        "found": res["found"],
                        "attempts": res["attempts"],
                        "hash": res["hash"],
                        "input1": res["input1"].hex() if res["found"] else "",
                        "input2": res["input2"].hex() if res["found"] else ""
                    }
            
            return {"success": False, "error": f"Unknown endpoint: {endpoint}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

def wsgi_app(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    
    if method == 'GET':
        if path == '/' or path == '/index.html':
            filepath = os.path.join(DIRECTORY, 'index.html')
            content_type = 'text/html; charset=utf-8'
        elif path == '/style.css':
            filepath = os.path.join(DIRECTORY, 'style.css')
            content_type = 'text/css; charset=utf-8'
        elif path == '/app.js':
            filepath = os.path.join(DIRECTORY, 'app.js')
            content_type = 'application/javascript; charset=utf-8'
        else:
            rel_path = path.lstrip('/')
            filepath = os.path.join(DIRECTORY, rel_path)
            if os.path.isfile(filepath) and not rel_path.startswith('.'):
                if filepath.endswith('.html'):
                    content_type = 'text/html; charset=utf-8'
                elif filepath.endswith('.css'):
                    content_type = 'text/css; charset=utf-8'
                elif filepath.endswith('.js'):
                    content_type = 'application/javascript; charset=utf-8'
                elif filepath.endswith('.png'):
                    content_type = 'image/png'
                elif filepath.endswith('.webp'):
                    content_type = 'image/webp'
                elif filepath.endswith('.ico'):
                    content_type = 'image/x-icon'
                else:
                    content_type = 'application/octet-stream'
            else:
                start_response('404 Not Found', [('Content-Type', 'text/plain')])
                return [b'404 Not Found']

        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            start_response('200 OK', [
                ('Content-Type', content_type),
                ('Content-Length', str(len(content))),
                ('Access-Control-Allow-Origin', '*')
            ])
            return [content]
        except Exception as e:
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            return [f"500 Internal Server Error: {str(e)}".encode('utf-8')]
            
    elif method == 'POST' and path.startswith('/api/'):
        try:
            content_length = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            content_length = 0
            
        post_data = environ['wsgi.input'].read(content_length)
        try:
            data = json.loads(post_data.decode('utf-8'))
        except Exception:
            data = {}
            
        response_data = handle_api(path, data)
        response_bytes = json.dumps(response_data).encode('utf-8')
        
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(response_bytes))),
            ('Access-Control-Allow-Origin', '*')
        ])
        return [response_bytes]
        
    elif method == 'OPTIONS':
        start_response('204 No Content', [
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Content-Type'),
        ])
        return [b'']
        
    else:
        start_response('405 Method Not Allowed', [('Content-Type', 'text/plain')])
        return [b'405 Method Not Allowed']

app = wsgi_app
application = wsgi_app
handler = wsgi_app

if __name__ == "__main__":
    # Standard static files server with Custom API handler
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), CryptoAPIHandler) as httpd:
        print(f"Server berjalan pada http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer dihentikan.")
