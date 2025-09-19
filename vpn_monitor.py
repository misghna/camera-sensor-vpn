#!/usr/bin/env python3

import os
import subprocess
import urllib.parse
import base64
import json
import logging
import time
import socket
import binascii
import sys
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from vpn_http_root_configurer import handle_device_request

# Import the TS-7 serial function
from ts_test_tcp_t4d_protocol import get_ts7_serial

# Key for decryption
KEY_STRING = 'Vj9bh768KdajsdBSK0J'

# Dynamically fetch public IP
EC2_PUBLIC_IP = subprocess.check_output(["curl", "-s", "ifconfig.me"]).decode().strip()

# WireGuard settings
WIREGUARD_DIR = "/etc/wireguard"
SERVER_PUBLIC_KEY_FILE = os.path.join(WIREGUARD_DIR, "server_public.key")

# Client list file
CLIENT_LIST_FILE = os.path.join(WIREGUARD_DIR, "client_list.json")
MAX_CLIENTS = 252

# Configure logging to stdout
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')


def add_or_update_wireguard_peer(client_name, client_public_key, client_ip):
    try:
        if_exists = subprocess.run(['ip', 'link', 'show', 'wg0'],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0
        if not if_exists:
            logging.warning("WireGuard interface wg0 not running, updating config file only")

        server_config_file = os.path.join(WIREGUARD_DIR, "wg0.conf")
        if not os.path.exists(server_config_file):
            return f"Error: Server config file {server_config_file} not found"

        with open(server_config_file, 'r') as f:
            config_content = f.read()

        if client_public_key in config_content:
            lines = config_content.splitlines()
            in_peer = False
            match_peer = False
            for i, line in enumerate(lines):
                if line.strip() == "[Peer]":
                    in_peer = True
                    match_peer = False
                    continue

                if in_peer and line.strip().startswith("PublicKey"):
                    if client_public_key in line:
                        match_peer = True
                    else:
                        in_peer = False

                if match_peer and line.strip().startswith("AllowedIPs"):
                    expected = f"AllowedIPs = {client_ip}/32"
                    if line.strip() != expected:
                        lines[i] = expected
                        with open(server_config_file, 'w') as f:
                            f.write('\n'.join(lines))
                        if if_exists:
                            subprocess.run([
                                'wg', 'set', 'wg0', 'peer', client_public_key,
                                'allowed-ips', f'{client_ip}/32'
                            ], check=True)
                        return f"Updated AllowedIPs for {client_name}"
                    return f"Peer {client_name} already correct"
            return f"Peer section found but AllowedIPs missing"

        # Add new peer
        if not config_content.endswith('\n'):
            config_content += '\n'
        peer_section = f"""
# Client: {client_name}
[Peer]
PublicKey = {client_public_key}
AllowedIPs = {client_ip}/32
"""
        with open(server_config_file, 'w') as f:
            f.write(config_content + peer_section)

        if if_exists:
            subprocess.run([
                'wg', 'set', 'wg0', 'peer', client_public_key,
                'allowed-ips', f'{client_ip}/32'
            ], check=True)

        return f"Added new peer {client_name}"
    except Exception as e:
        return f"WireGuard error: {e}"


def get_client_id(client_name):
    if not os.path.exists(CLIENT_LIST_FILE):
        with open(CLIENT_LIST_FILE, 'w') as f:
            json.dump([], f)

    with open(CLIENT_LIST_FILE, 'r') as f:
        lst = json.load(f)

    if client_name in lst:
        return (lst.index(client_name) + 2, False)
    if len(lst) >= MAX_CLIENTS:
        raise ValueError("Max clients reached")

    lst.append(client_name)
    client_id = len(lst) + 1
    with open(CLIENT_LIST_FILE, 'w') as f:
        json.dump(lst, f, indent=2)
    return (client_id, True)


def get_server_public_key():
    try:
        if os.path.exists(SERVER_PUBLIC_KEY_FILE):
            with open(SERVER_PUBLIC_KEY_FILE, 'r') as f:
                return f.read().strip()
        return None
    except Exception as e:
        logging.error(f"Reading server public key failed: {e}")
        return None


def generate_client_keys(client_name):
    priv_file = os.path.join(WIREGUARD_DIR, f"{client_name}_private.key")
    pub_file = os.path.join(WIREGUARD_DIR, f"{client_name}_public.key")
    if os.path.exists(priv_file) and os.path.exists(pub_file):
        with open(priv_file, 'r') as f:
            priv = f.read().strip()
        with open(pub_file, 'r') as f:
            pub = f.read().strip()
        return (priv, pub)
    try:
        res = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
        priv = res.stdout.strip()
        with open(priv_file, 'w') as f:
            f.write(priv)
        os.chmod(priv_file, 0o600)
        res = subprocess.run(['wg', 'pubkey'], input=priv, capture_output=True, text=True, check=True)
        pub = res.stdout.strip()
        with open(pub_file, 'w') as f:
            f.write(pub)
        return (priv, pub)
    except Exception as e:
        logging.error(f"Key gen failed: {e}")
        return (None, None)


def get_key_from_string(key_str):
    if len(key_str) < 16:
        key_str = key_str.ljust(16, 'x')
    else:
        key_str = key_str[:16]
    return key_str.encode('utf-8')


def decrypt(encrypted, key_str):
    try:
        key = get_key_from_string(key_str)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        enc_bytes = base64.b64decode(encrypted)
        dec_bytes = decryptor.update(enc_bytes) + decryptor.finalize()
        return dec_bytes.decode('utf-8').strip()
    except Exception as e:
        logging.warning(f"Decrypt error ({e}), treating as cleartext")
        return encrypted


def create_nginx_configs(subdomain, client_ip, stream_port=8000, http_port=9000, base_domain="hydro2geotech.net"):
    results = []
    cid = int(client_ip.split('.')[-1])
    cp = 8000 + cid

    # Stream configuration (keeping this)
    s_avail = "/etc/nginx/streams-available"
    s_en = "/etc/nginx/streams-enabled"
    os.makedirs(s_avail, exist_ok=True)
    os.makedirs(s_en, exist_ok=True)
    stream_file = os.path.join(s_avail, f"{subdomain}.conf")
    if not os.path.exists(stream_file):
        cfg = f"""server {{
    listen {cp};
    proxy_pass {client_ip}:8000;
}}
"""
        with open(stream_file, "w") as f:
            f.write(cfg)
        results.append(f"Created stream config: {stream_file}")
    else:
        results.append(f"Stream exists: {stream_file}")

    link = os.path.join(s_en, f"{subdomain}.conf")
    if not os.path.exists(link):
        os.symlink(stream_file, link)
        results.append(f"Enabled stream: {link}")
    else:
        results.append(f"Stream link exists: {link}")

    return "\n".join(results)


def validate_and_reload_nginx():
    out = "Validating nginx...\n"
    test = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if test.returncode == 0:
        out += "Valid. Reloading...\n"
        reload = subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True, text=True)
        if reload.returncode == 0:
            out += "Reloaded successfully."
        else:
            out += f"Reload error: {reload.stderr}"
    else:
        out += f"Invalid config: {test.stderr}"
    return out


class NginxConfigHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to send to our logger instead of stderr
        logging.info("%s - - [%s] %s\n" %
                     (self.address_string(),
                      self.log_date_time_string(),
                      format % args))

    def do_GET(self):
        if self.path.startswith("/test"):
            self.handle_test_request()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def get_real_client_ip(self):
        """Get the real client IP, checking proxy headers if needed"""
        # Check common proxy headers first
        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()

        real_ip = self.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()

        # Fall back to direct connection IP
        return self.client_address[0]

    def handle_test_request(self):
        """Handle /test endpoint to get TS-7 serial number from requesting client"""
        client_ip = self.get_real_client_ip()

        # Restrict access to /test endpoint - only allow 10.0.x.x clients
        if not client_ip.startswith("10.0."):
            logging.warning(f"=== 401 UNAUTHORIZED: /test access denied for {client_ip} ===")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            error_response = {
                "status": "unauthorized",
                "error": "Access to /test endpoint is restricted to 10.0.x.x network",
                "client_ip": client_ip,
                "timestamp": str(time.time())
            }
            self.wfile.write(json.dumps(error_response, indent=2).encode())
            return

        # Parse query parameters for port (default 8006) and host override
        url_parts = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url_parts.query)
        port = int(query.get('port', ['8006'])[0])
        host = query.get('host', [client_ip])[0]  # Default to client_ip if no host override

        logging.info(f"=== /test request from {client_ip} targeting {host}:{port} ===")

        try:
            # Call the TS-7 serial function with specified host and port
            serial = get_ts7_serial(host, port, enable_logging=False)

            if serial != "0":
                logging.info(f"SUCCESS: Got TS-7 serial {serial} from {host}:{port} (requested by {client_ip})")
                response = {
                    "status": "success",
                    "serial": serial,
                    "client_ip": client_ip,
                    "target_host": host,
                    "port": port,
                    "timestamp": str(time.time())
                }
            else:
                logging.warning(f"FAILED: Could not get TS-7 serial from {host}:{port} (requested by {client_ip})")
                response = {
                    "status": "failed",
                    "serial": "0",
                    "client_ip": client_ip,
                    "target_host": host,
                    "port": port,
                    "error": "Could not retrieve serial number",
                    "timestamp": str(time.time())
                }

        except Exception as e:
            logging.error(f"ERROR: Exception getting TS-7 serial from {host}:{port} (requested by {client_ip}): {e}")
            response = {
                "status": "error",
                "serial": "0",
                "client_ip": client_ip,
                "target_host": host,
                "port": port,
                "error": str(e),
                "timestamp": str(time.time())
            }

        # Send JSON response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        if self.path.startswith("/test"):
            self.handle_test_request()
            return

        logging.info(f"Incoming POST {self.path}")
        logging.debug(f"Headers: {dict(self.headers)}")

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='ignore')
        logging.debug(f"Raw body: '{body}'")

        params = urllib.parse.parse_qs(body)
        logging.debug(f"Form params: {params}")

        url_parts = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url_parts.query)
        logging.debug(f"Query params: {query}")

        # Default values
        encrypted_key = params.get('key', [''])[0] or query.get('key', [''])[0]
        name = params.get('name', [''])[0] or query.get('name', [''])[0]
        port = params.get('port', ['8000'])[0] or query.get('port', ['8000'])[0]
        logging.debug(f"Extracted key='{encrypted_key}', name='{name}', port='{port}'")

        # If still missing key, try JSON
        if not encrypted_key:
            try:
                data_json = json.loads(body)
                encrypted_key = data_json.get('key', encrypted_key)
                name = data_json.get('name', name)
                port = data_json.get('port', port)
                logging.debug(f"From JSON: key='{encrypted_key}', name='{name}', port='{port}'")
            except Exception as e:
                logging.debug(f"JSON parse failed: {e}")

        if not encrypted_key:
            logging.warning("=== 401 UNAUTHORIZED: Missing Key ===")
            logging.warning(f"Request path: {self.path}")
            logging.warning(f"Request headers: {dict(self.headers)}")
            logging.warning(f"Raw body content: '{body}'")
            logging.warning(f"Parsed form params: {params}")
            logging.warning(f"Parsed query params: {query}")
            logging.warning("No 'key' parameter found in form data, query params, or JSON body")
            logging.warning("=== End 401 Details ===")
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        server_pub = get_server_public_key()
        logging.debug(f"Server public key: '{server_pub}'")

        if not name:
            logging.error("Missing 'name' parameter")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Missing 'name'")
            return

        decrypted = decrypt(encrypted_key, KEY_STRING)
        logging.debug(f"Decrypted key='{decrypted}'")

        if decrypted != name:
            logging.warning("=== 401 UNAUTHORIZED: Key Mismatch ===")
            logging.warning(f"Request path: {self.path}")
            logging.warning(f"Client IP: {self.client_address[0]}")
            logging.warning(f"Request headers: {dict(self.headers)}")
            logging.warning(f"Raw encrypted key received: '{encrypted_key}'")
            logging.warning(f"Expected name parameter: '{name}'")
            logging.warning(f"Decrypted key result: '{decrypted}'")
            logging.warning(f"Decryption key used: '{KEY_STRING}'")
            logging.warning(f"Key lengths - encrypted: {len(encrypted_key)}, decrypted: {len(decrypted)}, name: {len(name)}")
            logging.warning(f"Key comparison: decrypted==name -> {decrypted == name}")
            if decrypted and name:
                logging.warning(f"Character-by-character comparison:")
                for i, (c1, c2) in enumerate(zip(decrypted, name)):
                    if c1 != c2:
                        logging.warning(f"  Position {i}: decrypted='{c1}' (ord={ord(c1)}) vs name='{c2}' (ord={ord(c2)})")
                        break
            logging.warning("=== End 401 Details ===")
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        try:
            client_id, is_new = get_client_id(name)
            logging.info(f"Client '{name}' → ID {client_id} (new={is_new})")
        except ValueError as e:
            logging.error(f"Client list error: {e}")
            resp = {"nginx_config": "NA", "sub_domain_config": "NA",
                    "sKey": "NA", "client_ip": "NA",
                    "port": "NA", "device_host_name": "NA",
                    "wireguard_config": "NA"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return

        try:
            port_int = int(port)
        except ValueError:
            logging.error(f"Invalid port '{port}'")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid port")
            return

        client_ip = f"10.0.0.{client_id}"
        client_port = 8000 + client_id
        logging.info(f"Assigning IP={client_ip}, port={client_port}")

        # Skip DNS part
        dns_ok = True
        full_domain = f"{name}.hydro2geotech.net"
        logging.debug(f"Full domain: {full_domain}")

        nginx_res = create_nginx_configs(name, client_ip, stream_port=port_int, http_port=9000)
        logging.info(f"NGINX config result:\n{nginx_res}")

        priv_key, pub_key = generate_client_keys(name)
        logging.debug(f"Client keys: priv={priv_key}, pub={pub_key}")

        wg_ok = False
        if pub_key and dns_ok:
            wg_res = add_or_update_wireguard_peer(name, pub_key, client_ip)
            logging.info(f"WireGuard update: {wg_res}")
            wg_ok = "Error" not in wg_res
        else:
            logging.warning("Skipping WireGuard config (no pub_key or DNS fail)")

        validate_res = validate_and_reload_nginx()
        logging.info(f"Nginx reload:\n{validate_res}")

        response = {
            "nginx_config": "ok",
            "sub_domain_config": "ok" if dns_ok else "fail",
            "sKey": server_pub or "NA",
            "client_ip": client_ip,
            "port": str(client_port),
            "device_host_name": full_domain,
            "wireguard_config": "ok" if wg_ok else "fail"
        }
        if priv_key:
            response["cKey"] = priv_key

        # configure 9000 listners
        if wg_ok:
            # Update nginx vpn-root config
            nginx_update_result = handle_device_request({
                "name": name,
                "port": str(client_port),  # This is 8000 + client_id
                "key": encrypted_key
            })
            logging.info(f"Nginx vpn-root update: {nginx_update_result}")

        logging.debug(f"Returning JSON: {response}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


def run(server_class=HTTPServer, handler_class=NginxConfigHandler):
    logging.info("Starting server on port 8080")
    server = server_class(('', 8080), handler_class)
    server.serve_forever()


if __name__ == '__main__':
    run()
