import json
import os
import subprocess
from flask import Flask, request, jsonify
import logging


import os, json

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
config_path = os.path.join(project_root, 'config', 'config.json')
with open(config_path) as f:
    config = json.load(f)

SOAR_API_KEY = config.get("soar_api_key", "test_soar_api_key")
SOAR_API_PORT = config.get("soar_api_port", 7000)
SOAR_API_HOST = config.get("soar_api_host", "0.0.0.0")


app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# -------- ACTION HANDLERS ---------

def disconnect_network():
    try:
        # Requires root/sudo privileges
        # Use "nmcli networking off" for NetworkManager, "ifconfig" for manual
        result = subprocess.run(["nmcli", "networking", "off"], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Network disconnected.")
            return True, "Network disconnected"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

def block_port(port):
    try:
        port = int(port)
        # Requires sudo/root!
        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logging.info(f"Port {port} blocked.")
            return True, f"Port {port} blocked"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

def kill_process(pid):
    try:
        pid = int(pid)
        os.kill(pid, 9)
        logging.info(f"Process {pid} killed.")
        return True, f"Process {pid} killed"
    except Exception as e:
        return False, str(e)

def disable_user(username):
    try:
        # Locks the user account
        result = subprocess.run(
            ["sudo", "usermod", "--expiredate", "1", username],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logging.info(f"User {username} disabled.")
            return True, f"User {username} disabled"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

ACTION_HANDLERS = {
    "disconnect_network": lambda params: disconnect_network(),
    "block_port": lambda params: block_port(params.get("port")),
    "kill_process": lambda params: kill_process(params.get("pid")),
    "disable_user": lambda params: disable_user(params.get("username"))
}

# ---------- SOAR API Endpoint ----------

@app.route('/api/soar/action', methods=['POST'])
def soar_action():
    # API Key Auth (Bearer)
    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {SOAR_API_KEY}":
        logging.warning("Unauthorized SOAR request")
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json(force=True)
    action = data.get("action")
    params = data.get("params", {})

    handler = ACTION_HANDLERS.get(action)
    if not handler:
        logging.warning(f"Unsupported action: {action}")
        return jsonify({
            "status": "error",
            "message": f"Unsupported action: {action}"
        }), 400

    success, message = handler(params)
    status = "success" if success else "error"
    logging.info(f"SOAR action '{action}' executed: {message}")

    return jsonify({
        "status": status,
        "action": action,
        "params": params,
        "message": message
    }), 200 if success else 500

if __name__ == '__main__':
    app.run(host=SOAR_API_HOST, port=SOAR_API_PORT)
