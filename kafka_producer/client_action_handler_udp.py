import json
import os
import subprocess
import socket
import logging
from datetime import datetime, timezone

# ================= CONFIG =================
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

# UDP ports
CLIENT_UDP_PORT = 6008                         # listen here for commands from server
SERVER_ACK_IP = config["udp"]["server_ip"]     # server IP from config
SERVER_ACK_PORT = 6010                         # server ack listener port

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT_ACTION_HANDLER] %(levelname)s: %(message)s"
)

# ================= ACTION HANDLERS =================
def disconnect_network(_=None):
    try:
        result = subprocess.run(["nmcli", "networking", "off"], capture_output=True, text=True)
        if result.returncode == 0:
            return True, "Network disconnected"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

def block_port(port):
    try:
        port = int(port)
        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return True, f"Port {port} blocked"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

def kill_process(pid):
    try:
        pid = int(pid)
        os.kill(pid, 9)
        return True, f"Process {pid} killed"
    except Exception as e:
        return False, str(e)

def disable_user(username):
    try:
        result = subprocess.run(
            ["sudo", "usermod", "--expiredate", "1", username],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return True, f"User {username} disabled"
        else:
            return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)

ACTION_HANDLERS = {
    "disconnect_network": lambda attr: disconnect_network(),
    "block_port": lambda attr: block_port(attr),
    "kill_process": lambda attr: kill_process(attr),
    "disable_user": lambda attr: disable_user(attr),
}

# ================= ACK SENDER (STRUCT_SOAR_ACK) =================
def send_ack(incident_id, action_name, success, message):
    ack_msg = {
        "msgId": config["msg_id"]["UEBA_SOAR_ACTION_ACK_MSG"],
        "incidentId": incident_id,
        "action": action_name,
        "actionStatus": "SUCCESS" if success else "FAILED",
        # "acknowledgementTimestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        "acknowledgementTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "communicationLog": message
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(ack_msg).encode(), (SERVER_ACK_IP, SERVER_ACK_PORT))
        sock.close()
        logging.info(f"Sent ACK to server {SERVER_ACK_IP}:{SERVER_ACK_PORT} -> {ack_msg}")
    except Exception as e:
        logging.error(f"Failed to send ACK: {e}")

# ================= UDP LISTENER =================
def listen_for_actions():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", CLIENT_UDP_PORT))
    logging.info(f"Client listening for actions on UDP port {CLIENT_UDP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            action_msg = json.loads(data.decode())
            logging.info(f"Received action from server {addr}: {action_msg}")

            action_name = action_msg.get("action_name")
            action_attributes = action_msg.get("action_attributes")
            incident_id = action_msg.get("incident_id")

            handler = ACTION_HANDLERS.get(action_name)
            if not handler:
                logging.warning(f"Unsupported action: {action_name}")
                send_ack(incident_id, action_name, False, f"Unsupported action: {action_name}")
                continue

            success, result_msg = handler(action_attributes)
            logging.info(f"Executed {action_name}: {'success' if success else 'error'} - {result_msg}")
            send_ack(incident_id, action_name, success, result_msg)

        except Exception as e:
            logging.error(f"Error handling incoming action: {e}")

if __name__ == "__main__":
    listen_for_actions()
