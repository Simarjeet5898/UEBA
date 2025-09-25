# import json
# import os
# import subprocess
# import logging
# import pika

# CONFIG_PATH = "/home/config.json"
# with open(CONFIG_PATH) as f:
#     config = json.load(f)

# rabbit_cfg = config["rabbitmq"]["soar"]
# queue_cfg = config["soar_queue"]
# QUEUE_NAME = queue_cfg.get("queue_name", "SOAR_UEBA_ACTION_FOR_ANOMALY")

# logging.basicConfig(level=logging.INFO)


# # -------- ACTION HANDLERS ---------

# def disconnect_network():
#     try:
#         # Requires root/sudo privileges
#         # Use "nmcli networking off" for NetworkManager, "ifconfig" for manual
#         result = subprocess.run(["nmcli", "networking", "off"], capture_output=True, text=True)
#         if result.returncode == 0:
#             logging.info("Network disconnected.")
#             return True, "Network disconnected"
#         else:
#             return False, result.stderr.strip()
#     except Exception as e:
#         return False, str(e)

# def block_port(port):
#     try:
#         port = int(port)
#         # Requires sudo/root!
#         result = subprocess.run(
#             ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
#             capture_output=True, text=True
#         )
#         if result.returncode == 0:
#             logging.info(f"Port {port} blocked.")
#             return True, f"Port {port} blocked"
#         else:
#             return False, result.stderr.strip()
#     except Exception as e:
#         return False, str(e)

# def kill_process(pid):
#     try:
#         pid = int(pid)
#         os.kill(pid, 9)
#         logging.info(f"Process {pid} killed.")
#         return True, f"Process {pid} killed"
#     except Exception as e:
#         return False, str(e)

# def disable_user(username):
#     try:
#         # Locks the user account
#         result = subprocess.run(
#             ["sudo", "usermod", "--expiredate", "1", username],
#             capture_output=True, text=True
#         )
#         if result.returncode == 0:
#             logging.info(f"User {username} disabled.")
#             return True, f"User {username} disabled"
#         else:
#             return False, result.stderr.strip()
#     except Exception as e:
#         return False, str(e)

# ACTION_HANDLERS = {
#     "disconnect_network": lambda params: disconnect_network(),
#     "block_port": lambda params: block_port(params.get("port")),
#     "kill_process": lambda params: kill_process(params.get("pid")),
#     "disable_user": lambda params: disable_user(params.get("username"))
# }

# # -------- RabbitMQ Message Processor --------
# def process_message(ch, method, properties, body):
#     try:
#         data = json.loads(body)
#         action = data.get("action")
#         params = data.get("params", {})

#         logging.info(f"Received SOAR action: {action}, params={params}")

#         handler = ACTION_HANDLERS.get(action)
#         if not handler:
#             logging.warning(f"Unsupported action: {action}")
#             ch.basic_ack(delivery_tag=method.delivery_tag)
#             return

#         success, message = handler(params)
#         status = "success" if success else "error"

#         logging.info(f"SOAR action '{action}' executed: {status} - {message}")

#         # ack to RabbitMQ
#         ch.basic_ack(delivery_tag=method.delivery_tag)

#     except Exception as e:
#         logging.error(f"Error handling SOAR message: {e}")
#         ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

# def main():
#     connection = pika.BlockingConnection(
#         pika.ConnectionParameters(
#             host=rabbit_cfg["host"],
#             port=rabbit_cfg["port"],
#             virtual_host=rabbit_cfg.get("virtual_host", "/"),
#             credentials=pika.PlainCredentials(
#                 rabbit_cfg.get("username", "guest"),
#                 rabbit_cfg.get("password", "guest")
#             )
#         )
#     )
#     channel = connection.channel()
#     channel.queue_declare(queue=QUEUE_NAME, durable=True)

#     logging.info(f"Listening for SOAR actions on queue: {QUEUE_NAME}")

#     channel.basic_consume(queue=QUEUE_NAME, on_message_callback=process_message, auto_ack=False)
#     channel.start_consuming()

# if __name__ == "__main__":
#     main()

################ IN THE ABOVE CODE THE SERVER TAKES THE ACTION ###################3
import json
import logging
import pika
import socket
import threading

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

# RabbitMQ config
rabbit_cfg = config["rabbitmq"]["soar"]
queue_cfg = config["soar_queue"]
SOAR_TO_UEBA_QUEUE = queue_cfg.get("queue_name", "SOAR_UEBA_ACTION_FOR_ANOMALY")

queue_map = config.get("queue_name", {})
ACK_QUEUE = queue_map.get(str(config["msg_id"]["UEBA_SOAR_ACTION_ACK_MSG"]))

# UDP ports
CLIENT_UDP_PORT = 6008  # clients listen here
SERVER_ACK_PORT = 6010  # server listens for client ACKs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SOAR_CONNECTOR] %(levelname)s: %(message)s"
)

# Global RabbitMQ channel (for publishing ACKs)
connection = None
channel = None


# -------- Forward action to client --------
def forward_to_client(target_ip, action_msg):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(action_msg).encode(), (target_ip, CLIENT_UDP_PORT))
        logging.info(f"Forwarded action to client {target_ip}:{CLIENT_UDP_PORT} -> {action_msg}")
        sock.close()
        return True
    except Exception as e:
        logging.error(f"Failed to forward to client {target_ip}: {e}")
        return False


# -------- RabbitMQ Message Processor (SOAR → UEBA) --------
def process_message(ch, method, properties, body):
    try:
        data = json.loads(body)

        target_ip = data.get("target_ip")  # from STRUCT_SOAR_ACTION

        if not target_ip:
            logging.warning("No target_ip in SOAR message, cannot forward")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        logging.info(
            f"Received SOAR action: incident_id={data.get('incident_id')}, "
            f"action_name={data.get('action_name')}, "
            f"action_attributes={data.get('action_attributes')}, "
            f"target_ip={target_ip}"
        )

        # Forward the full STRUCT_SOAR_ACTION message unchanged
        success = forward_to_client(target_ip, data)
        if success:
            logging.info("Message forwarded to client successfully")

        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logging.error(f"Error handling SOAR message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


# -------- UDP Listener for Client ACKs --------
def listen_for_client_acks():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SERVER_ACK_PORT))
    logging.info(f"Listening for client ACKs on UDP port {SERVER_ACK_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            ack_msg = json.loads(data.decode())
            logging.info(f"Received ACK from client {addr}: {ack_msg}")

            # Publish ACK to SOAR via RabbitMQ
            send_ack_to_soar(ack_msg)

        except Exception as e:
            logging.error(f"Error processing client ACK: {e}")


# -------- Publish ACK back to SOAR (RabbitMQ) --------
def send_ack_to_soar(ack_msg):
    try:
        channel.queue_declare(queue=ACK_QUEUE, durable=True)
        channel.basic_publish(
            exchange=rabbit_cfg.get("exchange", ""),
            routing_key=ACK_QUEUE,
            body=json.dumps(ack_msg),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logging.info(f"Published ACK to SOAR queue {ACK_QUEUE}: {ack_msg}")
    except Exception as e:
        logging.error(f"Failed to publish ACK to SOAR: {e}")


# -------- Main --------
def main():
    global connection, channel

    logging.info(f"Connecting to RabbitMQ at {rabbit_cfg['host']}:{rabbit_cfg['port']}")

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host=rabbit_cfg["host"],
            port=rabbit_cfg["port"],
            virtual_host=rabbit_cfg.get("virtual_host", "/"),
            credentials=pika.PlainCredentials(
                rabbit_cfg.get("username", "guest"),
                rabbit_cfg.get("password", "guest")
            )
        )
    )
    channel = connection.channel()

    # Start UDP listener for client ACKs in background
    threading.Thread(target=listen_for_client_acks, daemon=True).start()

    # Consume SOAR → UEBA messages
    channel.queue_declare(queue=SOAR_TO_UEBA_QUEUE, durable=True)
    logging.info(f"Listening for SOAR actions on queue: {SOAR_TO_UEBA_QUEUE}")

    channel.basic_consume(queue=SOAR_TO_UEBA_QUEUE, on_message_callback=process_message, auto_ack=False)
    channel.start_consuming()


if __name__ == "__main__":
    main()
