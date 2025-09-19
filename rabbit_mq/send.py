### UEBA → SIEM queues (UEBA sends anomalies to SIEM):

    # UEBA_SIEM_ANOMALOUS_APPLICATION_USAGE

    # UEBA_SIEM_ANOMALOUS_CPU_GPU_RAM_CONSP

    # UEBA_SIEM_ANOMALOUS_FILE_ACCESS

    # UEBA_SIEM_ANOMALOUS_USER_SESSION

    # UEBA_SIEM_BEHAVIOURAL_CHANGE_DETECTION

    # UEBA_SIEM_BRUTE_FORCE_ATTACK_DETECTION

    # UEBA_SIEM_COMMAND_EXE_MONI

    # UEBA_SIEM_DATA_EXFILTRATION_ATTEMPTS_DETECTION

    # UEBA_SIEM_DATA_EXFILTRATION_DETECTION

    # UEBA_SIEM_DOS_DDOS_DETECTION

    # UEBA_SIEM_FILE_SYS_MONI

    # UEBA_SIEM_SSH_BRUTE_FORCE_DETECTION

    # UEBA_SIEM_UNUSED_ACC_ACTIVITY

    # UEBA_SIEM_PRIVILEGED_USER_MONI

    # UEBA_SIEM_PRIVILEGE_ESCALATION_MONI

### UEBA → SOAR queues (UEBA sends acknowledgements/actions to SOAR):

    # UEBA_SOAR_ACTION_ACK

# SOAR → UEBA queues (SOAR sends instructions to UEBA):

    # SOAR_UEBA_ACTION_FOR_ANOMALY

import pika
import json
import logging
import os

CONFIG_PATH = "/home/config.json"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

config = load_config()

# def send_to_rabbitmq(packet, msg_id: int, target="siem") -> bool:
#     """Publish anomaly packet to RabbitMQ based on msg_id mapping."""
#     try:
#         # Pick correct rabbitmq block
#         rabbit_cfg = config["rabbitmq"][target]

#         queue_map = config.get("queue_name", {})
#         target_queue = queue_map.get(str(msg_id))
#         if not target_queue:
#             logging.warning(f"No RabbitMQ queue mapping for msg_id={msg_id}")
#             return False

#         # Establish connection using config
#         connection = pika.BlockingConnection(
#             pika.ConnectionParameters(
#                 host=rabbit_cfg["host"],
#                 port=rabbit_cfg["port"],
#                 virtual_host=rabbit_cfg.get("virtual_host", "/"),
#                 credentials=pika.PlainCredentials(
#                     rabbit_cfg.get("username", "guest"),
#                     rabbit_cfg.get("password", "guest")
#                 )
#             )
#         )
#         channel = connection.channel()

#         # Ensure queue exists
#         channel.queue_declare(queue=target_queue, durable=True)

#         # Publish message
#         channel.basic_publish(
#             exchange=rabbit_cfg.get("exchange", ""),
#             routing_key=target_queue,
#             body=json.dumps(packet),
#             properties=pika.BasicProperties(delivery_mode=2)
#         )

#         connection.close()
#         return True

#     except Exception as e:
#         logging.error(f"RabbitMQ publish failed: {e}")
#         return False
def send_to_rabbitmq(packet, msg_id: int, target="siem") -> bool:
    """Publish anomaly packet to RabbitMQ based on msg_id mapping."""
    try:
        print(f"[RabbitMQ] Preparing to send packet. msg_id={msg_id}, target={target}")
        print(f"[RabbitMQ] Packet preview: {json.dumps(packet, indent=2, default=str)[:500]}")

        # Pick correct rabbitmq block
        rabbit_cfg = config["rabbitmq"][target]
        print(f"[RabbitMQ] Using config: host={rabbit_cfg.get('host')}, port={rabbit_cfg.get('port')}, vhost={rabbit_cfg.get('virtual_host', '/')}")

        queue_map = config.get("queue_name", {})
        target_queue = queue_map.get(str(msg_id))
        print(f"[RabbitMQ] Queue map: {queue_map}, target_queue={target_queue}")

        if not target_queue:
            print(f"[RabbitMQ] WARNING: No queue mapping for msg_id={msg_id}")
            return False

        # Establish connection using config
        print(f"[RabbitMQ] Connecting to broker...")
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
        print(f"[RabbitMQ] Connection established.")

        channel = connection.channel()
        print(f"[RabbitMQ] Channel opened.")

        # Ensure queue exists
        print(f"[RabbitMQ] Declaring queue: {target_queue}")
        channel.queue_declare(queue=target_queue, durable=True)

        # Publish message
        print(f"[RabbitMQ] Publishing to exchange='{rabbit_cfg.get('exchange', '')}', routing_key='{target_queue}'")
        channel.basic_publish(
            exchange=rabbit_cfg.get("exchange", ""),
            routing_key=target_queue,
            body=json.dumps(packet),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        print(f"[RabbitMQ] Message published successfully.")

        connection.close()
        print(f"[RabbitMQ] Connection closed.")
        return True

    except Exception as e:
        print(f"[RabbitMQ] ERROR: Publish failed: {e}")
        return False


