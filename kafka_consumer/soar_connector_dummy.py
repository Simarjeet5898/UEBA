import pika
import json

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

rabbit_cfg = config["rabbitmq"]["soar"]
queue_cfg = config["soar_queue"]
QUEUE_NAME = queue_cfg.get("queue_name", "SOAR_UEBA_ACTION_FOR_ANOMALY")

# Connect to RabbitMQ
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

# Make sure queue exists
channel.queue_declare(queue=QUEUE_NAME, durable=True)

# Example SOAR action
msg = {
    "action": "block_port",
    "params": {"port": 8080},
    "target_ip": "127.0.0.1" 
    
}

channel.basic_publish(
    exchange=rabbit_cfg.get("exchange", ""),
    routing_key=QUEUE_NAME,
    body=json.dumps(msg),
    properties=pika.BasicProperties(delivery_mode=2)  # make message persistent
)

print(f"Sent dummy SOAR message: {msg}")
connection.close()
