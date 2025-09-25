import json
import logging
import pika
import signal
import sys

# ========== Load Config ==========
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

rabbit_cfg = config["rabbitmq"]["soar"]
queue_cfg = config["soar_queue"]
QUEUE_NAME = queue_cfg.get("queue_name", "SOAR_UEBA_ACTION_FOR_ANOMALY")

# ========== Logging ==========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SOAR-UEBA] %(levelname)s: %(message)s"
)

# ========== Message Processor ==========
def process_message(ch, method, properties, body):
    try:
        data = json.loads(body)
        logging.info(f"Received SOAR action message: {json.dumps(data, indent=2)}")

        # For now, just acknowledge
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logging.error(f"Error processing SOAR message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

# ========== Setup Consumer ==========
def main():
    try:
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

        # Ensure queue exists
        channel.queue_declare(queue=QUEUE_NAME, durable=True)
        logging.info(f"Listening on queue: {QUEUE_NAME}")

        channel.basic_consume(queue=QUEUE_NAME, on_message_callback=process_message, auto_ack=False)

        # Graceful shutdown
        def shutdown(sig, frame):
            logging.info("Shutting down SOAR connector...")
            connection.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        channel.start_consuming()

    except Exception as e:
        logging.error(f"Failed to start SOAR consumer: {e}")

if __name__ == "__main__":
    main()
