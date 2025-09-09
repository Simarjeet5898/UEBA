import json
import logging
from send import send_to_rabbitmq  

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    # Fake anomaly packet
    anomaly_packet = {
        "msgId": 121,
        "eventId": "E-001",
        "username": "simar",
        "eventType": "LOGIN",
        "eventName": "FAILED_LOGIN",
        "severity": "HIGH",
        "deviceIp": "192.168.100.103",
        "deviceMacId": "FE-AD-11-43-23-11",
        "logText": "Test anomaly from UEBA"
    }

    # Choose a msg_id that exists in config.json queue mapping
    msg_id = anomaly_packet["msgId"]

    success = send_to_rabbitmq(anomaly_packet, msg_id,"siem")
    if success:
        logging.info("Test anomaly sent successfully to RabbitMQ")
    else:
        logging.error(" Failed to send test anomaly")