import time
from datetime import datetime
from kafka_producer.new_log_monitor import collect_network_status

if __name__ == "__main__":
    print("\033[1;92m[DEBUG] Starting Network Status Monitor Test...\033[0m")
    while True:
        try:
            results = collect_network_status()
            print(f"\n\033[1;94m[{datetime.now().strftime('%H:%M:%S')}] Network Status Snapshot:\033[0m")
            for entry in results:
                print(f"Interface: {entry['interface']}")
                print(f"  Status: {'UP' if entry['is_up'] else 'DOWN'}")
                print(f"  IP: {entry['ip_address']}")
                print(f"  MAC: {entry['mac_address']}")
                print(f"  Gateway: {entry['gateway_ip']}")
                print(f"  Ping OK: {entry['ping_ok']}, Latency: {entry['latency_ms']} ms")
                print(f"  Bytes Sent: {entry['bytes_sent']}, Bytes Recv: {entry['bytes_recv']}")
                print(f"  Event: {entry['event']}")
                print("-" * 50)
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n\033[1;91m[STOPPED] Exiting network status monitor test.\033[0m")
            break
        except Exception as e:
            print(f"\033[1;91m[ERROR] {e}\033[0m")
            time.sleep(5)
