ReadMe – User Entity Behavior Analysis

1. Prerequisites

-   Operating System: Linux (tested on Ubuntu 20.04 / 22.04, x64)
-   PostgreSQL: Installed and running (v14 or higher recommended)
-   Network: Required ports open (e.g., 5432 for PostgreSQL, UDP port
    for client-server communication, SIEM endpoint ports)

2. Installation Steps

	Provide execution permissions:

        chmod 777 ueba/ueba_client_v1.0.0
        chmod 777 ueba/ueba_server_v1.0.0

3. Configuration

    Place config.json in the /home directory 
    Update the following parameters as per deployment:
    -   Database Connection: Host, port, user, password for PostgreSQL.
    -   SIEM Endpoint URL(s): REST API endpoints for forwarding logs.

4. Execution

-   Start UEBA Server:

        ./ueba_server_v1.0.0

-   Start UEBA Client:

        ./ueba_client_v1.0.0

Logs will be generated in the runtime directory.

5. Notes

-   On first run, the server will auto-create the PostgreSQL schema
    (anomalies_log and supporting tables).
-   Ensure PostgreSQL service is running before starting the server.
-   SIEM/SOAR integrations depend on correct endpoint configuration in
    config.json.
