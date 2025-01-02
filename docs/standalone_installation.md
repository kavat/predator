# Predator standalone installation

Standalone version provides Predator ecosystem:
- **Predator core**, Predator complete tool
- **Predator dashboard**, dashboard for threats visualisation through Elasticsearch

Elasticsearch is considered outside of standalone perimeter.

Tested procedure is related to Ubuntu 22.04 LTS

## Dependencies
Clone the project (e.g., `/opt/predator`):
   ```bash
   apt-get update && cat requirements_system.txt | xargs apt-get install -y
   cd /opt/predator
   python3 -m venv predator_env
   source predator_env/bin/activate
   pip3 install -r requirements_python.txt
   mkdir -p /opt/predator/var/{log,run}
   chmod +x /opt/predator/predator.sh
   ```

## Forwarding preparation
Threats logs can be forwarded to third-parties softwares, such:
- **Elasticsearch**, (after set `SEND_TO_ES` to True) 
Run following script after editing with proper settings:
   ```bash
   cd /opt/predator/docker_utils
   chmod +x init_es.sh
   ./init_es.sh 
   ```

- **SQlite**, (after set `SEND_TO_SQLITE` to True) 
Run following script after editing with proper settings:
   ```bash
   cd /opt/predator/docker_utils
   chmod +x init_sqlite.sh
   ./init_sqlite.sh 
   ```

## Starting Predator
Start Predator using following command:
   ```bash
   ./predator_env/bin/python3 ./predator.py
   # or
   ./predator.sh start
   ```
   **Note**: Root privileges are required.

Status is available running:
   ```bash
   ./predator.sh status
   ```

## Starting Predator dashboard
Start Predator dashboard using following command:
   ```bash
   cd dashboard
   ./predator_env/bin/python3 ./dashboard.py
   # or
   chmod +x dashboard.sh
   ./dashboard.sh start
   ```
**Note**: Dashboard can be used only with Elasticsearch
**Note**: as default Dashboard is only reachable through Proxy at LINK_DASHBOARD URL because bind over 127.0.0.1, changing dasboard/config.py configuration Dasboard can be reached directly.
