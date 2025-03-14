# Predator dockerized installation
Dockerized version provides full Predator ecosystem:
- **Predator core**, Predator complete tool
- **Elasticsearch**, threats logs retention
- **Predator dashboard**, dashboard for threats visualisation through Elasticsearch

Tested procedure is related to Ubuntu 22.04 LTS

## Dependencies
Clone the project (e.g., `/opt/predator`):
   ```bash
   apt-get update
   apt install -y ca-certificates curl gnupg lsb-release
   mkdir -p /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
   echo  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   apt update
   apt install -y docker-ce docker-ce-cli containerd.io docker-compose docker-compose-plugin
   ```

## Predator environment installation with compose engine
Install Predator environment using following commands:
   ```bash
   cd /opt/predator
   docker-compose up -d --remove-orphans
   ```

## First execution commands
On first run, some commands have to be launched to prepare environments:
   ```bash
   docker exec predator_es /bin/bash /usr/share/elasticsearch/scripts/init_es.sh
   ```
This creates proper template in Elasticsearch

## Starting Predator
Start Predator using following command:
   ```bash
   docker exec predator_core /bin/bash /opt/predator/predator.sh start
   ```

Status is available running following command:
   ```bash
   docker exec predator_core /opt/predator/predator.sh status
   ```

Logs are available running following command:
   ```bash
   docker logs -ft predator_core
   docker logs -ft predator_dashboard
   ```

After set proxy in browser (refer to [config.py](./config.md) for feature enabling, generate CA through API and import in browser in order to complete SSL interception), visit [http://predator.dashboard](http://predator.dashboard).
**Note**: as default Dashboard is only reachable through Proxy at LINK_DASHBOARD URL because bind over 127.0.0.1, changing dasboard/config.py configuration Dasboard can be reached directly.
