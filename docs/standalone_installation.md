# Predator standalone installation
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
   ```

## Starting Predator
Start Predator using following command
   ```bash
   python3 ./predator.py
   # or
   ./predator.sh start
   ```
   **Note**: Root privileges are required.
