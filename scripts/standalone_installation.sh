apt-get update && cat requirements_system.txt | xargs apt-get install -y
cd /opt/predator
python3 -m venv predator_env
source predator_env/bin/activate
pip3 install -r requirements_python.txt
mkdir -p /opt/predator/var/{log,run}
chmod +x /opt/predator/predator.sh
