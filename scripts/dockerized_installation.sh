apt-get update
apt install -y ca-certificates curl gnupg lsb-release
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose docker-compose-plugin
cd /opt/predator

echo "Stopping containers"
docker ps -a | grep predator | awk -F' ' '{print $1}' | xargs docker stop
echo "Removing containers"
docker ps -a | grep predator | awk -F' ' '{print $1}' | xargs docker rm
echo "Removing volumes"
docker volume list | grep predator | grep -v "\(predator_core_certs\|predator_es_data\)" | awk -F' ' '{print $2}' | xargs docker volume rm
echo "Removing images"
docker images | grep predator | awk -F' ' '{print $3}' | xargs docker rmi

docker-compose up -d --remove-orphans
docker exec predator_es /bin/bash /usr/share/elasticsearch/scripts/init_es.sh
docker exec predator_core /bin/bash /opt/predator/predator.sh start
