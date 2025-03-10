#!/bin/bash

APP_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

APP_PATH="${APP_DIR}/predator.py"
CONF_PATH="${APP_DIR}/config.py"
CERTS_PATH="${APP_DIR}/certs"
JSON_PATH="${APP_DIR}/conf/json"
LOG_PATH="${APP_DIR}/var/log"
RUN_PATH="${APP_DIR}/var/run"
DB_PATH="${APP_DIR}/var/db"
PID_FILE="${APP_DIR}/var/run/predator.pid"
PATH_ANUBI_SIGNATURES="${APP_DIR}/../anubi-signatures"
PATH_VENV="${APP_DIR}/predator_env/"
MANAGEMENT_HOST=$(cat ${CONF_PATH} | grep MANAGEMENT_HOST | awk -F' = ' '{print $2}' | sed "s/\"//g")
MANAGEMENT_PORT=$(cat ${CONF_PATH} | grep MANAGEMENT_PORT | awk -F' = ' '{print $2}' | sed "s/\"//g")
PROXY_PORT=$(cat ${CONF_PATH} | grep PROXY_PORT | awk -F' = ' '{print $2}' | sed "s/\"//g")
DUMMY_PORT=$(cat ${CONF_PATH} | grep DUMMY_PORT | awk -F' = ' '{print $2}' | sed "s/\"//g")

mkdir -p $LOG_PATH
mkdir -p $RUN_PATH
mkdir -p $DB_PATH
mkdir -p $CERTS_PATH

update_full() {
        
  if [ -d "${PATH_ANUBI_SIGNATURES}" ]; then
    cd "${PATH_ANUBI_SIGNATURES}"
    git pull
  else
    cd "${APP_DIR}/.."
    git clone https://github.com/kavat/anubi-signatures.git
  fi
 
  echo "Updating IP"   
  for file_ip_list in $(ls "${PATH_ANUBI_SIGNATURES}/ips" | grep "[0-9][0-9][0-9][0-9]\-[0-9][0-9]\.list"); do
    anno=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $1}')
    mese=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $2}')
    cat "${PATH_ANUBI_SIGNATURES}/ips/${file_ip_list}" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | sed "s/'//g" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
    curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT}/api -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"
  done
        
  cat "${PATH_ANUBI_SIGNATURES}/ips/tor.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\"tor\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > ${JSON_PATH}/tor_nodes.json
  curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT}/api -d "{\"func\":\"loadjson\",\"file_json\":\"tor_nodes.json\"}"

  echo "Updating FQDN"
  for file_fqdn_list in $(ls "${PATH_ANUBI_SIGNATURES}/fqdn" | grep "[0-9][0-9][0-9][0-9]\-[0-9][0-9]\.list"); do
    anno=$(echo $file_fqdn_list | awk -F'.' '{print $1}' | awk -F'-' '{print $1}')
    mese=$(echo $file_fqdn_list | awk -F'.' '{print $1}' | awk -F'-' '{print $2}')
    cat "${PATH_ANUBI_SIGNATURES}/fqdn/${file_fqdn_list}" | grep -v "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | sed "s/'//g" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_fqdn.json"
    curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT}/api -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_fqdn.json\"}"
  done
                
  ls -lth ${JSON_PATH}/
        
}           

update() {

  anno=$1
  mese=$2

  if [ -d "${PATH_ANUBI_SIGNATURES}" ]; then
    cd "${PATH_ANUBI_SIGNATURES}"
    git pull
  else
    cd "${APP_DIR}/.."
    git clone https://github.com/kavat/anubi-signatures.git
  fi

  cat "${PATH_ANUBI_SIGNATURES}/ips/${anno}-${mese}.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
  curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT}/api -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"
  cat "${PATH_ANUBI_SIGNATURES}/fqdn/${anno}-${mese}.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_fqdn.json"
  curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT}/api -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_fqdn.json\"}"

  ls -lth ${JSON_PATH}/anubi_${anno}_${mese}_*.json

}

check_json() {
  for file_json in $(ls ${JSON_PATH}/*.json); do
    cat $file_json | jq . > /dev/null
    if [ $? -ne 0 ]; then
      echo $file_json errato
    fi
  done
}

clean_logs() {
  rm -rf ${LOG_PATH}/predator*.log
}

clean_local_db() {
  rm -rf ${DB_PATH}/*.json
}

status() {
  echo "Predator process status: "
  ps xa | grep predator.py | grep -v grep
  echo -en "\tPredator management socket status: "
  test_port=$(ss -antl | grep ":${MANAGEMENT_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    echo "down"	    
  fi
  echo -en "\tPredator proxy socket status: "
  test_port=$(ss -antl | grep ":${PROXY_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    check_conf=$(cat ${CONF_PATH} | grep "^PROXY = False")
    if [ "${check_conf}" != "" ]; then
      echo "disabled"
    else	
      echo "down"
    fi
  fi
  echo -en "\tPredator dummy socket status: "
  test_port=$(ss -antl | grep ":${DUMMY_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    check_conf=$(cat ${CONF_PATH} | grep "^DUMMY = False")
    if [ "${check_conf}" != "" ]; then
      echo "disabled"
    else
      echo "down"
    fi
  fi
  echo "Predator logs status: "
  ls -lht ${LOG_PATH}/predator*.log
  echo -n "Predator local DB items $(ls ${DB_PATH}/*.json | wc -l)"
  echo ""
}

start() {
    check_predator=$(ps xa | grep "python3" | grep "predator.py" | grep -v grep)
    if [ "${check_predator}" != "" ]; then
      echo "The service is already running."
      exit 1
    fi	
    if [ -f $PID_FILE ]; then
      echo "The service is already running."
      exit 1
    fi
    echo "Check port ${MANAGEMENT_PORT}/TCP already opened.."
    check_porta=$(ss -antl | grep ":${MANAGEMENT_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${MANAGEMENT_PORT} is already opened"
      exit 1
    fi
    echo "Check port ${PROXY_PORT}/TCP already opened.."
    check_porta=$(ss -antl | grep ":${PROXY_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${PROXY_PORT} is already opened"
      exit 1
    fi
    echo "Check port ${DUMMY_PORT}/TCP already opened.."
    check_porta=$(ss -antl | grep ":${DUMMY_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${DUMMY_PORT} is already opened"
      exit 1
    fi
    if [ $? -ne 0 ]; then
      echo "KO"
      exit 1
    fi
    echo ""
    update_full
    check_container=$(ps -o comm= -p 1 | grep -v "\(systemd\|init\)")
    if [ "${1}" == "daemon" ]; then
      if [ -f "/.dockerenv" ] || [ "${check_container}" != "" ]; then
	nohup python3 -u $APP_PATH >> /proc/1/fd/1 2>&1 &
	echo $! > $PID_FILE
	echo "Service started."
      else
        nohup $PATH_VENV/bin/python3 -u $APP_PATH >> ${LOG_PATH}/predator_std.log 2>&1 &
        echo $! > $PID_FILE
        echo "Service started."
      fi
    else
      if [ -f "/.dockerenv" ] || [ "${check_container}" != "" ]; then
        python3 -u $APP_PATH
      else
        $PATH_VENV/bin/python3 -u $APP_PATH
      fi
    fi
}

stop() {
  if [ -f $PID_FILE ]; then
    kill $(cat $PID_FILE) > /dev/null 2>&1
    rm $PID_FILE
  fi
  ps xa | grep python3 | grep predator.py | grep -v grep | grep -o "^[ 0-9]\+" | xargs kill -9 > /dev/null 2>&1
}

restart() {
  stop
  sleep 3
  start "daemon"
}

case "$1" in
  rules)
    if [ "$2" != "" ] && [ "$3" != "" ]; then
      echo "Updating for ${2} and ${3}.."
      update "$2" "$3"
    else
      echo "Updating full.."
      update_full
    fi
  ;;
  tail)
    if [ "$2" != "" ]; then
      if [ -f ${LOG_PATH}/predator_${2}.log ]; then
        tail -n100 -f ${LOG_PATH}/predator_${2}.log 
      else
        echo "${LOG_PATH}/predator_${2}.log not existent"
      fi
    else
      echo "Log name missed"
    fi
  ;;
  check_json)
    check_json
  ;;
  clean_logs)
    clean_logs
  ;;
  clean_local_db)
    clean_local_db
  ;;
  wipe)
    clean_logs
    clean_local_db
  ;;
  start)
    start "daemon"
  ;;
  stop)
    stop
  ;;
  restart)
    restart
  ;;
  status)
    status
  ;;
  run)
    start "nodaemon"
  ;;
  *)
  echo "Usage: $0 {start|stop|restart|run|rules|check_json|clean_logs|clean_local_db|status|tail|wipe}"
esac
