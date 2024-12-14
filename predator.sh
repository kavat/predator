#!/bin/bash

APP_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

APP_PATH="${APP_DIR}/predator.py"
CONF_PATH="${APP_DIR}/config.py"
JSON_PATH="${APP_DIR}/conf/json"
LOG_PATH="${APP_DIR}/var/log"
PID_FILE="${APP_DIR}/var/run/predator.pid"
PATH_ANUBI_SIGNATURES="${APP_DIR}/../anubi-signatures"
PATH_VENV="${APP_DIR}/predator_env/"
MANAGEMENT_HOST=$(cat ${CONF_PATH} | grep MANAGEMENT_HOST | awk -F' = ' '{print $2}')
MANAGEMENT_PORT=$(cat ${CONF_PATH} | grep MANAGEMENT_PORT | awk -F' = ' '{print $2}')
PROXY_PORT=$(cat ${CONF_PATH} | grep PROXY_PORT | awk -F' = ' '{print $2}')
DUMMY_PORT=$(cat ${CONF_PATH} | grep DUMMY_PORT | awk -F' = ' '{print $2}')

update_full() {
        
  if [ -d "${PATH_ANUBI_SIGNATURES}" ]; then
    cd "${PATH_ANUBI_SIGNATURES}"
    git pull
  else
    cd "${APP_DIR}/.."
    git clone git@github.com:kavat/anubi-signatures.git
  fi
    
  for file_ip_list in $(ls "${PATH_ANUBI_SIGNATURES}/ips" | grep "[0-9][0-9][0-9][0-9]\-[0-9][0-9]\.list"); do
    anno=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $1}')
    mese=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $2}')
    cat "${PATH_ANUBI_SIGNATURES}/ips/${file_ip_list}" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\"misp\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
    curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT} -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"
  done
        
  cat "${PATH_ANUBI_SIGNATURES}/ips/tor.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk '{print "\\\""$1"\\\":\\\"tor\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > ${JSON_PATH}/tor_nodes.json
  curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT} -d "{\"func\":\"loadjson\",\"file_json\":\"tor_nodes.json\"}"
                
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
    git clone git@github.com:kavat/anubi-signatures.git
  fi

  cat "${PATH_ANUBI_SIGNATURES}/ips/${anno}-${mese}.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
  curl -XPOST -s -H 'content-type: application/json' http://${MANAGEMENT_HOST}:${MANAGEMENT_PORT} -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"

  ls -lth ${JSON_PATH}/anubi_${anno}_${mese}_ip.json

}

check_json() {
  for file_json in $(ls ${JSON_PATH}/*.json); do
    cat $file_json | jq . > /dev/null
    if [ $? -ne 0 ]; then
      echo $file_json errato
    fi
  done
}

clean_log() {
  rm -rf ${LOG_PATH}/predator*.log
}

status() {
  echo "Predator process status: "
  ps xa | grep predator.py | grep -v grep
  echo -en "\tPredator management socket status: "
  test_port=$(ss -antp | grep ":${MANAGEMENT_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    echo "down"	    
  fi
  echo -en "\tPredator proxy socket status: "
  test_port=$(ss -antp | grep ":${PROXY_PORT}")
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
  test_port=$(ss -antp | grep ":${DUMMY_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    check_conf=$(cat ${CONF_PATH} | grep "^SEND_TO_DUMMY = False")
    if [ "${check_conf}" != "" ]; then
      echo "disabled"
    else
      echo "down"
    fi
  fi
  echo "Predator logs status: "
  ls -lht ${LOG_PATH}/predator*.log
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
    check_porta=$(ss -anpt | grep ":${MANAGEMENT_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${MANAGEMENT_PORT} is already opened"
      exit 1
    fi
    echo "Check port ${PROXY_PORT}/TCP already opened.."
    check_porta=$(ss -anpt | grep ":${PROXY_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${PROXY_PORT} is already opened"
      exit 1
    fi
    echo "Check port ${DUMMY_PORT}/TCP already opened.."
    check_porta=$(ss -anpt | grep ":${DUMMY_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${DUMMY_PORT} is already opened"
      exit 1
    fi
    if [ $? -ne 0 ]; then
      echo "KO"
      exit 1
    fi
    echo ""
    nohup $PATH_VENV/bin/python3 -u $APP_PATH >> ${LOG_PATH}/predator_std.log 2>&1 &
    echo $! > $PID_FILE
    echo "Service started."
}

stop() {
  if [ -f $PID_FILE ]; then
    kill $(cat $PID_FILE)
    rm $PID_FILE
    ps xa | grep python3 | grep predator.py | grep -v grep | grep -o "^[ 0-9]\+" | xargs kill -9
    echo "Service stopped."
  else
    ps xa | grep python3 | grep predator.py | grep -v grep | grep -o "^[ 0-9]\+" | xargs kill -9
    echo "The service is not running."
  fi
}

restart() {
  stop
  sleep 3
  start
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
  clean)
    clean_log
  ;;
  start)
    start
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
  *)
  echo "Usage: $0 {start|stop|restart|rules|check_json|clean|status|tail}"
esac
