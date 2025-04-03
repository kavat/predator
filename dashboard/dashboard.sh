#!/bin/bash

APP_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

APP_PATH="${APP_DIR}/dashboard.py"
CONF_PATH="${APP_DIR}/config.py"
PATH_VENV="${APP_DIR}/../predator_env/"
HOST=$(cat ${CONF_PATH} | grep DASHBOARD_HOST | awk -F' = ' '{print $2}' | sed "s/\"//g")
PORT=$(cat ${CONF_PATH} | grep DASHBOARD_PORT | awk -F' = ' '{print $2}' | sed "s/\"//g")
LOG_PATH="${APP_DIR}/var/log"
RUN_PATH="${APP_DIR}/var/run"
PID_FILE="${RUN_DIR}/dashboard.pid"

mkdir -p ${LOG_PATH}
mkdir -p ${RUN_PATH}

status() {
  echo "Predator dashboard process status: "
  ps xa | grep dashboard.py | grep -v grep
  echo -en "\tPredator dashboard socket status: "
  test_port=$(ss -antp | grep ":${PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    echo "down"	    
  fi
  ls -l ${LOG_PATH}
}

start() {
    check_predator=$(ps xa | grep "python3" | grep "dashboard.py" | grep -v grep)
    if [ "${check_predator}" != "" ]; then
      echo "The service is already running."
      exit 1
    fi	
    if [ -f $PID_FILE ]; then
      echo "The service is already running."
      exit 1
    fi
    echo "Check port ${PORT}/TCP already opened.."
    check_porta=$(ss -anpt | grep ":${PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "PID not found but port ${PORT} is already opened"
      exit 1
    fi
    if [ $? -ne 0 ]; then
      echo "KO"
      exit 1
    fi
    echo ""
    if [ "${1}" == "daemon" ]; then
      if [ -f "/.dockerenv" ]; then
	nohup python3 -u $APP_PATH >> /proc/1/fd/1 2>&1 &
	echo $! > $PID_FILE
	echo "Service started."
      else
        nohup $PATH_VENV/bin/python3 -u $APP_PATH >> ${LOG_PATH}/predator_dashboard.log 2>&1 &
        echo $! > $PID_FILE
        echo "Service started."
      fi
    else
      if [ -f "/.dockerenv" ]; then
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
  ps xa | grep python3 | grep dashboard.py | grep -v grep | grep -o "^[ 0-9]\+" | xargs kill -9 > /dev/null 2>&1
}

restart() {
  stop
  sleep 3
  start "daemon"
}

case "$1" in
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
  echo "Usage: $0 {start|stop|restart|run}"
esac
