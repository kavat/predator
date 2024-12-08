#!/bin/bash

APP_PATH="/Users/andreacavallini/Repository/predator/predator.py"
JSON_PATH="/Users/andreacavallini/Repository/predator/conf/json"
LOG_PATH="/Users/andreacavallini/Repository/predator/var/log"
PID_FILE="/Users/andreacavallini/Repository/predator/var/run/predator.pid"
PATH_ANUBI_SIGNATURES="/Users/andreacavallini/Repository/anubi-signatures"

update_full() {
        
    if [ -d "${PATH_ANUBI_SIGNATURES}" ]; then
      cd "${PATH_ANUBI_SIGNATURES}"
      git pull
    else
      cd "${PATH_ANUBI_SIGNATURES}"
      git clone git@github.com:kavat/anubi-signatures.git
    fi
    
    for file_ip_list in $(ls "${PATH_ANUBI_SIGNATURES}/ips" | grep "[0-9][0-9][0-9][0-9]\-[0-9][0-9]\.list"); do
      anno=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $1}')
      mese=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $2}')
      cat "${PATH_ANUBI_SIGNATURES}/ips/${file_ip_list}" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\"misp\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
      curl -XPOST -s -H 'content-type: application/json' http://127.0.0.1:10000 -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"
    done
        
    cat "${PATH_ANUBI_SIGNATURES}/ips/tor.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk '{print "\\\""$1"\\\":\\\"tor\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > ${JSON_PATH}/tor_nodes.json
    curl -XPOST -s -H 'content-type: application/json' http://127.0.0.1:10000 -d "{\"func\":\"loadjson\",\"file_json\":\"tor_nodes.json\"}"
                
    ls -lth ${JSON_PATH}/
        
}           

update() {

    anno=$1
    mese=$2

    if [ -d "${PATH_ANUBI_SIGNATURES}" ]; then
      cd "${PATH_ANUBI_SIGNATURES}"
      git pull
    else
      cd "${PATH_ANUBI_SIGNATURES}"
      git clone git@github.com:kavat/anubi-signatures.git
    fi

    for file_ip_list in $(ls "${PATH_ANUBI_SIGNATURES}/ips" | grep "[0-9][0-9][0-9][0-9]\-[0-9][0-9]\.list"); do
      anno=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $1}')
      mese=$(echo $file_ip_list | awk -F'.' '{print $1}' | awk -F'-' '{print $2}')
    cat "${PATH_ANUBI_SIGNATURES}/ips/${anno}-${mese}.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk -F':' '{print "\\\""$1"\\\":\\\""$2"\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > "${JSON_PATH}/anubi_${anno}_${mese}_ip.json"
      curl -XPOST -s -H 'content-type: application/json' http://127.0.0.1:10000 -d "{\"func\":\"loadjson\",\"file_json\":\"anubi_${anno}_${mese}_ip.json\"}"
    done

    cat "${PATH_ANUBI_SIGNATURES}/ips/tor.list" | grep "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | awk '{print "\\\""$1"\\\":\\\"tor\\\""}' | xargs echo | sed "s/ /,/g" | sed "s/^/{/g" | sed "s/$/}/g" > ${JSON_PATH}/tor_nodes.json
    curl -XPOST -s -H 'content-type: application/json' http://127.0.0.1:10000 -d "{\"func\":\"loadjson\",\"file_json\":\"tor_nodes.json\"}"

    ls -lth ${JSON_PATH}/

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
    rm -rf /var/log/predator*.log
}

status() {
    echo "Predator process status: "
    ps xa | grep predator.py | grep -v grep
    echo -n "Predator management socket status: "
    test_port=$(ss -antp | grep ":10000")
    if [ "${test_port}" != "" ]; then
      echo "up"
    else
      echo "down"	    
    fi
    echo -n "Predator proxy socket status: "
    test_port=$(ss -antp | grep ":7777")
    if [ "${test_port}" != "" ]; then
      echo "up"
    else
      check_conf=$(cat /opt/predator/config.py | grep "^PROXY = False")
      if [ "${check_conf}" != "" ]; then
        echo "disabled"
      else	
        echo "down"
      fi
    fi
    echo -n "Predator dummy socket status: "
    test_port=$(ss -antp | grep ":9999")
    if [ "${test_port}" != "" ]; then
      echo "up"
    else
      check_conf=$(cat /opt/predator/config.py | grep "^SEND_TO_DUMMY = False")
      if [ "${check_conf}" != "" ]; then
        echo "disabled"
      else
        echo "down"
      fi
    fi
    echo "Predator logs status: "
    ls -lht /var/log/predator*.log
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
    echo "Check port 10000/TCP already opened.."
    check_porta=$(ss -anpt | grep 10000)
    if [ "${check_porta}" != "" ]; then
        echo "PID not found but port 10000 is already opened"
        exit 1
    fi
    echo "Check port 7777/TCP already opened.."
    check_porta=$(ss -anpt | grep 7777)
    if [ "${check_porta}" != "" ]; then
        echo "PID not found but port 7777 is already opened"
        exit 1
    fi
    echo "Check port 9999/TCP already opened.."
    check_porta=$(ss -anpt | grep 9999)
    if [ "${check_porta}" != "" ]; then
        echo "PID not found but port 9999 is already opened"
        exit 1
    fi
    echo "Check Intellingence json consistency.."
    cat "${JSON_PATH}/intelligence.json" | jq . > /dev/null
    if [ $? -ne 0 ]; then
        echo "KO"
        exit 1
    fi
    echo ""
    nohup python3 -u $APP_PATH >> /var/log/predator_std.log 2>&1 &
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
    start
}

case "$1" in
    update)
        if [ "$2" != "" ] && [ "$3" != "" ]; then
            update "$2" "$3"
        else
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
        echo "Usage: $0 {start|stop|restart|update|check_json|clean|status|tail}"
esac
