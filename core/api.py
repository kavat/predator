from flask import Flask, request, render_template
from core.utils import parse_json
from core.networking import check_tcp_conn
from core.library import Library
from subprocess import PIPE, Popen
from glob import glob

import json
import copy
import config
import os

app = Flask(__name__)

def post_actions(data):
  msg = ""
  if 'func' in data:
    if data["func"] == "help":
      msg = "createca|loadjson|status|setloglevel|conf|check_ip"
    elif data["func"] == "check_ip":
      if 'ip' in data:
        msg = data["ip"] + " blacklisted: " + Library().client("blacklist_ip|{}".format(data["ip"])
      else:
        msg = "IP missed"
    elif data["func"] == "conf":
      if config.IDS:
        msg = "IDS: enabled<br>"
      else:
        msg = "IDS: disabled<br>"
      if config.PROXY:
        msg = "{}PROXY enabled<br>".format(msg)
      else:
        msg = "{}PROXY disabled<br>".format(msg)
      msg = "{}PROXY IP/PORT: {}:{}<br>".format(msg, config.PROXY_HOST, config.PROXY_PORT)
      if config.API:
        msg = "{}API enabled<br>".format(msg)
      else:
        msg = "{}API disabled<br>".format(msg)
      msg = "{}API IP/PORT: {}:{}<br>".format(msg, config.MANAGEMENT_HOST, config.MANAGEMENT_PORT)
      if config.DUMMY:
        msg = "{}DUMMY enabled<br>".format(msg)
      else:
        msg = "{}DUMMY disabled<br>".format(msg)
      msg = "{}DUMMY IP/PORT: {}:{}<br>".format(msg, config.DUMMY_HOST, config.DUMMY_PORT)
    elif data["func"] == "createca":
      if os.path.exists(config.CA_CRT):
        os.remove(config.CA_CRT)
      if os.path.exists(config.CA_KEY):
        os.remove(config.CA_KEY)
      Popen(["openssl", "genrsa", "-out", config.CA_KEY, str(config.CA_KEY_SIZE)]).communicate()
      Popen(["openssl", "req", "-new", "-x509", "-days", "3650", "-key", config.CA_KEY, "-sha256", "-out", config.CA_CRT, "-subj", "/CN=Predator CA", ]).communicate()
      Popen(["openssl", "genrsa", "-out", config.CERT_KEY, str(config.CERT_KEY_SIZE)]).communicate()
      os.makedirs(config.CERT_DIR, exist_ok=True)
      for old_cert in glob(os.path.join(config.CERT_DIR, "*.pem")):
        os.remove(old_cert)
      if os.path.exists(config.CA_CRT): 
        msg = "Certification authority created, please download it from {} after set Predator as proxy".format(config.LINK_DOWNLOAD_CA)
    elif data["func"] == "loadjson":
      if 'file_json' in data:
        if os.path.exists(config.PATH_JSON + data['file_json']):
          msg = data['file_json'] + " " + Library().client("feed_add|{}".format(data['file_json']))
        else:
          msg = "File " + data['file_json'] + " not found"
      else:
        msg = Library().client("json_reload|")
    elif data["func"] == "status":
      msg = "UP"
    elif data["func"] == "setloglevel":
      if "logger_name" in data and "logger_level" in data:
        if data["logger_name"] in config.LOGGERS["ASSOC"]:
          if data["logger_level"] in config.LOGGERS["LEVELS"]:
            config.LOGGERS["RESOURCES"][config.LOGGERS["ASSOC"][data["logger_name"]]].set_level(data["logger_level"])
            msg = "Impostato livello " + data["logger_level"] + " per " + config.LOGGERS["ASSOC"][data["logger_name"]]
          else:
            risposta = data["logger_level"] + " non impostabile"
        else:
          risposta = data["logger_name"] + " non presente tra i loggers"
      else:
        risposta = "LoggerName o LoggerLevel non passato come argomento"
    else:
      msg = "Funzione non gestita"
    return {"func":data["func"],"msg":msg}
  else:
    return {"func":"nofunc"}

@app.route("/api", methods=['GET', 'POST'])
def api():
  if request.method == 'POST':
    if request.data:
      rcv_data = json.loads(request.data.decode(encoding='utf-8'))
      rsp = post_actions(rcv_data)
      if rsp:
        return rsp
      else:
        return '200'
    else:
      return '404'
  if request.method == 'GET':
    rcv_data = request.args.to_dict(flat=True)
    if 'func' not in rcv_data:
      rcv_data['func'] = 'home'
    print(rcv_data)
    rsp = post_actions(rcv_data)
    if rsp:
      return rsp
    else:
      return '200'

@app.route("/", methods=['GET'])
def index():
  return render_template('index.html', host=config.MANAGEMENT_HOST, port=config.MANAGEMENT_PORT, json_path=config.PATH_JSON)

def start_api(host, port):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().info("Starting API..")
    app.run(host, port)
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False: 
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().critical("Tra " + str(config.SLEEP_THREAD_RESTART) + " riavvio il thread")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("api() BOOM!!!")
      time.sleep(config.SLEEP_THREAD_SOCKET_RESTART)
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().critical("Riavvio thread")
      start_api(host, port)
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().info("Server raggiungibile, riavvio del thread non necessario") 
