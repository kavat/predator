from flask import Flask
from flask import request
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
      msg = "createca|loadjson|status|setloglevel|conf"
    elif data["func"] == "conf":
      if config.IDS:
        msg = "IDS: enabled\n"
      else:
        msg = "IDS: disabled\n"
      if config.PROXY:
        msg = "PROXY enabled\n"
      else:
        msg = "PROXY disabled\n"
      msg = "{}PROXY IP/PORT: {}:{}\n".format(msg, config.PROXY_HOST, config.PROXY_PORT))
      if config.API:
        msg = "API enabled\n"
      else:
        msg = "API disabled\n"
      msg = "{}API IP/PORT: {}:{}\n".format(msg, config.MANAGEMENT_HOST, config.MANAGEMENT_PORT))
      if config.DUMMY:
        msg = "DUMMY enabled\n"
      else:
        msg = "DUMMY disabled\n"
      msg = "{}DUMMY IP/PORT: {}:{}\n".format(msg, config.DUMMY_HOST, config.DUMMY_PORT))
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
        msg = "CA creata correttamente, scaricala collegandoti al link " + config.LINK_DOWNLOAD_CA
    elif data["func"] == "loadjson":
      if 'file_json' in data:
        if os.path.exists(config.PATH_JSON + data['file_json']):
          msg = data['file_json'] + " " + Library().client("feed_add|{}".format(data['file_json']))
        else:
          msg = "File " + data['file_json'] + " non trovato"
      else:
        msg = "Nome file non passato come argomento"
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

@app.route("/", methods=['GET', 'POST'])
def index():
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
    rcv_data = json.loads(request.args)
    rsp = post_actions(rcv_data)
      if rsp:
        return rsp
      else:
        return '200'
    else:
      return '404'

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
