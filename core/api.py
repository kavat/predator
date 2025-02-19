from flask import Flask, request, render_template
from core.utils import parse_json, check_tcp_conn
from core.library import Library
from subprocess import PIPE, Popen
from glob import glob

import json
import os
import config

app = Flask(__name__)

class PredatorApi: 

  def __init__(self):
    self.library = Library()

  def _handle_conf(self, data):
    conf_message = [
      f"IDS: {'enabled' if config.IDS else 'disabled'}<br>",
      f"PROXY: {'enabled' if config.PROXY else 'disabled'}<br>",
      f"PROXY IP/PORT: {config.PROXY_HOST}:{config.PROXY_PORT}<br>",
      f"API: {'enabled' if config.API else 'disabled'}<br>",
      f"API IP/PORT: {config.MANAGEMENT_HOST}:{config.MANAGEMENT_PORT}<br>",
      f"DUMMY: {'enabled' if config.DUMMY else 'disabled'}<br>",
      f"DUMMY IP/PORT: {config.DUMMY_HOST}:{config.DUMMY_PORT}<br>",
    ]
    return {"func": data['func'], "msg": "".join(conf_message)}

  def _handle_createcert(self, data):
    for file_path in [config.REVERSE_PROXY_SSL_CERT, config.REVERSE_PROXY_SSL_KEY]: 
      if os.path.exists(file_path):
        os.remove(file_path)
    
    os.makedirs(config.CERT_DIR, exist_ok=True)
    commands = [
      ["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", config.REVERSE_PROXY_SSL_KEY, "-out", config.REVERSE_PROXY_SSL_CERT, "-sha256", "-days", "3650", "-nodes", "-subj", "/C=IT/ST=Italy/L=Sesto Fiorentino/O=Predator/OU=Proxy/CN=proxy"]
    ]
    for cmd in commands:
      Popen(cmd).communicate()

    if os.path.exists(config.REVERSE_PROXY_SSL_CERT):
      return {"func": data['func'], "msg": f"Reverse Proxy ertificate created."}
    return {"func": data['func'], "msg": "Error Reverse Proxy creating certificate."}

  def _handle_createca(self, data):
    for file_path in [config.CA_CRT, config.CA_KEY]:
      if os.path.exists(file_path):
        os.remove(file_path)

    os.makedirs(config.CERT_DIR, exist_ok=True)
    commands = [
      ["openssl", "genrsa", "-out", config.CA_KEY, str(config.CA_KEY_SIZE)],
      ["openssl", "req", "-new", "-x509", "-days", "3650", "-key", config.CA_KEY, "-sha256", "-out", config.CA_CRT, "-subj", "/CN=Predator CA"],
      ["openssl", "genrsa", "-out", config.CERT_KEY, str(config.CERT_KEY_SIZE)],
    ]
    for cmd in commands:
      Popen(cmd).communicate()

    for old_cert in glob(os.path.join(config.CERT_DIR, "*.pem")):
      os.remove(old_cert)

    if os.path.exists(config.CA_CRT):
      return {"func": data['func'], "msg": f"Certification authority created. Download it from {config.LINK_DOWNLOAD_CA} after setting Predator as proxy."}
    return {"func": data['func'], "msg": "Error creating certification authority."}

  def _handle_help(self, data):
    return {"func": data['func'], "msg": "threats|createca|createcert|loadjson|status|setloglevel|conf|check_ip"}

  def _handle_threats(self, data):
    ip = data.get("ip", "")
    return {"func": data['func'], "msg": self.library.client(f"threats|{ip or 'all'}")}

  def _handle_check_ip(self, data):
    ip = data.get("ip")
    if ip:
      return {"func": data['func'], "msg": f"{ip} blacklisted: {self.library.client(f'blacklist_ip|{ip}')}"}
    return {"func": data['func'], "msg": "IP not provided"}

  def _handle_loadjson(self, data):
    file_json = data.get("file_json")
    if file_json:
      file_path = os.path.join(config.PATH_JSON, file_json)
      if os.path.exists(file_path):
        return {"func": data['func'], "msg": self.library.client(f"feed_add|{file_path}")}
      return {"func": data['func'], "msg": f"File {file_json} not found"}
    return {"func": data['func'], "msg": self.library.client("json_reload|")}

  def _handle_status(self, data):
    return {"func": data['func'], "msg": "UP"}

  def _handle_setloglevel(self, data):
    logger_name = data.get("logger_name")
    logger_level = data.get("logger_level")
    if logger_name in config.LOGGERS["ASSOC"] and logger_level in config.LOGGERS["LEVELS"]:
      config.LOGGERS["RESOURCES"][config.LOGGERS["ASSOC"][logger_name]].set_level(logger_level)
      return {"func": data['func'], "msg": f"Set level {logger_level} for {logger_name}"}
    return {"func": data['func'], "msg": "Invalid logger name or level"}

  def _handle_get_session_by_id(self, data):
    session_id = data.get("session_id")
    if session_id:
      return {"func": data['func'], "msg": self.library.client(f"get_session_by_id|{session_id}")}
    else:
      return {"func": data['func'], "msg": f"session_id missed"}

  def _handle_get_sessions(self, data):
    return {"func": data['func'], "msg": self.library.client(f"get_sessions|")}

  def handle_post_actions(self, data):
    func = data.get("func")
    if not func:
      return {"func": "nofunc", "msg": "No function provided"}

    handler_name = f"_handle_{func}"
    if hasattr(self, handler_name):
      handler = getattr(self, handler_name)
      return handler(data)
    else:
      return {"func": "no_handler", "msg": "no_handler for func {}".format(func)}


@app.route("/api", methods=["GET", "POST"])
def api():
  if request.method == "POST":
    rcv_data = json.loads(request.data.decode("utf-8")) if request.data else {}
    return PredatorApi().handle_post_actions(rcv_data)

  if request.method == "GET":
    rcv_data = request.args.to_dict(flat=True)
    return PredatorApi().handle_post_actions(rcv_data)


@app.route("/", methods=["GET"])
def index():
  return render_template("index.html", host=config.MANAGEMENT_HOST, port=config.MANAGEMENT_PORT, json_path=config.PATH_JSON)


def start_api(host, port):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger().info("Starting API...")
    app.run(host, port)
  except Exception as e:
    logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"].get_logger()
    logger.critical(f"API error: {e}", exc_info=True)
    if not check_tcp_conn(host, port):
      logger.critical(f"Restarting thread in {config.SLEEP_THREAD_RESTART} seconds...")
      time.sleep(config.SLEEP_THREAD_RESTART)
      start_api(host, port)
