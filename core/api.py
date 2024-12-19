from flask import Flask, request, render_template
from core.utils import parse_json
from core.networking import check_tcp_conn
from core.library import Library
from subprocess import PIPE, Popen
from glob import glob

import json
import os
import config

app = Flask(__name__)

def generate_conf_message():
  conf_message = [
    f"IDS: {'enabled' if config.IDS else 'disabled'}<br>",
    f"PROXY: {'enabled' if config.PROXY else 'disabled'}<br>",
    f"PROXY IP/PORT: {config.PROXY_HOST}:{config.PROXY_PORT}<br>",
    f"API: {'enabled' if config.API else 'disabled'}<br>",
    f"API IP/PORT: {config.MANAGEMENT_HOST}:{config.MANAGEMENT_PORT}<br>",
    f"DUMMY: {'enabled' if config.DUMMY else 'disabled'}<br>",
    f"DUMMY IP/PORT: {config.DUMMY_HOST}:{config.DUMMY_PORT}<br>",
  ]
  return "".join(conf_message)


def create_certificate_authority():
  for file_path in [config.CA_CRT, config.CA_KEY]:
    if os.path.exists(file_path):
      os.remove(file_path)

  commands = [
    ["openssl", "genrsa", "-out", config.CA_KEY, str(config.CA_KEY_SIZE)],
    ["openssl", "req", "-new", "-x509", "-days", "3650", "-key", config.CA_KEY, "-sha256", "-out", config.CA_CRT, "-subj", "/CN=Predator CA"],
    ["openssl", "genrsa", "-out", config.CERT_KEY, str(config.CERT_KEY_SIZE)],
  ]
  for cmd in commands:
    Popen(cmd).communicate()

  os.makedirs(config.CERT_DIR, exist_ok=True)
  for old_cert in glob(os.path.join(config.CERT_DIR, "*.pem")):
    os.remove(old_cert)

  if os.path.exists(config.CA_CRT):
    return f"Certification authority created. Download it from {config.LINK_DOWNLOAD_CA} after setting Predator as proxy."
  return "Error creating certification authority."


def handle_post_actions(data):
  func = data.get("func")
  if not func:
    return {"func": "nofunc", "msg": "No function provided"}

  if func == "help":
    return {"func": func, "msg": "threats|createca|loadjson|status|setloglevel|conf|check_ip"}
    
  library = Library()
    
  if func == "threats":
    ip = data.get("ip", "")
    return {"func": func, "msg": library.client(f"threats|{ip or 'all'}")}

  if func == "check_ip":
    ip = data.get("ip")
    if ip:
      return {"func": func, "msg": f"{ip} blacklisted: {library.client(f'blacklist_ip|{ip}')}"}
    return {"func": func, "msg": "IP not provided"}
    
  if func == "conf":
    return {"func": func, "msg": generate_conf_message()}
    
  if func == "createca":
    return {"func": func, "msg": create_certificate_authority()}
    
  if func == "loadjson":
    file_json = data.get("file_json")
    if file_json:
      file_path = os.path.join(config.PATH_JSON, file_json)
      if os.path.exists(file_path):
        return {"func": func, "msg": library.client(f"feed_add|{file_json}")}
      return {"func": func, "msg": f"File {file_json} not found"}
    return {"func": func, "msg": library.client("json_reload|")}
    
  if func == "status":
    return {"func": func, "msg": "UP"}
    
  if func == "setloglevel":
    logger_name = data.get("logger_name")
    logger_level = data.get("logger_level")
    if logger_name in config.LOGGERS["ASSOC"] and logger_level in config.LOGGERS["LEVELS"]:
      config.LOGGERS["RESOURCES"][config.LOGGERS["ASSOC"][logger_name]].set_level(logger_level)
      return {"func": func, "msg": f"Set level {logger_level} for {logger_name}"}
    return {"func": func, "msg": "Invalid logger name or level"}
    
  return {"func": func, "msg": "Unknown function"}


@app.route("/api", methods=["GET", "POST"])
def api():
  if request.method == "POST":
    rcv_data = json.loads(request.data.decode("utf-8")) if request.data else {}
    return handle_post_actions(rcv_data)

  if request.method == "GET":
    rcv_data = request.args.to_dict(flat=True)
    return handle_post_actions(rcv_data)


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
