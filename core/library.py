import config
import socket
import os
import time
import json
import geoip2.database

from threading import Lock
from typing import Dict, List, Union
from core.common_utils import (
  id_generator,
  parse_json,
  parse_json_array,
  b642string,
  get_curdatetime
)

class Library:
  def __init__(self):
    self.blacklist_ip: Dict[str, str] = {}
    self.blacklist_ip_lock = Lock()

    self.blacklist_fqdn: Dict[str, str] = {}
    self.blacklist_fqdn_lock = Lock()

    self.pattern_tcp_udp: List[str] = []
    self.pattern_tcp_udp_lock = Lock()

    self.whitelist: Dict[str, Union[str, Dict]] = {}
    self.whitelist_lock = Lock()

    self.dns: Dict[str, Dict] = {}
    self.dns_lock = Lock()

    self.threats: Dict[str, List[Dict]] = {}
    self.threats_lock = Lock()

    self.session_content: Dict[str, Dict] = {}
    self.session_content_lock = Lock()

    self.geoloc_db = self._initialize_geolocation_db()

  def _initialize_geolocation_db(self):
    try:
      return geoip2.database.Reader(config.PATH_MMDB)
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().error(
        f"Error initializing GeoIP database: {e}"
      )
    return None

  def geoloc_ip(self, ip: str) -> Dict[str, Union[str, float]]:
    default_response = {"country": "ND", "city": "ND", "latitude": "ND", "longitude": "ND"}
    if not self.geoloc_db:
      return default_response

    try:
      response = self.geoloc_db.city(ip)
      return {
        "country": response.country.name,
        "city": response.city.name,
        "latitude": response.location.latitude,
        "longitude": response.location.longitude,
      }
    except geoip2.errors.AddressNotFoundError:
      return default_response

  def init_rules(self):
    logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger()
    logger.info("Loading rules...")

    for file_name in os.listdir(config.PATH_JSON):
      file_path = os.path.join(config.PATH_JSON, file_name)
      logger.info(f"Processing file: {file_path}")

      try:
        if file_name == "whitelist.json":
          self.upd_whitelist(parse_json(file_path))
        elif file_name == "dns.json":
          self.upd_dns(parse_json(file_path))
        elif file_name == "hole_cert_fqdn.json":
          self.upd_blacklist_fqdn(parse_json(file_path))
        elif file_name == "patterns_tcp_udp.json":
          self.upd_pattern_tcp_udp(parse_json_array(file_path))
        elif file_name.endswith("_ip.json"):
          self.upd_blacklist_ip(parse_json(file_path))
        elif file_name.endswith("_fqdn.json"):
          self.upd_blacklist_fqdn(parse_json(file_path))
        elif file_name == "tor_nodes.json":
          self.upd_blacklist_ip(parse_json(file_path))
        else:
          logger.warning(f"Ignoring unknown file: {file_name}")
      except Exception as e:
        logger.error(f"Error processing file {file_name}: {e}")

    logger.info(f"WHITELIST: {len(self.whitelist)}")
    logger.info(f"BLACKLIST_IP: {len(self.blacklist_ip)}")
    logger.info(f"BLACKLIST_FQDN: {len(self.blacklist_fqdn)}")
    logger.info(f"DNS: {len(self.dns)}")
    logger.info("Rules loaded successfully.")

  def server(self):

    if config.IDS == True:
      self.init_rules()

    try:
      os.unlink(config.SOCKET_LIBRARY)
    except FileNotFoundError:
      pass
    except OSError as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().critical(
        f"Error unlinking socket: {e}"
      )
      raise

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(config.SOCKET_LIBRARY)

    logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger()
    logger.info("Server is listening for incoming connections...")

    while True:
      try:
        data, addr = server.recvfrom(4096)
        if addr:
          response = self._handle_request(data.decode("utf-8"))
          server.sendto(response.encode("utf-8"), addr)
      except BlockingIOError:
        continue
      except Exception as e:
        logger.error(f"Error handling request: {e}")

  def _handle_request(self, data: str) -> str:
    logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger()
    logger.debug(f"Received data: {data}")

    try:
      client, func, message = data.split("|", 2)
      logger.debug(f"Client: {client}, Func: {func}, Message: {message}")

      handler_name = f"_handle_{func}"
      if hasattr(self, handler_name):
        handler = getattr(self, handler_name)
        return handler(message)
      else:
        return "no_handler for func {}".format(func)
    except Exception as e:
      logger.critical(e, exc_info=True)
      return "error"

  def _handle_dns_add(self, message: str) -> str:
    key = message.split("___")[0]
    qname = message.split("___")[1]
    way = message.split("___")[2]
    a_d = {key:{qname:way}}
    self.upd_dns(a_d)
    return "ack"

  def _handle_feed_add(self, message: str) -> str:
    logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger()
    if os.path.exists(message):
      if message.endswith("whitelist.json"):
        self.upd_whitelist(parse_json(message))
      elif message.endswith("dns.json"):
        self.upd_dns(parse_json(message))
      elif message.endswith("hole_cert_fqdn.json"):
        self.upd_blacklist_fqdn(parse_json(message))
      elif message.endswith("patterns_tcp_udp.json"):
        self.upd_pattern_tcp_udp(parse_json_array(message))
      elif message.endswith("_ip.json"):
        self.upd_blacklist_ip(parse_json(message))
      elif message.endswith("_fqdn.json"):
        self.upd_blacklist_fqdn(parse_json(message))
      elif message.endswith("tor_nodes.json"):
        self.upd_blacklist_ip(parse_json(message))
      else:
        logger.warning(f"Ignoring unknown file: {message}")
        return "file_unknown"
    else:
      return "no_file"
    return "ack"

  def _handle_whitelist(self, message: str) -> str:
    if message in self.whitelist:
      return "yes"
    else:
      return "no"

  def _handle_whitelist_fqdn_all_static(self, message: str) -> str:
    if message in self.whitelist["fqdn"]["all"]["static"]:
      return "yes"
    else:
      return "no"

  def _handle_whitelist_fqdn_dns_requests(self, message: str) -> str:
    if message in self.whitelist["fqdn"]["dns_requests"]:
      return "yes"
    else:
      return "no"

  def _handle_whitelist_layer4(self, message: str) -> str:
    if message in self.whitelist["layer4"]:
      return self.whitelist["layer4"][message]
    else:
      return "no"

  def _handle_whitelist_fqdn(self, message: str) -> str:
    if message in self.whitelist["fqdn"]:
      return "yes"
    else:
      return "no"

  def _handle_pattern_tcp_udp(self, message: str) -> str:
    return "|".join(self.pattern_tcp_udp)

  def _handle_get_whitelist_fqdn_all_wild(self, message: str) -> str:
    return "|".join(self.whitelist["fqdn"]["all"]["wild"])

  def _handle_get_whitelist_fqdn_servernames(self, message: str) -> str:
    return "{}|{}".format("|".join(self.whitelist["fqdn"]["all"]["static"]),"|".join(self.whitelist["fqdn"]["all"]["wild"]))

  def _handle_blacklist_ip(self, message: str) -> str:
    if message in self.blacklist_ip:
      return self.blacklist_ip[message]
    else:
      return "no"

  def _handle_blacklist_fqdn(self, message: str) -> str:
    if message in self.blacklist_fqdn:
      return self.blacklist_fqdn[message]
    else:
      return "no"

  def _handle_dns(self, message: str) -> str:
    if message in self.dns:
      return json.dumps(self.dns[message])
    else:
      return "no"

  def _handle_add_threat(self, message: str) -> str:
    src = message.split(",")[0]
    dst = message.split(",")[1]
    sport = message.split(",")[2]
    dport = message.split(",")[3]
    protocol = message.split(",")[4]
    flags = message.split(",")[5]
    host = message.split(",")[6]
    sni = message.split(",")[7]
    report = message.split(",")[8]
    event = message.split(",")[9]
    evento = {
      "timestamp": round(time.time()), 
      "src": src, 
      "dst": dst, 
      "sport": sport, 
      "dport": dport,
      "protocol": protocol,
      "flags":flags,
      "event": event, 
      "geo_src": self.geoloc_ip(src), 
      "geo_dst": self.geoloc_ip(dst), 
      "host": host, 
      "sni": sni, 
      "report": report
    }
    self.upd_threats(evento)
    return "ack"

  def _handle_threats(self, message: str) -> str:
    buffer = ""
    threats_list = []
    if message == "all":
      buffer = "Threats no filtered<br>"
      threats_list = self.threats
    else:
      buffer = "Threats filtered for {}<br>".format(message)
      if message in self.threats:
        threats_list[message] = self.threats[message]
    if len(threats_list) == 0:
      buffer = "{}no_data".format(buffer)
    else:
      buffer = "{}<br><table cellspacing=0 cellpadding=0 border=1><tr><td>TIMESTAMP</td><td>SRC</td><td>DST</td><td>PROTOCOL</td><td>FLAGS</td><td>EVENT</td><td>REPORT</td><td>HOST</td><td>SNI</td></tr>".format(buffer)
      for ip in threats_list:
        for threat in threats_list[ip]:
          buffer = "{}<tr><td>{}</td><td>{}:{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(buffer, threat["timestamp"], threat["src"], threat["sport"], threat["dst"], threat["dport"], threat["protocol"], threat["flags"], threat["event"], threat["report"], threat["host"], threat["sni"])
      buffer = "{}</table>".format(buffer)
    return buffer

  def _handle_json_reload(self, message: str) -> str:
    self.init_rules()
    return "ack"

  def _handle_delete_session_by_id(self, message: str) -> str:
    id_connection =message.split(",")[0]
    with self.session_content_lock:
      if id_connection in self.session_content:
        del self.session_content[id_connection]
    return "ack"

  def _handle_add_content_session(self, message: str) -> str:
    src = message.split(",")[0]
    dst = message.split(",")[1]
    content_session_id = message.split(",")[2]
    content_session = message.split(",")[3]
    with self.session_content_lock:
      if content_session_id not in self.session_content:
        self.session_content[content_session_id] = {
          'content': [],
          'first_packet': get_curdatetime(), 
          'chiave1': "{}_{}".format(src, dst),
          'chiave2': "{}_{}".format(dst, src)
        }
      self.session_content[content_session_id]['content'].append(content_session)
    return "ack"

  def _handle_get_sessions(self, message: str) -> str:
    r = []
    for session_id in self.session_content:
      r.append(session_id)
    return "L7 sessions list:<br>{}".format('<br>'.join(r)) if len(r) > 0 else "L7 sessions list:<br>no_data"

  def _handle_get_session_by_id(self, message: str) -> str:
    if message in self.session_content:
      apply_function = lambda arr, func: list(map(func, arr))
      print(self.session_content[message])
      return "L7 session {} <br>first_packet: {}<br>flow: {}<br>content:<br>{}".format(message, self.session_content[message]['first_packet'], self.session_content[message]['chiave1'], '<br>'.join(apply_function(self.session_content[message]['content'], lambda x: b642string(x))))
    return "L7 session {} content:<br>no_data".format(message)

  def client(self, message: str, json_r: bool = False) -> Union[str, dict]:
    client_socket = f"{config.SOCKET_LIBRARY_BASE_CLIENT}/{id_generator(10)}.sock"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.bind(client_socket)

    try:
      client.sendto(f"{client_socket}|{message}".encode("utf-8"), config.SOCKET_LIBRARY)
      response = client.recv(4096).decode("utf-8")
      return json.loads(response) if json_r else response
    finally:
      client.close()
      os.unlink(client_socket)

  def upd_blacklist_ip(self, cnt: Dict[str, str]):
    with self.blacklist_ip_lock:
      self.blacklist_ip.update(cnt)

  def upd_blacklist_fqdn(self, cnt: Dict[str, str]):
    with self.blacklist_fqdn_lock:
      self.blacklist_fqdn.update(cnt)

  def upd_whitelist(self, cnt: Dict[str, Union[str, Dict]]):
    with self.whitelist_lock:
      self.whitelist.update(cnt)

  def upd_dns(self, cnt: Dict[str, Dict]):
    with self.dns_lock:
      self.dns.update(cnt)

  def upd_pattern_tcp_udp(self, cnt: List[str]):
    with self.pattern_tcp_udp_lock:
      self.pattern_tcp_udp = cnt

  def upd_threats(self, cnt: Dict):
    with self.threats_lock:
      for key in ("src", "dst"):
        if cnt[key] not in self.threats:
          self.threats[cnt[key]] = []
        self.threats[cnt[key]].append(cnt)


def start_library_server():
  logger = config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger()
  try:
    logger.info("Starting Library Server...")
    Library().server()
  except Exception as e:
    logger.critical(f"Server crashed: {e}", exc_info=True)
    logger.info(f"Restarting server in {config.SLEEP_THREAD_RESTART} seconds...")
    time.sleep(config.SLEEP_THREAD_RESTART)
    start_library_server()
