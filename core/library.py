import config
import socket
import os
import time
import json
import geoip2.database

from threading import Lock
from core.common_utils import (
  id_generator,
  parse_json,
  parse_json_array
)

class Library:

  def __init__(self):
    self.blacklist_ip = {}
    self.blacklist_ip_lock = Lock()
    self.blacklist_fqdn = {}
    self.blacklist_fqdn_lock = Lock()
    self.pattern_tcp_udp = []
    self.pattern_tcp_udp_lock = Lock()
    self.whitelist = {}
    self.whitelist_lock = Lock()
    self.dns = {}
    self.dns_lock = Lock()
    self.threats = {}
    self.threats_lock = Lock()
    try:
      self.geoloc_db = geoip2.database.Reader(config.PATH_MMDB)
    except:
      self.geoloc_db = False
    self.geoloc_db_lock = Lock()

  def geoloc_ip(self, ip):
    ritorno = {'country':'ND', 'city':'ND', 'latitude':'ND', 'longitude':'ND'}
    try:
      if self.geoloc_db != False:
        response = self.geoloc_db.city(ip)
        ritorno = {'country':response.country.name, 'city':response.city.name, 'latitude':response.location.latitude, 'longitude':response.location.longitude}
    except geoip2.errors.AddressNotFoundError:
      ritorno = {'country':'ND', 'city':'ND', 'latitude':'ND', 'longitude':'ND'}
    return ritorno

  def init_rules(self):
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("Carico le regole..")
    for file_json in list(os.listdir(config.PATH_JSON)):
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("Carico il file " + file_json)
      chiave = file_json.split(".")[0]
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("Carico " + chiave + " da " + config.PATH_JSON + file_json)
      if(file_json == "whitelist.json"):
        self.upd_whitelist(parse_json(config.PATH_JSON + file_json))
      elif(file_json == "dns.json"):
        self.upd_dns(parse_json(config.PATH_JSON + file_json))
      elif file_json == "hole_cert_fqdn.json":
        self.upd_blacklist_fqdn(parse_json(config.PATH_JSON + file_json))
      elif file_json == "patterns_tcp_udp.json":
        self.upd_pattern_tcp_udp(parse_json_array(config.PATH_JSON + file_json))
      elif(file_json.endswith("_ip.json")):
        self.upd_blacklist_ip(parse_json(config.PATH_JSON + file_json))
      elif(file_json.endswith("_fqdn.json")):
        self.upd_blacklist_fqdn(parse_json(config.PATH_JSON + file_json))
      elif(file_json == "tor_nodes.json"):
        self.upd_blacklist_ip(parse_json(config.PATH_JSON + file_json))
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().warn("Scarto il file " + config.PATH_JSON + file_json)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("WHITELIST: " + str(len(self.whitelist)))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("BLACKLIST_IP: " + str(len(self.blacklist_ip)))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("BLACKLIST_FQDN: " + str(len(self.blacklist_fqdn)))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("DNS: " + str(len(self.dns)))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("Caricati json")

  def server(self):
    self.init_rules()
    try:
      os.unlink(config.SOCKET_LIBRARY)
    except OSError:
      if os.path.exists(config.SOCKET_LIBRARY):
        raise

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(config.SOCKET_LIBRARY)

    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info('Server is listening for incoming connections...')
    while True:
      try:
        data, addr = server.recvfrom(4096)
        if addr is not None:
          ricevuto = data.decode('utf-8')
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().debug("BUFFER RICEVUTO {}".format(ricevuto))
          client = ricevuto.split("|")[0]
          func = ricevuto.split("|")[1]
          messaggio = ricevuto.split("|")[2]
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().debug("Ricevuto da {}: {} - {}".format(client, func, messaggio))
          inviato = "no_func"
          if func == "json_reload":
            inviato = "ack"
            self.init_rules()
          if func == "feed_add":
            if os.path.exists(config.PATH_JSON + messaggio):
              inviato = "ack"
              if messaggio == "whitelist.json":
                self.upd_whitelist(parse_json(config.PATH_JSON + messaggio))
              elif messaggio == "dns.json":
                self.upd_dns(parse_json(config.PATH_JSON + messaggio))
              elif messaggio == "hole_cert_fqdn.json":
                self.upd_blacklist_fqdn(parse_json(config.PATH_JSON + messaggio))
              elif messaggio == "patterns_tcp_udp.json":
                self.upd_pattern_tcp_udp(parse_json_array(config.PATH_JSON + messaggio))
              elif messaggio.endswith("_ip.json"):
                self.upd_blacklist_ip(parse_json(config.PATH_JSON + messaggio))
              elif messaggio.endswith("_fqdn.json"):
                self.upd_blacklist_fqdn(parse_json(config.PATH_JSON + messaggio))
              else:
                inviato = "file_unknown"
            else:
              inviato = "no_file"
          if func == "whitelist":
            if messaggio in self.whitelist:
              inviato = self.whitelist[messaggio]
            else:
              inviato = "no"
          if func == "whitelist_fqdn_servernames":
            if messaggio in self.whitelist["fqdn"]["servernames"]:
              inviato = self.whitelist["fqdn"]["servernames"]["messaggio"]
            else:
              inviato = "no"
          if func == "whitelist_fqdn_all_static":
            if messaggio in self.whitelist["fqdn"]["all"]["static"]:
              inviato = self.whitelist["fqdn"]["all"]["static"][messaggio]
            else:
              inviato = "no"
          if func == "whitelist_fqdn_dns_requests":
            if messaggio in self.whitelist["dns_requests"]:
              inviato = self.whitelist["dns_requests"][messaggio]
            else:
              inviato = "no"
          if func == "whitelist_layer4":
            if messaggio in self.whitelist["layer4"]:
              inviato = self.whitelist["layer4"][messaggio]
            else:
              inviato = "no"
          if func == "whitelist_fqdn":
            if messaggio in self.whitelist["fqdn"]:
              inviato = self.whitelist["fqdn"][messaggio]
            else:
              inviato = "no"
          if func == "whitelist_fqdn_all_static":
            if messaggio in self.whitelist["fqdn"]["all"]["static"]:
              inviato = self.whitelist["fqdn"]["all"]["static"][messaggio]
            else:
              inviato = "no"
          if func == "pattern_tcp_udp":
            inviato = "|".join(self.pattern_tcp_udp)
          if func == "get_whitelist_fqdn_all_wild":
            inviato = "|".join(self.whitelist["fqdn"]["all"]["wild"])
          if func == "get_whitelist_fqdn_servernames":
            inviato = "|".join(self.whitelist["fqdn"]["servernames"])
          if func == "blacklist_ip":
            if messaggio in self.blacklist_ip:
              inviato = self.blacklist_ip[messaggio]
            else:
              inviato = "no"
          if func == "blacklist_fqdn":
            if messaggio in self.blacklist_fqdn:
              inviato = self.blacklist_fqdn[messaggio]
            else:
              inviato = "no"
          if func == "dns":
            if messaggio in self.dns:
              inviato = json.dumps(self.dns[messaggio])
            else:
              inviato = "no"
          if func == "dns_add":
            qname = ricevuto.split("|")[3] 
            percorso = ricevuto.split("|")[4] 
            a_d = {messaggio:{qname:percorso}}
            self.upd_dns(a_d)
            inviato = "ack"
          if func == "add_threat":
            inviato = "ack"
            src = messaggio.split(",")[0]
            dst = messaggio.split(",")[1]
            sport = messaggio.split(",")[2]
            dport = messaggio.split(",")[3]
            protocol = messaggio.split(",")[4]
            flags = messaggio.split(",")[5]
            event = messaggio.split(",")[6]
            evento = {"timestamp":round(time.time()), "src":src, "dst":dst, "sport":sport, "dport":dport, "protocol":protocol, "flags":flags, "event":event, "geo_src":self.geoloc_ip(src), "geo_dst":self.geoloc_ip(dst)}
            self.upd_threats(evento)
          if func == "threats":
            threats_list = []
            if messaggio == "all":
              inviato = "Threats no filtered<br>"
              threats_list = self.threats
            else:
              inviato = "Threats filtered for {}<br>".format(messaggio)
              if messaggio in self.threats:
                threats_list[messaggio] = self.threats[messaggio]
            if len(threats_list) == 0:
              inviato = "{}no_data".format(inviato)
            else:
              inviato = "{}<br><table cellspacing=0 cellpadding=0 border=1><tr><td>TIMESTAMP</td><td>SRC</td><td>DST</td><td>PROTOCOL</td><td>FLAGS</td><td>EVENT</td></tr>".format(inviato)  
              for ip in threats_list:
                for threat in threats_list[ip]:
                  inviato = "{}<tr><td>{}</td><td>{}:{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(inviato, threat["timestamp"], threat["src"], threat["sport"], threat["dst"], threat["dport"], threat["protocol"], threat["flags"], threat["event"])
              inviato = "{}</table>".format(inviato)
          server.sendto(str.encode(inviato), client)
      except BlockingIOError:
        pass

    os.unlink(socket_path)

  def client(self, messaggio, json_r=False):
    client_socket = "{}/{}.sock".format(config.SOCKET_LIBRARY_BASE_CLIENT, id_generator(10))
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.bind(client_socket)
    client.sendto(str.encode("{}|{}".format(client_socket, messaggio)), config.SOCKET_LIBRARY)

    response = client.recv(4096)
    ritorno = response.decode()
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().debug(f'Received response: {ritorno}')

    client.close()
    os.unlink(client_socket)

    if json_r == True:
      return json.loads(ritorno)
    else:
      return ritorno

  def upd_blacklist_ip(self, cnt):
    with self.blacklist_ip_lock:
      self.blacklist_ip.update(cnt)

  def upd_blacklist_fqdn(self, cnt):
    with self.blacklist_fqdn_lock:
      self.blacklist_fqdn.update(cnt)

  def upd_whitelist(self, cnt):
    with self.whitelist_lock:
      self.whitelist.update(cnt)

  def upd_dns(self, cnt):
    with self.dns_lock:
      self.dns.update(cnt)

  def upd_pattern_tcp_udp(self, cnt):
    with self.pattern_tcp_udp_lock:
      self.pattern_tcp_udp = cnt

  def upd_threats(self, cnt):
    with self.threats_lock:
      if cnt['src'] not in self.threats:
        self.threats[cnt['src']] = []
      self.threats[cnt['src']].append(cnt)
      if cnt['dst'] not in self.threats:
        self.threats[cnt['dst']] = []
      self.threats[cnt['dst']].append(cnt)

def start_library_server():
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().info("STARTING LIBRARY")
    server_library = Library()
    server_library.server()
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().critical("Tra " + str(config.SLEEP_THREAD_RESTART) + " riavvio il thread")
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("start_library_server() BOOM!!!")
    time.sleep(config.SLEEP_THREAD_RESTART)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"].get_logger().critical("Riavvio thread")
    start_library_server()
