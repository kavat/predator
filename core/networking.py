from scapy.all import *
from threading import Lock

from core.library import Library
from core.utils import (
  id_generator,
  get_type_ip_fqdn_warn,
  net_whitelisted,
  check_domain_whitelisted,
  static_fqdn_checks,
  check_domain_dns_whitelisted,
  inspect_packet_content,
  print_connection_content,
  check_connection_content,
  check_if_ip_is_in_cidrs,
  get_connection_content_size,
  get_connection_content_session_id,
  is_ip_checkable,
  is_malicious_host,
  is_ip_checkable_library,
  is_malicious_host_library,
  check_tcp_conn,
  get_curdatetime,
  ip_is_checkable
)
from core.common_utils import (
  parse_json,
  parse_json_array,
  get_string_md5,
  append_json_threat,
  string2b64,
  split_array
)
from core.logging import PredatorLogger

import os
import config
import time
import syslog
import ipaddress
import socket
import redis

class PredatorPacketAnalysis:

  def __init__(self, filter_string, label):
    self.filter_string = filter_string
    self.label = label
    self.matrix_connections = {}
    self.matrix_connections_lock = Lock()
    self.upd_lock = Lock()
    self.packets_stored = 0
    self.packets_managed = 0
    self.redis = redis.Redis(host="127.0.0.1", port=6379)
    self.redis_pipeline = self.redis.pipeline()

    self.blacklist_ip: Dict[str, str] = {}
    self.blacklist_fqdn: Dict[str, str] = {}
    self.pattern_tcp_udp: List[str] = []
    self.whitelist: Dict[str, Union[str, Dict]] = {}
    self.dns: Dict[str, Dict] = {}
    self.init_rules()

  def init_rules(self):

    for file_name in os.listdir(config.PATH_JSON):
      file_path = os.path.join(config.PATH_JSON, file_name)

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
        elif file_name == "suricata.json":
          self.upd_blacklist_ip(parse_json(file_path))
        else:
          print(f"Ignoring unknown file: {file_name}")
      except Exception as e:
        print(f"Error processing file {file_name}: {e}")

  def upd_blacklist_ip(self, cnt: Dict[str, str]):
    self.blacklist_ip.update(cnt)

  def upd_blacklist_fqdn(self, cnt: Dict[str, str]):
    self.blacklist_fqdn.update(cnt)

  def upd_whitelist(self, cnt: Dict[str, Union[str, Dict]]):
    self.whitelist.update(cnt)

  def upd_dns(self, cnt: Dict[str, Dict]):
    self.dns.update(cnt)

  def upd_pattern_tcp_udp(self, cnt: List[str]):
    self.pattern_tcp_udp = cnt

  def print_matrix(self, flags):
    print("PRINT POST " + flags)
    print(self.matrix_connections)
    print("------------------------------------------------")

  def get_handler(self):
    return self

  def get_num_packets(self):
    return self.packets_managed

  def add_threat_l7(self, ip1, port1, ip2, port2, proto, flags, type_threat, type_flow, content_whitelisted, content_size, content_session_id, reporting, sni, host, payload):
    if type_flow == "dst":
      (src_ip, src_port, dst_ip, dst_port) = ip2, port2, ip1, port1
    else:
      (src_ip, src_port, dst_ip, dst_port) = ip1, port1, ip2, port2
    Library().client("add_threat|{},{},{},{},{},{},{},{},static_patterns,{}".format(src_ip, dst_ip, src_port, dst_port, proto, flags, host, sni, type_threat))
    stringa_log = "LOG=PREDATOR_THREAT SRC={} SPORT={} DST={} DPORT={} PROTO={} FLAGS={} WHITELISTED_CONTENT={} CONTENT_SIZE={} CONTENT_SESSION_ID={} EVENT={}_{} REPORTING={} SNI={} HOST={} PAYLOAD={}".format(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)

    if config.SEND_TO_SQLITE == True:
      from core.sqlite import SQLite
      SQLite().write_threat_l7(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload)
    if config.SEND_TO_SYSLOG == True:
      syslog.syslog(stringa_log)
    if config.SEND_TO_ES == True:
      from core.elk import Elk
      Elk(config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"]).write_threat_l7(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload)
    if config.SEND_TO_LOCAL_JSON == True:
      with self.upd_lock:
        append_json_threat(get_string_md5(self.filter_string), {
          'src_ip': src_ip,
          'src_port': src_port,
          'dst_ip': dst_ip,
          'dst_port': dst_port,
          'protocol': proto,
          'flags': flags,
          'content_whitelisted': content_whitelisted,
          'content_size': content_size,
          'content_session_id': content_session_id,
          'event': "{}_{}".format(type_threat, type_flow),
          'reporting': reporting,
          'sni': sni,
          'host': host,
          'payload': payload
        })

  def add_threat_l4(self, ip1, port1, ip2, port2, proto, flags, type_threat, type_flow, content_whitelisted, content_size, content_session_id, reporting, sni, host, handshake_type, tls_session_id, pe_file):
    if type_flow == "dst":
      (src_ip, src_port, dst_ip, dst_port) = ip2, port2, ip1, port1
    else:
      (src_ip, src_port, dst_ip, dst_port) = ip1, port1, ip2, port2
    Library().client("add_threat|{},{},{},{},{},{},{},{},{},{}".format(src_ip, dst_ip, src_port, dst_port, proto, flags, host, sni, reporting, type_threat))
    stringa_log = "LOG=PREDATOR_THREAT SRC={} SPORT={} DST={} DPORT={} PROTO={} FLAGS={} WHITELISTED_CONTENT={} CONTENT_SIZE={} CONTENT_SESSION_ID={} EVENT={}_{} REPORTING={} PE_FILE={} HANDSHAKE_TYPE={} TLS_SESSION_ID={} SNI={} HOST={}".format(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, pe_file, handshake_type, tls_session_id, sni, host)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)

    if config.SEND_TO_SQLITE == True:
      from core.sqlite import SQLite
      SQLite().write_threat_l4(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host)
    if config.SEND_TO_SYSLOG == True:
      syslog.syslog(stringa_log)
    if config.SEND_TO_ES == True:
      from core.elk import Elk
      Elk(config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"]).write_threat_l4(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host)
    if config.SEND_TO_LOCAL_JSON == True:
      with self.upd_lock:
        append_json_threat(get_string_md5(self.filter_string), {
          'src_ip': src_ip,
          'src_port': src_port,
          'dst_ip': dst_ip,
          'dst_port': dst_port,
          'protocol': proto,
          'flags': flags,
          'content_whitelisted': content_whitelisted,
          'content_size': content_size,
          'content_session_id': content_session_id,
          'event': "{}_{}".format(type_threat, type_flow),
          'reporting': reporting,
          'sni': sni,
          'host': host
        })

  def add_threat_dns(self, pkt, sport, dport, proto, event, rdata, qname):
    stringa_log = "LOG=PREDATOR_THREAT SRC={} SPORT={} DST={} DPORT={} PROTO={} FLAGS=ND WHITELISTED_CONTENT=N REPORTING={} EVENT={} RDATA={} FQDN={}".format(pkt[IP].src, sport, pkt[IP].dst, dport, proto, get_type_ip_fqdn_warn("", qname), event, rdata, qname)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)

    if config.SEND_TO_SYSLOG == True:
      syslog.syslog(stringa_log)
    if config.SEND_TO_SQLITE == True:
      from core.sqlite import SQLite
      SQLite().write_threat_dns(pkt[IP].src, sport, pkt[IP].dst, dport, proto, get_type_ip_fqdn_warn("", qname), event, rdata, qname)
    if config.SEND_TO_ES:
      from core.elk import Elk
      Elk(config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"]).write_threat_dns(pkt[IP].src, sport, pkt[IP].dst, dport, proto, get_type_ip_fqdn_warn("", qname), event, rdata, qname)
    if config.SEND_TO_LOCAL_JSON == True:
      with self.upd_lock:
        append_json_threat(get_string_md5(self.filter_string), {
          'src_ip': pkt[IP].src,
          'src_port': sport,
          'dst_ip': pkt[IP].dst,
          'dst_port': dport,
          'protocol': proto,
          'event': event,
          'reporting': get_type_ip_fqdn_warn("", qname),
          'rdata': rdata,
          'qname': qname
        })

  def add_content_session(self, src_ip, src_port, dst_ip, dst_port, content_session_id, content_session):
    Library().client("add_content_session|{}:{},{}:{},{},{}".format(src_ip, src_port, dst_ip, dst_port, content_session_id, string2b64(content_session)))

  def get_matrix_connections(self):
    return self.matrix_connections

  def init_matrix_connection(self, p1, p2, p3, p4, label, flags):
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("P1 {} P2 {} P3 {} P4 {}".format(p1, p2, p3, p4))
    try:
      with self.matrix_connections_lock:
        session_id = self.matrix_connections[p1][p2][p3][p4]['id_connection']
        content = self.matrix_connections[p1][p2][p3][p4]['content']
        size_content = self.matrix_connections[p1][p2][p3][p4]['size_content']
        session_datetime = self.matrix_connections[p1][p2][p3][p4]['datetime']
    except:
      try:
        with self.matrix_connections_lock:
          session_id = self.matrix_connections[p3][p4][p1][p2]['id_connection']
          content = self.matrix_connections[p3][p4][p1][p2]['content']
          size_content = self.matrix_connections[p3][p4][p1][p2]['size_content']
          session_datetime = self.matrix_connections[p3][p4][p1][p2]['datetime']
      except:
        session_id = id_generator(30)
        size_content = 0
        content = []
        session_datetime = get_curdatetime()
    try:
      if p1 not in self.matrix_connections:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("P1 {} non presente sopra".format(p1))
        with self.matrix_connections_lock:
          self.matrix_connections[p1] = {}
      if p2 not in self.matrix_connections[p1]:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("P2 {} non presente sopra".format(p2))
        with self.matrix_connections_lock:
          self.matrix_connections[p1][p2] = {}
      if p3 not in self.matrix_connections[p1][p2]:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("P3 {} non presente sopra".format(p3))
        with self.matrix_connections_lock:
          self.matrix_connections[p1][p2][p3] = {}
      if p4 not in self.matrix_connections[p1][p2][p3]:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("P4 {} non presente sopra".format(p4))
        with self.matrix_connections_lock:
          self.matrix_connections[p1][p2][p3][p4] = {}
          self.matrix_connections[p1][p2][p3][p4]['content'] = content
          self.matrix_connections[p1][p2][p3][p4]['size_content'] = size_content
          self.matrix_connections[p1][p2][p3][p4]['id_connection'] = session_id
          self.matrix_connections[p1][p2][p3][p4]['datetime'] = session_datetime
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().debug("Created session {} {} for {}:{}:{}:{} [{}]".format(label, flags, p1, p2, p3, p4, session_id))
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("{} received, error creating session {} for {}:{}:{}:{}".format(label, flags, p1, p2, p3, p4))
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("init_matrix_connection() BOOM!!!")

  def end_matrix_connection(self, p1, p2, p3, p4, label, flags):
    try:
      if p1 in self.matrix_connections:
        if p2 in self.matrix_connections[p1]:
          if p3 in self.matrix_connections[p1][p2]:
            if p4 in self.matrix_connections[p1][p2][p3]:
              if 'id_connection' in self.matrix_connections[p1][p2][p3][p4]:
                id_connection = self.matrix_connections[p1][p2][p3][p4]['id_connection']
                Library().client("delete_session_by_id|{}".format(id_connection))
              else:
                config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().error("Connection {}:{} -> {}:{} without id_connection".format(p1, p2, p3, p4))
              with self.matrix_connections_lock:
                del self.matrix_connections[p1][p2][p3][p4]
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("{} received, error ending session {} for {}:{}:{}:{}".format(label, flags, p1, p2, p3, p4))
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("end_matrix_connection() BOOM!!!")

  def append_content_matrix_connection(self, p1, p2, p3, p4, content, label):
    try:
      if p1 in self.matrix_connections:
        if p2 in self.matrix_connections[p1]:
          if p3 in self.matrix_connections[p1][p2]:
            if p4 in self.matrix_connections[p1][p2][p3]:
              for content_line in content.split("\n"):
                with self.matrix_connections_lock:
                  self.matrix_connections[p1][p2][p3][p4]['content'].append(content_line)
                with self.matrix_connections_lock:
                  self.add_content_session(p1, p2, p3, p4, self.matrix_connections[p1][p2][p3][p4]['id_connection'], content_line)
              if 'size_content' not in self.matrix_connections[p1][p2][p3][p4]:
                with self.matrix_connections_lock:
                  self.matrix_connections[p1][p2][p3][p4]['size_content'] = 0
              for content_line in self.matrix_connections[p1][p2][p3][p4]['content']:
                with self.matrix_connections_lock:
                  self.matrix_connections[p1][p2][p3][p4]['size_content'] += len(content_line)
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("{} received, error appending session {}:{}:{}:{}".format(label, p1, p2, p3, p4))
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("append_content_matrix_connection() BOOM!!!")

  def init_matrix_connections(self):
    with self.matrix_connections_lock:
      self.matrix_connections = {}

  def tcp_flag_fr(self, packet, flags, ip_check, port_check, ip2, port2, proto, type_flow):
    if "F" in flags or "R" in flags:
      #print_connection_content(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(type_flow), flags)
      #print_connection_content(self.get_handler(), ip2, port2, ip_check, port_check, "evil_{}".format(type_flow), flags)
      self.end_matrix_connection(ip_check, port_check, ip2, port2, "evil_{}".format(type_flow), flags)
      self.end_matrix_connection(ip2, port2, ip_check, port_check, "evil_{}".format(type_flow), flags)
      #self.print_matrix(flags)

  def tcp_flag_p(self, packet, flags, ip_check, port_check, ip2, port2, proto, type_flow, content_tls):
    if 'P' in flags and 'Raw' in packet:
      packet_content = ""
      if content_tls == False:
        try:
          packet_content = packet[Raw].load.decode('latin-1')
        except Exception as ed:
          packet_content = ""
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error decoding payload for evil_{} {} {}:{} -> {}:{} = {}".format(type_flow, flags, ip_check, port_check, ip2, port2, ed))
      if packet_content != "":
        self.append_content_matrix_connection(ip_check, port_check, ip2, port2, packet[Raw].load.decode('latin-1'), "evil_{}".format(type_flow))
        self.append_content_matrix_connection(ip2, port2, ip_check, port_check, packet[Raw].load.decode('latin-1'), "evil_{}".format(type_flow))
        check_content_packet = inspect_packet_content(packet_content)
        type_reporting = "static_patterns"
        if check_content_packet != "":
          self.add_threat_l7(ip_check, port_check, ip2, port2, proto, flags, "L7", check_content_packet)
        #self.print_matrix(flags)

  def get_host_from_packet_raw(self, packet):
    try:
      if Raw in packet:
        packet_content = packet[Raw].load.decode('latin-1')
        for riga in packet_content.split("\n"):
          if riga.strip() != "":
            if riga.strip().lower().startswith('host') == True:
              return (riga.strip().replace("host: ", ""), len(packet_content))
    except:
      pass
    return ("", 0)

  def dns_response(self, pkt, sport, dport, proto):
    if 'DNS Question Record' not in pkt:
      return

    dns = pkt['DNS']

    try:
      qname = dns.qd.qname.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
      qname = dns.qd.qname

    rdata_loop = [qname]
    percorso = []
    action_dns = "DNS_QUESTION"

    if 'DNS Resource Record' in pkt:
      action_dns = "DNS_RESOURCE_RECORD"
      for i in range(dns.ancount):
        dnsrr = dns.an[i]

        try:
          rrname = dnsrr.rrname.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
          rrname = dnsrr.rrname

        if rrname not in percorso:
          percorso.append(rrname)

        try:
          rdata = dnsrr.rdata.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
          try:
            rdata = dnsrr.rdata
          except:
            rdata = ""

        if isinstance(rdata, list):
          for rdata_ in rdata:
            rdata_loop.append(rdata_)
        else:
          rdata_loop.append(rdata)

    library = Library()
    for rdata in filter(lambda x: x not in {'.', ''} and not isinstance(x, list), rdata_loop):
      client_response = library.client(f"dns_add|{rdata}___{qname}___{' -> '.join(percorso)}")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DNS"].get_logger().debug(
        library.client(f"dns|{rdata}", json_r=True)
      )

      qname_variants = {qname, qname[:-1]}
      if any(library.client(f"blacklist_fqdn|{variant}") != "no" for variant in qname_variants) or static_fqdn_checks(qname_variants):
        if not check_domain_whitelisted(qname, rdata, "dns_request"):
          self.add_threat_dns(pkt, sport, dport, proto, "dns_request", rdata, qname)

  def store(self, packet):
    if IP in packet:
      if ip_is_checkable(packet[IP].src, self) or ip_is_checkable(packet[IP].dst, self):
        self.redis.rpush(self.label, raw(packet))
        #self.packets_stored += 1
        #self.redis_pipeline.rpush(self.label, raw(packet))
        #if self.packets_stored >= config.REDIS_BATCH_SIZE:
        #  print("eseguito")
        #  self.packets_stored = 0
        #  self.redis_pipeline.execute()

  def analyze(self, packet):
    #self.packets_managed += 1
    if IP in packet:
      if packet.haslayer('UDP') and packet.haslayer('DNS'):
        self.dns_response(packet, packet[UDP].sport, packet[UDP].dport, "UDP")
      else:
        (dport, sport, proto, flags, sni, host) = 0, 0, "", "ND", "", ""
        if ICMP in packet:
          proto = "ICMP"
        if TCP in packet:
          (proto, dport, sport, flags) = "TCP", packet[TCP].dport, packet[TCP].sport, packet.sprintf('%TCP.flags%')
        if UDP in packet:
          (proto, dport, sport) = "UDP", packet[UDP].dport, packet[UDP].sport
        if proto != "":
          id_log = id_generator(30)
          connection_to_analyze = [
            {'ip': packet[IP].dst, 'port': dport, 'proto': proto, 'type': 'dst', 'ip2': packet[IP].src, 'port2': sport},
            {'ip': packet[IP].src, 'port': sport, 'proto': proto, 'type': 'src', 'ip2': packet[IP].dst, 'port2': dport}
          ]

          for ip in connection_to_analyze:
            (ip_check, port_check, proto_check, ip_type_flow, ip2, port2)  = ip['ip'], ip['port'], ip['proto'], ip['type'], ip['ip2'], ip['port2']
            pe_in_header = check_pe_signature(packet)
            content_tls = False
            sni = ""
            handshake_type = ""
            tls_session_id = ""
            config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = CHECK")
            if check_tls(packet):
              sni = extract_sni(packet)
              (handshake_type, tls_session_id) = extract_tls_session_id(packet)
              content_tls = True
            config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST CHECK TLS")

            if is_ip_checkable(ip_check, port_check, proto_check, self):
            #if is_ip_checkable_library(ip_check, port_check, proto_check, self):
              if flags.startswith("S"):
                self.init_matrix_connection(ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
                config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST MATRIX INIT")
              self.tcp_flag_p(packet, flags, ip_check, port_check, ip2, port2, proto, ip_type_flow, content_tls)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST FLAG PUSH")
              self.tcp_flag_fr(packet, flags, ip_check, port_check, ip2, port2, proto, ip_type_flow)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST FLAG FIN RST")
              host = get_host_from_header(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST HOST")
              content_whitelisted = check_connection_content(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST CONTENT WL")
              content_size = get_connection_content_size(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST CONTENT SIZE")
              content_session_id = get_connection_content_session_id(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST CONTENT SESSION")
              self.add_threat_l4(ip_check, port_check, ip2, port2, proto, flags, "L4_ip", ip_type_flow, content_whitelisted, content_size, content_session_id, get_type_ip_fqdn_warn(ip_check, ""), sni, host, handshake_type, tls_session_id, str(pe_in_header))
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = POST ADD THREAT")
            else:
              config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {ip_check} {port_check} {proto_check} {ip_type_flow} {ip2} {port2} = SKIP")
              if pe_in_header:
                host, content_size = self.get_host_from_packet_raw(packet)
                self.add_threat_l4(ip_check, port_check, ip2, port2, proto, flags, "L4_ip", ip_type_flow, "NO", content_size, "ND", get_type_ip_fqdn_warn(ip_check, ""), sni, host, handshake_type, tls_session_id, str(pe_in_header))

          host, content_size = self.get_host_from_packet_raw(packet)
          if is_malicious_host(host, self):
          #if is_malicious_host_library(host, self):
            config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {host} L4_domain")
            reporting = get_type_ip_fqdn_warn("", host)
            if reporting == "":
              reporting = "static_patterns"
            config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {host} pre add threat")
            self.add_threat_l4(ip_check, port_check, ip2, port2, proto, flags, "L4_domain", ip_type_flow, "NO", content_size, "ND", reporting, sni, host, "False")
            config.LOGGERS_SNIFFERS[self.label].get_logger().debug(f"{id_log} {host} post add threat")


def extract_tls_session_id(packet):
  try:

    if packet.haslayer(TCP) and packet.haslayer(Raw):
      payload = packet[Raw].load

      if len(payload) < 6:
        return "", ""

      if payload[0] != 0x16:
        return "", ""  # Not TLS Handshake record

      record_version = payload[1:3]
      handshake_type = payload[5]
      if handshake_type not in (0x01, 0x02):  # 0x01 = ClientHello, 0x02 = ServerHello
        return "", ""

      idx = 9  # TLS record header (5) + handshake header (4)
      if idx + 2 > len(payload):
        return "", ""

      version = payload[idx:idx+2]
      idx += 2
      idx += 32  # skip random
      if idx >= len(payload):
        return "", ""

      session_id_len = payload[idx]
      idx += 1
      if idx + session_id_len > len(payload):
        return "", ""

      session_id = payload[idx:idx+session_id_len]
      return str(handshake_type), str(session_id.hex())
  except:
    return "", ""

  return "", ""

def extract_sni(packet):
  try:

    if packet.haslayer(TCP) and packet.haslayer(Raw):
      data = packet[Raw].load

      if data[0] == 0x16 and data[5] == 0x01:  # TLS Handshake + ClientHello
        session_id_length = data[43]
        ptr = 44 + session_id_length

        if ptr + 2 > len(data):
          return ""

        cipher_suites_length = (data[ptr] << 8) | data[ptr+1]
        ptr += 2 + cipher_suites_length

        if ptr + 1 > len(data):
          return ""

        compression_methods_length = data[ptr]
        ptr += 1 + compression_methods_length

        if ptr + 2 > len(data):
          return ""

        extensions_length = (data[ptr] << 8) | data[ptr+1]
        ptr += 2
        end = ptr + extensions_length

        while ptr + 4 <= end and ptr + 4 <= len(data):
          ext_type = (data[ptr] << 8) | data[ptr+1]
          ext_length = (data[ptr+2] << 8) | data[ptr+3]
          ptr += 4
          if ext_type == 0x00 and ptr + ext_length <= len(data):  # SNI
            sni_list_length = (data[ptr] << 8) | data[ptr+1]
            ptr += 2
            sni_type = data[ptr]
            ptr += 1
            sni_length = (data[ptr] << 8) | data[ptr+1]
            ptr += 2
            sni = data[ptr:ptr+sni_length].decode(errors='ignore')
            return sni
          ptr += ext_length
  except Exception:
    pass
  return ""

def check_tls(packet):
  try:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
      data = packet[Raw].load
      if data[0] == 0x16 and data[5] == 0x01:  # TLS Handshake, ClientHello
        return True
  except:
    pass
  return False

def get_host_from_header(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            for riga in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['content']:
              if riga.strip() != "":
                if riga.strip().lower().startswith('host') == True:
                  return riga.strip().lower().replace("host: ", "")
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error getting sni from session content {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("get_sni_from_header() BOOM!!!")
  return ""

def sniff(interface, str_filter, label, predator_handler):
  try:
    config.LOGGERS_SNIFFERS[label] = PredatorLogger(f"PREDATOR_SNIFFERS_{label}", config.PATH_LOGGER_PREDATOR_SNIFFERS_GEN.replace("XXX", label), config.LOG_TO_STD, logging.INFO)
    config.LOGGERS_SNIFFERS[label].get_logger().info("STARTING THREAD SNIFFER " + str(interface) + " WITH FILTER " + str_filter)
    #scapy.all.sniff(iface=interface, store=False, prn=handler.analyze, filter=str_filter)
    scapy.all.sniff(iface=interface, store=False, prn=predator_handler.store, filter=str_filter)
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS_SNIFFERS[label].get_logger().critical(e, exc_info=True)
    config.LOGGERS_SNIFFERS[label].get_logger().critical("Wait " + str(config.SLEEP_THREAD_RESTART) + " to thread restart")
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("sniff() BOOM!!!")
    time.sleep(config.SLEEP_THREAD_RESTART)
    config.LOGGERS_SNIFFERS[label].get_logger().critical("Restarting thread")
    sniff(interface, str_filter, label, predator_handler)

def build_net(cidrs):
  r = []
  for cidr in cidrs:
    r.append(f"net {cidr}")
  return ' or '.join(r)

def check_pe_signature(packet):
  try:

    if Raw in packet:
      data = packet[Raw].load

      # Step 1: verifica che 'MZ' sia entro i primi 2 byte
      if b"MZ" not in data[:2]:
        return False

      # Step 2: leggi 4 byte in little endian a offset 58 (e_lfanew in PE header è a offset 0x3C = 60, ma forse Suricata parte da 'mz')
      if len(data) < 62:
        return False  # Evita index error

      if b'PE\x00\x00' in data:
        return True

    return False
  except Exception:
    return False

def analyze_packets(interface, str_filter, label, predator_handler):
  try:
    config.LOGGERS_SNIFFERS[label] = PredatorLogger(f"PREDATOR_SNIFFERS_{label}", config.PATH_LOGGER_PREDATOR_SNIFFERS_GEN.replace("XXX", label), config.LOG_TO_STD, logging.INFO)
    config.LOGGERS_SNIFFERS[label].get_logger().info("STARTING THREAD ANALYZER " + str(interface) + " WITH FILTER " + str_filter)
    predator_handler.init_matrix_connections()
    while True:
      try:
        redis_llen = predator_handler.redis.llen(label)
        if redis_llen > 0:
          #packets = predator_handler.redis.lrange(label, 0, redis_llen -1)
          packets = predator_handler.redis.lrange(label, 0, config.REDIS_READ_SIZE -1)
          if packets:
            for raw_pkt in packets:
              predator_handler.analyze(Ether(raw_pkt))
            predator_handler.redis.ltrim(label, config.REDIS_READ_SIZE, -1)
            #predator_handler.redis.ltrim(label, redis_llen, -1)
          else:
            time.sleep(0.100)
        else:
          time.sleep(0.100)
      except Exception as e:
        config.LOGGERS_SNIFFERS[label].get_logger().critical(f"Exception during handling {label}: {e}", exc_info=True)
        time.sleep(0.100)
        pass
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS_SNIFFERS[label].get_logger().critical(e, exc_info=True)
    config.LOGGERS_SNIFFERS[label].get_logger().critical("Wait " + str(config.SLEEP_THREAD_RESTART) + " to thread restart")
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("analyze_packets() BOOM!!!")
    time.sleep(config.SLEEP_THREAD_RESTART)
    config.LOGGERS_SNIFFERS[label].get_logger().critical("Restarting thread")
    analyze_packets(interface, str_filter, label, predator_handler)
