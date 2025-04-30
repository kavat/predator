from scapy.all import *
from scapy.layers.tls import *
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
  check_tcp_conn,
  get_curdatetime
)
from core.common_utils import (
  parse_json, 
  parse_json_array, 
  get_string_md5,
  append_json_threat,
  string2b64
)

import os
import config
import time
import syslog
import ipaddress
import socket

class PredatorPacketAnalysis:

  def __init__(self, filter_string):
    self.filter_string = filter_string
    self.matrix_connections = {}
    self.matrix_connections_lock = Lock()
    self.upd_lock = Lock()

  def print_matrix(self, flags):
    print("PRINT POST " + flags)
    print(self.matrix_connections)
    print("------------------------------------------------")

  def get_handler(self):
    return self

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

  def add_threat_l4(self, ip1, port1, ip2, port2, proto, flags, type_threat, type_flow, content_whitelisted, content_size, content_session_id, reporting, sni, host):
    if type_flow == "dst":
      (src_ip, src_port, dst_ip, dst_port) = ip2, port2, ip1, port1
    else:
      (src_ip, src_port, dst_ip, dst_port) = ip1, port1, ip2, port2
    Library().client("add_threat|{},{},{},{},{},{},{},{},{},{}".format(src_ip, dst_ip, src_port, dst_port, proto, flags, host, sni, reporting, type_threat))
    stringa_log = "LOG=PREDATOR_THREAT SRC={} SPORT={} DST={} DPORT={} PROTO={} FLAGS={} WHITELISTED_CONTENT={} CONTENT_SIZE={} CONTENT_SESSION_ID={} EVENT={}_{} REPORTING={} SNI={} HOST={}".format(src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host)
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
      print_connection_content(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(type_flow), flags)
      print_connection_content(self.get_handler(), ip2, port2, ip_check, port_check, "evil_{}".format(type_flow), flags)
      self.end_matrix_connection(ip_check, port_check, ip2, port2, "evil_{}".format(type_flow), flags)
      self.end_matrix_connection(ip2, port2, ip_check, port_check, "evil_{}".format(type_flow), flags)
      #self.print_matrix(flags)

  def tcp_flag_p(self, packet, flags, ip_check, port_check, ip2, port2, proto, type_flow):
    if 'P' in flags and 'Raw' in packet:
      packet_content = ""
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
            if riga.strip().startswith('Host') == True:
              return (riga.strip().replace("Host: ", ""), len(packet_content))
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

  def analyze(self, packet):
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
          if packet.haslayer(TLS):
            conf.tls_session_enable = True
            sni = get_sni(packet)

        connection_to_analyze = [
          {'ip': packet[IP].dst, 'port': dport, 'proto': proto, 'type': 'dst', 'ip2': packet[IP].src, 'port2': sport},
          {'ip': packet[IP].src, 'port': sport, 'proto': proto, 'type': 'src', 'ip2': packet[IP].dst, 'port2':dport}
        ]
        for ip in connection_to_analyze:
          (ip_check, port_check, proto_check, ip_type_flow, ip2, port2)  = ip['ip'], ip['port'], ip['proto'], ip['type'], ip['ip2'], ip['port2']
          if(is_ip_checkable(ip_check, port_check, proto_check)):
            self.init_matrix_connection(ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
            self.tcp_flag_p(packet, flags, ip_check, port_check, ip2, port2, proto, ip_type_flow)
            self.tcp_flag_fr(packet, flags, ip_check, port_check, ip2, port2, proto, ip_type_flow)
            host = get_host_from_header(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
            content_whitelisted = check_connection_content(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
            content_size = get_connection_content_size(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
            content_session_id = get_connection_content_session_id(self.get_handler(), ip_check, port_check, ip2, port2, "evil_{}".format(ip_type_flow), flags)
            self.add_threat_l4(ip_check, port_check, ip2, port2, proto, flags, "L4_ip", ip_type_flow, content_whitelisted, content_size, content_session_id, get_type_ip_fqdn_warn(ip_check, ""), sni, host)
        host, content_size = self.get_host_from_packet_raw(packet)
        if is_malicious_host(host):
          reporting = get_type_ip_fqdn_warn("", host)
          if reporting == "":
            reporting = "static_patterns"
          self.add_threat_l4(ip_check, port_check, ip2, port2, proto, flags, "L4_domain", ip_type_flow, "N", content_size, "ND", reporting, sni, host) 
          

def get_sni(packet):
  try:
    for riga in packet[TLS].msg:
      if hasattr(riga, 'ext') and riga.ext != None:
        for ext in riga.ext:
          if hasattr(ext, 'servernames'):
            for servername in ext.servernames:
              if servername != None:
                return str(servername.servername.decode('latin-1'))
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().warn("Unable to get SNI from TLS packet section: " + str(e), exc_info=True)
    pass
  return ""

def get_host_from_header(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            for riga in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['content']:
              if riga.strip() != "":
                if riga.strip().startswith('Host') == True:
                  return riga.strip().replace("Host: ", "")
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error getting sni from session content {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("get_sni_from_header() BOOM!!!")
  return ""

def sniff(interface, str_filter):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().info("STARTING THREAD SNIFFER " + interface + " WITH FILTER " + str_filter)
    handler = PredatorPacketAnalysis(str_filter)
    handler.init_matrix_connections()
    load_layer('tls')
    scapy.all.sniff(iface=interface, store=False, prn=handler.analyze, filter=str_filter)
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().critical("Wait " + str(config.SLEEP_THREAD_RESTART) + " to thread restart")
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("sniff() BOOM!!!")
    time.sleep(config.SLEEP_THREAD_RESTART)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().critical("Restarting thread")
    sniff(interface, str_filter)
