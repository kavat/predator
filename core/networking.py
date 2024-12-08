from scapy.all import *
from scapy.layers.tls import *

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
  parse_json,
  parse_json_array
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

  def print_matrix(self, flags):
    print("PRINT POST " + flags)
    print(self.matrix_connections)
    print("------------------------------------------------")

  def get_handler(self):
    return self

  def get_matrix_connections(self):
    return self.matrix_connections

  def init_matrix_connection(self, p1, p2, p3, p4, label, flags):
    try:
      if p1 not in self.matrix_connections:
        self.matrix_connections[p1] = {}
      if p2 not in self.matrix_connections[p1]:
        self.matrix_connections[p1][p2] = {}
      if p3 not in self.matrix_connections[p1][p2]:
        self.matrix_connections[p1][p2][p3] = {}
      if p4 not in self.matrix_connections[p1][p2][p3]:
        self.matrix_connections[p1][p2][p3][p4] = {}
        self.matrix_connections[p1][p2][p3][p4]['content'] = []
        self.matrix_connections[p1][p2][p3][p4]['size_content'] = 0
        self.matrix_connections[p1][p2][p3][p4]['id_connection'] = id_generator(30)
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("{} received, error creating session {} for {}:{}:{}:{}".format(label, flags, p1, p2, p3, p4))
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("init_matrix_connection() BOOM!!!")

  def end_matrix_connection(self, p1, p2, p3, p4, label, flags):
    try:
      if p1 in self.matrix_connections:
        if p2 in self.matrix_connections[p1]:
          if p3 in self.matrix_connections[p1][p2]:
            if p4 in self.matrix_connections[p1][p2][p3]:
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
                self.matrix_connections[p1][p2][p3][p4]['content'].append(content_line)
              self.matrix_connections[p1][p2][p3][p4]['size_content'] = 0
              for content_line in self.matrix_connections[p1][p2][p3][p4]['content']:
                self.matrix_connections[p1][p2][p3][p4]['size_content'] += len(content_line)
    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("{} received, error appending session {}:{}:{}:{}".format(label, p1, p2, p3, p4))
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("append_content_matrix_connection() BOOM!!!")

  def init_matrix_connections(self):
    self.matrix_connections = {}

  def analyze(self, packet):
    if IP in packet:
      if packet.haslayer('UDP') and packet.haslayer('DNS'):
        get_dns_response(packet)
      else:
        dport = ""
        sport = ""
        proto = ""
        flags = "ND"
        sni = ""
        host = ""
        if ICMP in packet:
          proto = "ICMP"
        if TCP in packet:
          proto = "TCP"
          dport = packet[TCP].dport
          sport = packet[TCP].sport
          flags = packet.sprintf('%TCP.flags%')
        if UDP in packet:
          proto = "UDP"
          dport = packet[UDP].dport
          sport = packet[UDP].sport
        if proto != "":
          if Raw in packet:
            check_content_packet = inspect_packet_content(packet[Raw].load)
            type_reporting = ""
            if check_content_packet != "":
              config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical("LOG=PREDATOR_THREAT SRC=" + str(packet[IP].src) + " SPORT=" + str(sport) + " DST=" + str(packet[IP].dst) + " DPORT=" + str(dport) + " PROTO=" + str(proto) + " FLAGS=" + flags + " WHITELISTED_CONTENT=N PAYLOAD=" + str(check_content_packet) + " REPORTING=" + type_reporting  + " EVENT=LAYER7")
          if packet.haslayer(TLS):
            conf.tls_session_enable = True
            sni = get_sni(packet)
          if ((Library().client("blacklist_ip|{}".format(packet[IP].dst)) != "no" and Library().client("whitelist|{}".format(packet[IP].dst)) == "no") or (Library().client("blacklist_ip|{}".format(packet[IP].src)) != "no" and Library().client("whitelist|{}".format(packet[IP].src)) == "no")):
            if(ipaddress.ip_address(packet[IP].dst).is_private == False and check_if_ip_is_in_cidrs(packet[IP].src, packet[IP].dst)):
              fqdn = ""
              whitelisted = net_whitelisted(packet[IP].dst, proto, str(dport), fqdn)
              if whitelisted == False:
                type_ip_fqdn_warn = get_type_ip_fqdn_warn(packet[IP].dst, fqdn)
                if 'P' in flags and 'Raw' in packet:
                  packet_content = ""
                  try:
                    packet_content = packet[Raw].load.decode('latin-1')
                  except Exception as ed:
                    packet_content = ""
                    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error decoding payload for evil_dst {} {}:{} -> {}:{} = {}".format(flags, packet[IP].src, sport, packet[IP].dst, dport, ed))
                  if packet_content != "":
                    self.append_content_matrix_connection(packet[IP].src, sport, packet[IP].dst, dport, packet[Raw].load.decode('latin-1'), "evil_dst")
                    self.append_content_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, packet[Raw].load.decode('latin-1'), "evil_dst")
                    #self.print_matrix(flags)
                self.init_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                if "F" in flags or "R" in flags:
                  print_connection_content(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                  self.end_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                  self.end_matrix_connection(packet[IP].src, sport, packet[IP].dst, dport, "evil_dst", flags)
                  #self.print_matrix(flags)
                content_whitelisted = check_connection_content(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                content_size = get_connection_content_size(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                content_session_id = get_connection_content_session_id(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                host = get_host_from_header(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_dst", flags)
                stringa_log = "LOG=PREDATOR_THREAT SRC=" + str(packet[IP].src) + " SPORT=" + str(sport) + " DST=" + str(packet[IP].dst) + " DPORT=" + str(dport) + " PROTO=" + str(proto) + " FLAGS=" + flags + " WHITELISTED_CONTENT=" + content_whitelisted + " CONTENT_SIZE=" + str(content_size) + " CONTENT_SESSION_ID=" + content_session_id + " EVENT=LAYER4_DST REPORTING=" + type_ip_fqdn_warn + " FQDN=" + str(fqdn) + " SNI=" + str(sni) + " HOST=" + host + " "
                config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)
                if config.SEND_TO_SYSLOG == True:
                  syslog.syslog(stringa_log)
            if(ipaddress.ip_address(packet[IP].src).is_private == False and check_if_ip_is_in_cidrs(packet[IP].src, packet[IP].dst)):
              fqdn = ""
              whitelisted = net_whitelisted(packet[IP].src, proto, str(sport), fqdn)
              if whitelisted == False:
                type_ip_fqdn_warn = get_type_ip_fqdn_warn(packet[IP].src, fqdn)
                self.init_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                if "F" in flags or "R" in flags:
                  print_connection_content(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                  #self.print_matrix(flags)
                  self.end_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                  self.end_matrix_connection(packet[IP].src, sport, packet[IP].dst, dport, "evil_src", flags)
                if 'P' in flags and 'Raw' in packet:
                  packet_content = ""
                  try:
                    packet_content = packet[Raw].load.decode('latin-1')
                  except Exception as ed:
                    packet_content = ""
                    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error decoding payload for evil_src {} {}:{} -> {}:{} = {}".format(flags, packet[IP].dst, dport, packet[IP].src, sport, ed))
                  if packet_content != "":
                    self.append_content_matrix_connection(packet[IP].dst, dport, packet[IP].src, sport, packet[Raw].load.decode('latin-1'), "evil_src")
                    self.append_content_matrix_connection(packet[IP].src, sport, packet[IP].dst, dport, packet[Raw].load.decode('latin-1'), "evil_src")
                    #self.print_matrix(flags)
                content_whitelisted = check_connection_content(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                content_size = get_connection_content_size(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                content_session_id = get_connection_content_session_id(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                host = get_host_from_header(self.get_handler(), packet[IP].dst, dport, packet[IP].src, sport, "evil_src", flags)
                stringa_log = "LOG=PREDATOR_THREAT SRC=" + str(packet[IP].src) + " SPORT=" + str(sport) + " DST=" + str(packet[IP].dst) + " DPORT=" + str(dport) + " PROTO=" + str(proto) + " FLAGS=" + flags + " WHITELISTED_CONTENT=" + content_whitelisted + " CONTENT_SIZE=" + str(content_size) + " CONTENT_SESSION_ID=" + content_session_id + " EVENT=LAYER4_SRC REPORTING=" + type_ip_fqdn_warn + " FQDN=" + str(fqdn) + " SNI=" + str(sni) + " HOST=" + host + " " 
                config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)
                if config.SEND_TO_SYSLOG == True:
                  syslog.syslog(stringa_log)

def get_dns_response(pkt):

  #config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DNS"].get_logger().debug(str(pkt.show()))
  if 'DNS Question Record' in pkt:
    dns = pkt['DNS']

    try:
      qname = dns.qd.qname.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
      qname = dns.qd.qname

    rdata_loop = []
    action_dns = "DNS_QUESTION"
    if 'DNS Resource Record' in pkt:
      action_dns = "DNS_RESOURCE_RECORD"
      percorso = []
      for i in range(dns.ancount):
        rrname = ""
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
        if rdata != "":
          rdata_loop.append(rdata)

    for rdata in rdata_loop:
      if not isinstance(rdata, list) and rdata != '.' and rdata != '':
        Library().client("dns_add|{}|{}|{}".format(rdata, qname, ' -> '.join(percorso)))
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DNS"].get_logger().debug(str(Library().client("dns|{}".format(rdata), json_r=True)))

      qname_check_1 = Library().client("blacklist_fqdn|{}".format(qname))
      qname_check_2 = Library().client("blacklist_fqdn|{}".format(qname[:-1]))
      if qname != "" and (qname_check_1 != "no" or qname_check_2 != "no" or static_fqdn_checks(qname)) and check_domain_whitelisted(qname, rdata, "dns_request") == False:
        proto = "UDP"
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport

        if(qname[-1] == '.'):
          fqdn = qname[:-1]
        else:
          fqdn = qname

        #config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DNS"].get_logger().debug(str(pkt.show()))

        type_ip_fqdn_warn = get_type_ip_fqdn_warn("", qname)
        stringa_log = "LOG=PREDATOR_THREAT SRC=" + str(pkt[IP].src) + " SPORT=" + str(sport) + " DST=" + str(pkt[IP].dst) + " DPORT=" + str(dport) + " PROTO=" + str(proto) + " FLAGS=ND WHITELISTED_CONTENT=N REPORTING=" + type_ip_fqdn_warn + " EVENT=" + str(action_dns) + " RDATA=" + str(rdata) + " FQDN=" + str(qname)
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical(stringa_log)
        if config.SEND_TO_SYSLOG == True:
          syslog.syslog(stringa_log)

def get_sni(packet):
  try:
    for riga in packet[TLS].msg:
      if hasattr(riga, 'ext'):
        for ext in riga.ext:
          if hasattr(ext, 'servernames'):
            for servername in ext.servernames:
              if servername != None:
                return str(servername.servername.decode('latin-1'))
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().warn("Unable to get SNI from TLS packet section: " + e, exc_info=True)
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
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().critical("Tra " + str(config.SLEEP_THREAD_RESTART) + " riavvio il thread")
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("sniff() BOOM!!!")
    time.sleep(config.SLEEP_THREAD_RESTART)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().critical("Riavvio thread")
    sniff(interface, str_filter)

def check_tcp_conn(host, port):
  s =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  result = s.connect_ex((host, port))
  s.close()
  if result:
    return False
  else:
    return True
