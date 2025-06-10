from datetime import datetime
from core.library import Library
from core.common_utils import id_generator, parse_json, parse_json_array 

import json
import string
import random
import os
import config
import socket
import time
import copy
import ipaddress
import syslog

def get_domain(qname):
  if(qname[-1] == '.'):
    qname = qname.rstrip(qname[-1])
  tld, domain, *sub_domains = qname.split(".")[::-1]
  return domain + "." + tld

def get_curdatetime():
  now = datetime.now()
  return now.strftime("%Y-%m-%d %H:%M:%S")

def get_es_index_date():
  now = datetime.now()
  return now.strftime("%Y.%m.%d")

def logga(messaggio):
  print(get_curdatetime() + " - " + messaggio)

def net_whitelisted(ip, proto, port, fqdn):
  whitelist_l4 = ""
  whitelist_fqdn = ""
  whitelist_l4 = Library().client("whitelist_layer4|{}".format(ip))
  if whitelist_l4 == "no":
    whitelist_l4 = Library().client("whitelist_layer4|all")
  whitelist_fqdn = Library().client("whitelist_fqdn|{}".format(ip))
  if whitelist_l4 == "no" and whitelist_fqdn == "no":
    return False
  if whitelist_l4.lower() == "all":
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted L4 with ALL rule")
    return True
  if (proto + "_" + port).lower() in whitelist_l4.split(","):
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted L4 with " + proto + "_" + port + " rule")
    return True
  if fqdn == "":
    return False
  if whitelist_fqdn.lower()[:1] != '*':
    if whitelist_fqdn.lower() == fqdn.lower():
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted FQDN exact match " + fqdn.lower() + " rule (" + whitelist_fqdn.lower() + ")")
      return True
  else:
    if fqdn.lower().endswith(whitelist_fqdn.lower()[1:]):
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted FQDN wild match " + fqdn.lower() + " rule (" + whitelist_fqdn.lower() + ")") 
      return True
  check_fqdn_lower = Library().client("whitelist_fqdn_all_static|{}".format(fqdn.lower()))
  if check_fqdn_lower != "no":
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted FQDN " + fqdn.lower() + " rule ALL") 
    return True
  for domain in Library().client("get_whitelist_fqdn_all_wild|").split("|"):
    if domain[:1] == '*':
      if fqdn.lower().endswith(domain.lower()[1:]):
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"].get_logger().debug("IP " + ip + ":" + port + " (" + proto + ") whitelisted FQDN wild match " + fqdn.lower() + " rule ALL") 
        return True
  return False

def check_domain_whitelisted(qname, rdata, type_request):
  qname_check_1 = Library().client("whitelist_fqdn_dns_requests|{}".format(qname))
  qname_check_2 = Library().client("whitelist_fqdn_dns_requests|{}".format(qname[-1]))
  if (qname_check_1 != "no" or qname_check_2 != "no") and type_request == "dns_request":
    return True
  qname_check_1 = Library().client("whitelist_fqdn_all_static|{}".format(qname))
  qname_check_2 = Library().client("whitelist_fqdn_all_static|{}".format(qname[-1]))
  if qname_check_1 != "no" or qname_check_2 != "no":
    return True
  for domain in Library().client("get_whitelist_fqdn_all_wild|").split("|"):
    if domain[:1] == '*':
      if qname.lower().endswith(domain.lower()[1:]) or qname[-1].lower().endswith(domain.lower()[1:]):
        return True
  qname_check_1 = Library().client("whitelist_fqdn|{}".format(rdata))
  if qname_check_1 != "no" and qname_check_1 == qname:
    return True 
  return False

def check_domain_dns_whitelisted(qname):
  qname_check_1 = Library().client("whitelist_fqdn_dns_requests|{}".format(qname))
  if qname_check_1 != "no":
    return True
  return False

def get_type_ip_fqdn_warn(ip, fqdn):
  if ip != "":
    ip_check = Library().client("blacklist_ip|{}".format(ip))
    if ip_check != "no":
      return ip_check
  if fqdn != "":
    if fqdn[-1] == '.':
      qname = fqdn[:-1]
    else:
      qname = fqdn
    fqdn_check = Library().client("blacklist_fqdn|{}".format(qname))
    if fqdn_check != "no":
      return fqdn_check
  return ""

def static_fqdn_checks(fqdns):
  for fqdn in fqdns:
    if fqdn != "":
      if fqdn[-1] == '.':
        qname = fqdn[:-1]
      else:
        qname = fqdn
      for malicious_suffix in config.MALICIOUS_SUFFIXES:
        data = ""
        try:
          data = qname.decode("ascii")
        except:
          data = str(qname)
        if data.endswith(malicious_suffix):
          return True
  return False

def inspect_packet_content(packet_content):
  if packet_content == None:
    return ""
  try:
    packet_content = packet_content.decode()
  except:
    pass
  for pattern in Library().client("pattern_tcp_udp|").split("|"):
    try:
      if str.encode(pattern) in packet_content:
        return pattern
    except:
      pass
    try:
      if pattern in packet_content:
        return pattern
    except:
      pass
  return ""

def start_threads():
  for thread_name in config.THREADS:
    config.THREADS[thread_name].start()

def join_threads():
  for thread_name in config.THREADS:
    config.THREADS[thread_name].join()

def print_connection_content(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            for riga in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['content']:
              session_id = matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['id_connection']
              if riga.strip() != "":
                riga_utf8 = ""
                try:
                  riga_utf8 = riga.strip().encode("utf-8")
                except:
                  pass
                if riga_utf8 != "":
                  config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().info("{} after {} => {}:{} -> {}:{} [{}] = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, session_id, riga_utf8))
                  if config.SEND_TO_SYSLOG == True:
                    syslog.syslog("LOG=PREDATOR_L7 SESSION_ID={} CONTENT={}".format(session_id, riga_utf8))
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error printing session {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e), exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("print_connection_content() BOOM!!!")

def check_connection_content(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            for riga in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['content']:
              if riga.strip() != "":
                if riga.strip().startswith('Host'):
                  for riga_w in Library().client("get_whitelist_fqdn_servernames|").split("|"):
                    if riga_w.strip()[:1] == '*':
                      str_pattern = ""
                      if riga_w.strip()[-1] == '.':
                        str_pattern = riga_w.strip()[1:-1]
                      else:
                        str_pattern = riga_w.strip()[1:]
                      if str_pattern != "" and riga.strip().endswith(str_pattern):
                        return "Y"
                    else:
                      if riga.strip() == "HOST: {}".format(riga_w):
                        return "Y"
                      if riga.strip() == "Host: {}".format(riga_w):
                        return "Y"
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content() BOOM!!!")
  try:
    if endpoint_conn_ip in matrix_connections:
      if endpoint_conn_port in matrix_connections[endpoint_conn_ip]:
        if init_conn_ip in matrix_connections[endpoint_conn_ip][endpoint_conn_port]:
          if init_conn_port in matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip]:
            for riga in matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip][init_conn_port]['content']:
              if riga.strip() != "":
                if riga.strip().startswith('Host'):
                  for riga_w in Library().client("get_whitelist_fqdn_servernames|").split("|"):
                    if riga_w[:1] == '*':
                      str_pattern = ""
                      if riga_w[:-1] == '.':
                        str_pattern = riga_w[-1]
                      else:
                        str_pattern = riga_w[1:]
                      if str_pattern != "" and riga.strip().endswith(str_pattern):
                        return "Y"
                    else: 
                      if riga.strip() == "HOST: {}".format(riga_w):
                        return "Y"
                      if riga.strip() == "Host: {}".format(riga_w):
                        return "Y"
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content {} {} {}:{} -> {}:{} = {}".format(label, flags, endpoint_conn_ip, endpoint_conn_port, init_conn_ip, init_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content() BOOM!!!")
  return "N"

def get_connection_content_size(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            return matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['size_content']
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content size {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content_size() BOOM!!!")
  try:
    if endpoint_conn_ip in matrix_connections:
      if endpoint_conn_port in matrix_connections[endpoint_conn_ip]:
        if init_conn_ip in matrix_connections[endpoint_conn_ip][endpoint_conn_port]:
          if init_conn_port in matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip]:
            return matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip][init_conn_port]['size_content']
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content size {} {} {}:{} -> {}:{} = {}".format(label, flags, endpoint_conn_ip, endpoint_conn_port, init_conn_ip, init_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content_size() BOOM!!!")
  return "0"

def get_connection_content_session_id(predator_packet_analysis, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, label, flags):
  matrix_connections = predator_packet_analysis.get_matrix_connections()
  try:
    if init_conn_ip in matrix_connections:
      if init_conn_port in matrix_connections[init_conn_ip]:
        if endpoint_conn_ip in matrix_connections[init_conn_ip][init_conn_port]:
          if endpoint_conn_port in matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip]:
            return matrix_connections[init_conn_ip][init_conn_port][endpoint_conn_ip][endpoint_conn_port]['id_connection']
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content id {} {} {}:{} -> {}:{} = {}".format(label, flags, init_conn_ip, init_conn_port, endpoint_conn_ip, endpoint_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content_session_id() BOOM!!!")
  try:
    if endpoint_conn_ip in matrix_connections:
      if endpoint_conn_port in matrix_connections[endpoint_conn_ip]:
        if init_conn_ip in matrix_connections[endpoint_conn_ip][endpoint_conn_port]:
          if init_conn_port in matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip]:
            return matrix_connections[endpoint_conn_ip][endpoint_conn_port][init_conn_ip][init_conn_port]['id_connection']
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"].get_logger().critical("Error checking session content id {} {} {}:{} -> {}:{} = {}".format(label, flags, endpoint_conn_ip, endpoint_conn_port, init_conn_ip, init_conn_port, e))
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("check_connection_content_session_id() BOOM!!!")
  return "ND"

def check_if_ip_is_in_cidrs_old(ip):
  for cidr in config.CIDRS:
    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
      return True
  return False

def check_if_ip_is_in_cidrs(ip):
  for label,values in config.CIDRS.items():
    for cidr in values['cidrs']:
      if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
        return True
  return False

def ip_is_checkable(ip, predator_obj):
  if(ipaddress.ip_address(ip).is_private == False and check_if_ip_is_in_cidrs(ip) == False):
    return True
  return False

def is_ip_checkable(ip, port, proto, predator_obj):
  if(ipaddress.ip_address(ip).is_private == False and check_if_ip_is_in_cidrs(ip) == False):
    if ip in predator_obj.blacklist_ip and ip not in predator_obj.whitelist:
      if net_whitelisted(ip, proto, str(port), "") == False:
        return True
  return False

def is_ip_checkable_library(ip, port, proto, predator_obj):
  if(ipaddress.ip_address(ip).is_private == False and check_if_ip_is_in_cidrs(ip) == False):
    if(Library().client("blacklist_ip|{}".format(ip)) != "no" and Library().client("whitelist|{}".format(ip))):
      if net_whitelisted(ip, proto, str(port), "") == False:
        return True
  return False

def is_malicious_host(host, predator_obj):
  if host == "":
    return False
  if host in predator_obj.blacklist_fqdn or static_fqdn_checks([host]):
    return True
  return False

def is_malicious_host_library(host, predator_obj):
  if host == "":
    return False
  if Library().client("blacklist_fqdn|{}".format(host)) != "no" or static_fqdn_checks([host]):
    return True
  return False

def check_tcp_conn(host, port):
  s =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  result = s.connect_ex((host, port))
  s.close()
  if result:
    return False
  else:
    return True
