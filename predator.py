from core.threads import PredatorThread
from core.pool import PredatorPool
from core.networking import sniff, PredatorPacketAnalysis, analyze_packets, build_net
from core.library import Library, start_library_server
from core.api import start_api
from core.proxy import start_proxy
from core.reverse_proxy import start_reverse_proxies
from core.dummy import start_dummy

import time
import config
import os
import sys

def main():
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Starting Predator..")

    config.THREADS["library"] = PredatorThread("library", start_library_server, (), True)
    time.sleep(3)

    try:
      args = sys.argv[1:]
    except:
      args = []

    if config.IDS == True:
      for label_net in config.CIDRS.keys(): 
        nets = build_net(config.CIDRS[label_net]['cidrs'])
        if (args != [] and args[0] == "-ids" and (args[1] == "tcp_http" or args[1] == "all")) or args == []:
          str_filter = f"tcp port 80 and ({nets})"
          label = f"{label_net}_HTTP"
          handler = PredatorPacketAnalysis(str_filter, label)
          config.THREADS[f"{label_net}_sniffer_tcp_http"] = PredatorPool(f"{label_net}_sniffer_tcp_http", sniff, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
          config.THREADS[f"{label_net}_analyze_tcp_http"] = PredatorPool(f"{label_net}_analyze_tcp_http", analyze_packets, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
        if (args != [] and args[0] == "-ids" and (args[1] == "tcp_https" or args[1] == "all")) or args == []:
          str_filter = f"tcp port 443 and ({nets})"
          label = f"{label_net}_HTTPS"
          handler = PredatorPacketAnalysis(str_filter, label)
          config.THREADS[f"{label_net}_sniffer_tcp_https"] = PredatorPool(f"{label_net}_sniffer_tcp_https", sniff, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
          config.THREADS[f"{label_net}_analyze_tcp_https"] = PredatorPool(f"{label_net}_analyze_tcp_https", analyze_packets, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
        if (args != [] and args[0] == "-ids" and (args[1] == "tcp_nohttp" or args[1] == "all")) or args == []:
          str_filter = f"tcp and not tcp port 80 and not tcp port 443 and ({nets})"
          label = f"{label_net}_NOHTTP"
          handler = PredatorPacketAnalysis(str_filter, label)
          config.THREADS[f"{label_net}_sniffer_tcp_nohttp"] = PredatorPool(f"{label_net}_sniffer_tcp_nohttp", sniff, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
          config.THREADS[f"{label_net}_analyze_tcp_nohttp"] = PredatorPool(f"{label_net}_analyze_tcp_nohttp", analyze_packets, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
        if (args != [] and args[0] == "-ids" and (args[1] == "udp" or args[1] == "all")) or args == []:
          str_filter = f"udp and ({nets})"
          label = f"{label_net}_UDP"
          handler = PredatorPacketAnalysis(str_filter, label)
          config.THREADS[f"{label_net}_sniffer_udp"] = PredatorPool(f"{label_net}_sniffer_udp", sniff, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
          config.THREADS[f"{label_net}_analyze_udp"] = PredatorPool(f"{label_net}_analyze_udp", analyze_packets, (config.NICS_TO_SNIFF, str_filter, label, handler,), True)
      
#      for nic in config.NICS_TO_SNIFF:
#        if args != None and args[0] == "-ids" and (args[1] == "tcp_http" or args[1] == "all"):
#          config.THREADS["sniffer_" + nic + "_tcp_http"] = PredatorPool("sniffer_" + nic + "_tcp_http", sniff, (nic,"tcp port 80",), True)
#        if args != None and args[0] == "-ids" and (args[1] == "tcp_https" or args[1] == "all"):
#          config.THREADS["sniffer_" + nic + "_tcp_https"] = PredatorPool("sniffer_" + nic + "_tcp_https", sniff, (nic,"tcp port 443",), True)
#        if args != None and args[0] == "-ids" and (args[1] == "tcp_nohttp" or args[1] == "all"):
#          config.THREADS["sniffer_" + nic + "_tcp_nohttp"] = PredatorPool("sniffer_" + nic + "_tcp_nohttp", sniff, (nic,"tcp and not tcp port 80 and not tcp port 443",), True)
#        if args != None and args[0] == "-ids" and (args[1] == "udp" or args[1] == "all"):
#          config.THREADS["sniffer_" + nic + "_udp"] = PredatorPool("sniffer_" + nic + "_udp", sniff, (nic,"udp",), True)


    if config.API == True:
      config.THREADS["management"] = PredatorThread("management", start_api, (config.MANAGEMENT_HOST, config.MANAGEMENT_PORT,), True)

    if config.DUMMY == True:
      config.THREADS["dummy"] = PredatorThread("dummy", start_dummy, (config.DUMMY_HOST, config.DUMMY_PORT,), True)

    if config.PROXY == True:
      if (os.path.isdir(config.CERT_DIR) and os.path.isfile(config.CA_KEY) and os.path.isfile(config.CA_CRT) and os.path.isfile(config.CERT_KEY)):
        config.THREADS["proxy"] = PredatorPool("proxy", start_proxy, (config.PROXY_HOST, config.PROXY_PORT, config.PROXY_PROTOCOL,), True)
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().warning("Reverse proxy cannot be execute due to certificate authority missed")

    if config.REVERSE_PROXY == True:
      if (os.path.isdir(config.CERT_DIR) and os.path.isfile(config.REVERSE_PROXY_SSL_CERT) and os.path.isfile(config.REVERSE_PROXY_SSL_KEY)):
        start_reverse_proxies(config.REVERSE_PROXY_HOSTS)
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().warning("Reverse proxy cannot be execute due to certificate missed")

    while True:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Living Predator..") 
      time.sleep(60)

  except KeyboardInterrupt:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Stop")

if __name__ == '__main__':
  main()
