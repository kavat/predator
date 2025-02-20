from core.threads import PredatorThread
from core.pool import PredatorPool
from core.networking import sniff
from core.library import Library, start_library_server
from core.api import start_api
from core.proxy import start_proxy
from core.reverse_proxy import start_reverse_proxies
from core.dummy import start_dummy

import time
import config
import os

def main():
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Starting Predator..")

    config.THREADS["library"] = PredatorThread("library", start_library_server, (), True)
    time.sleep(3)

    if config.IDS == True:
      for nic in config.NICS_TO_SNIFF:
        config.THREADS["sniffer_" + nic + "_tcp_http"] = PredatorPool("sniffer_" + nic + "_tcp_http", sniff, (nic,"tcp port 80",), True)
        config.THREADS["sniffer_" + nic + "_tcp_https"] = PredatorPool("sniffer_" + nic + "_tcp_http", sniff, (nic,"tcp port 443",), True)
        config.THREADS["sniffer_" + nic + "_tcp_nohttp"] = PredatorPool("sniffer_" + nic + "_tcp_nohttp", sniff, (nic,"tcp and not tcp port 80 and not tcp port 443",), True)
        config.THREADS["sniffer_" + nic + "_udp"] = PredatorPool("sniffer_" + nic + "_udp", sniff, (nic,"udp",), True)

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
      rp_certs = True
      for proxy in config.REVERSE_PROXY_HOSTS:
        if proxy["ssl"] != False:
          if (os.path.isfile(proxy["ssl"]["cert"]) == False or os.path.isfile(proxy["ssl"]["key"]) == False):
            config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().error("{} not loaded for reverse proxy module".format(proxy["ssl"]["cert"]))
            rp_certs = False
          else:
            config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("{} loaded for reverse proxy module".format(proxy["ssl"]["cert"]))
      if rp_certs == True:
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
