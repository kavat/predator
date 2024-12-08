from core.threads import PredatorThread
from core.pool import PredatorPool
from core.networking import sniff
from core.library import Library, start_library_server
from core.api import start_api
from core.proxy import start_proxy
from core.dummy import start_dummy

import time
import config

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
      config.THREADS["proxy"] = PredatorThread("proxy", start_proxy, (config.PROXY_HOST, config.PROXY_PORT, config.PROXY_PROTOCOL,), True)

    while True:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Living Predator..") 
      time.sleep(60)

  except KeyboardInterrupt:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().info("Stop")

if __name__ == '__main__':
  main()
