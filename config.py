import os
import logging
import requests
import urllib3

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from core.logging import PredatorLogger

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

predator_file_path = os.path.dirname(__file__)

PATH_LOCAL_JSON = "{}/var/db".format(predator_file_path)
PATH_SQLITE = "{}/var/db".format(predator_file_path)

PATH_LOGGER_PREDATOR_MAIN = "{}/var/log/predator.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_DNS = "{}/var/log/predator_dns.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_THREATS = "{}/var/log/predator_threats.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_MANAGEMENT = "{}/var/log/predator_management.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_SNIFFERS = "{}/var/log/predator_sniffers.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_SNIFFERS_GEN = "{}/var/log/predator_sniffers_XXX.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_L7 = "{}/var/log/predator_l7.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_LIBRARY = "{}/var/log/predator_library.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_PROXY = "{}/var/log/predator_proxy.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_REVERSE_PROXY = "{}/var/log/predator_reverse_proxy.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_DUMMY = "{}/var/log/predator_dummy.log".format(predator_file_path)
PATH_LOGGER_PREDATOR_MASTER_EXCEPTIONS = "{}/var/log/predator_boom.log".format(predator_file_path)
PATH_JSON = "{}/conf/json/".format(predator_file_path)
PATH_MMDB = "{}/../anubi-signatures/geo/GeoLite2-City.mmdb".format(predator_file_path)

SOCKET_LIBRARY = "{}/var/run/library.sock".format(predator_file_path)
SOCKET_LIBRARY_BASE_CLIENT = "{}/var/run/".format(predator_file_path)

DNS = {}
THREADS = {}
HTTP_DUMMY_REQUESTS = {}

SLEEP_THREAD_RESTART = 10
SLEEP_THREAD_SOCKET_RESTART = 90

LOG_TO_STD = True
REDIS_BATCH_SIZE = 100
REDIS_READ_SIZE = 10000

LOGGERS = {}
LOGGERS["RESOURCES"] = {}
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"] = PredatorLogger("PREDATOR_MAIN", PATH_LOGGER_PREDATOR_MAIN, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DNS"] = PredatorLogger("PREDATOR_DNS", PATH_LOGGER_PREDATOR_DNS, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"] = PredatorLogger("PREDATOR_THREATS", PATH_LOGGER_PREDATOR_THREATS, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MANAGEMENT"] = PredatorLogger("PREDATOR_MANAGEMENT", PATH_LOGGER_PREDATOR_MANAGEMENT, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_SNIFFERS"] = PredatorLogger("PREDATOR_SNIFFERS", PATH_LOGGER_PREDATOR_SNIFFERS, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_L7"] = PredatorLogger("LOGGER_PREDATOR_L7", PATH_LOGGER_PREDATOR_L7, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_LIBRARY"] = PredatorLogger("LOGGER_PREDATOR_LIBRARY", PATH_LOGGER_PREDATOR_LIBRARY, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"] = PredatorLogger("PREDATOR_PROXY", PATH_LOGGER_PREDATOR_PROXY, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"] = PredatorLogger("PREDATOR_REVERSE_PROXY", PATH_LOGGER_PREDATOR_REVERSE_PROXY, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"] = PredatorLogger("PREDATOR_DUMMY", PATH_LOGGER_PREDATOR_DUMMY, LOG_TO_STD, logging.INFO)
LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"] = PredatorLogger("PREDATOR_MASTER_EXCEPTIONS", PATH_LOGGER_PREDATOR_MASTER_EXCEPTIONS, LOG_TO_STD, logging.INFO)
LOGGERS["ASSOC"] = {}
LOGGERS["ASSOC"]["main"] = "LOGGER_PREDATOR_MAIN"
LOGGERS["ASSOC"]["dns"] = "LOGGER_PREDATOR_DNS"
LOGGERS["ASSOC"]["threats"] = "LOGGER_PREDATOR_THREATS"
LOGGERS["ASSOC"]["management"] = "LOGGER_PREDATOR_MANAGEMENT"
LOGGERS["ASSOC"]["sniffers"] = "LOGGER_PREDATOR_SNIFFERS"
LOGGERS["ASSOC"]["proxy"] = "LOGGER_PREDATOR_PROXY"
LOGGERS["ASSOC"]["reverse_proxy"] = "LOGGER_PREDATOR_REVERSE_PROXY"
LOGGERS["ASSOC"]["l7"] = "LOGGER_PREDATOR_L7"
LOGGERS["ASSOC"]["library"] = "LOGGER_PREDATOR_LIBRARY"
LOGGERS["ASSOC"]["exceptions"] = "LOGGER_PREDATOR_MASTER_EXCEPTIONS"
LOGGERS["LEVELS"] = ["debug", "info", "warn", "error", "critical"]

CA_KEY = "{}/certs/ca.key".format(predator_file_path)
CA_CRT = "{}/certs/ca.crt".format(predator_file_path)
CERT_KEY = "{}/certs/cert.key".format(predator_file_path)
CERT_DIR = "{}/certs".format(predator_file_path)
CA_KEY_SIZE = 2048
CERT_KEY_SIZE = 2048
REVERSE_PROXY_SSL_CERT = "{}/certs/rp_cert.pem".format(predator_file_path)
REVERSE_PROXY_SSL_KEY = "{}/certs/rp_key.pem".format(predator_file_path)
LINK_DOWNLOAD_CA = "http://predator.fuck"
LINK_DASHBOARD = "http://predator.dashboard"
PROXY_TIMEOUT = 3
PROXY_PROTOCOL = "HTTP/1.1"

MALICIOUS_SUFFIXES = [".onion"]

CIDRS = {
  'home': {
    'cidr': ['192.168.1.0/24']
  }
}
NICS_TO_SNIFF = ["en0"]
MANAGEMENT_HOST = "0.0.0.0"
MANAGEMENT_PORT = 10000
DUMMY_HOST = "127.0.0.1"
DUMMY_PORT = 9999
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 7777
REVERSE_PROXY_HOSTS = [
  {"host": "0.0.0.0", 
   "port": 443, 
   "ssl": {"cert": "{}/certs/tls.crt".format(predator_file_path), "key": "{}/certs/tls.key".format(predator_file_path)},
   "upstream_https": "https://github.com",
   "upstream_wss": {
     "url": "https://github.com",
     "origin": "ciao"
   }
  } 
#  {"host": "0.0.0.0", 
#   "port": 8080, 
#   "ssl": False, 
#   "upstream_http": "http://security.ubuntu.com/ubuntu"
#  }
]
REVERSE_PROXY_STATIC_JUMP = 0
REVERSE_PROXY_REGEXP = [r"(?i)(<script.*?>.*?</script>|javascript:|on\w+\s*=|alert\s*\(|document\.cookie|document\.write|eval\s*\(|union\s+select|select.*?from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|or\s+1=1|--|#|/\*.*?\*/)"]

ES_URL = "https://127.0.0.1:9200"
ES_AUTH = True
ES_TLS = True
ES_USERNAME = "elastic"
ES_PASSWORD = "hifjeut67_hhgR77jih"
ES_INDEX_PREFIX = "predator"

DASHBOARD_URL = "http://127.0.0.1:8888"

IDS = False
PROXY = False
REVERSE_PROXY = False
API = True
DUMMY = False
SEND_TO_SYSLOG = False
SEND_TO_ES = False
SEND_TO_LOCAL_JSON = False
SEND_TO_SQLITE = False
