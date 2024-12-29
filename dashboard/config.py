import requests
import urllib3

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8888

ES_URL = "https://127.0.0.1:9200"
ES_AUTH = True
ES_TLS = True
ES_USERNAME = "elastic"
ES_PASSWORD = "hifjeut67_hhgR77jih"
ES_INDEX_PREFIX = "predator"
