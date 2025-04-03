import os
import requests
import urllib3

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dashboard_file_path = os.path.dirname(__file__)

PATH_LOCAL_JSON = "{}/../var/db".format(dashboard_file_path)
PATH_SQLITE = "{}/../var/db".format(dashboard_file_path)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8888

ES_URL = "https://127.0.0.1:9200"
ES_AUTH = True
ES_TLS = True
ES_USERNAME = "elastic"
ES_PASSWORD = "hifjeut67_hhgR77jih"
ES_INDEX_PREFIX = "predator"

READ_THREATS_FROM_ES = False
READ_THREATS_FROM_LOCAL_DB = False
READ_THREATS_FROM_SQLITE = True
