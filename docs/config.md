# Predator configuration file config.py
Below are reported the settings customizable by user: 

```python
SLEEP_THREAD_RESTART = 10                    # time used to restart failed internal module related thread
SLEEP_THREAD_SOCKET_RESTART = 90             # time used to restart socket related to internal module after exception
LOG_TO_STD = True                            # allow log to STDOUT
CA_KEY_SIZE = 2048                           # ÃPredator proxy module CA key siz
CERT_KEY_SIZE = 2048                         # Predator proxy module runtime certificate key size
LINK_DOWNLOAD_CA = "http://predator.fuck/"   # URL used to download CA generated before to be used for proxy; URL can be reached after proxy is set
PROXY_TIMEOUT = 3                            # Proxy request timeout
MALICIOUS_SUFFIXES = [".onion"]              # Static malicious domain extension
CIDRS = ['192.168.1.0/24']                   # CIDR to be monitored
NICS_TO_SNIFF = ["vmbr0"]                    # Network interface to be monitored
MANAGEMENT_HOST = "192.168.1.239"            # API host
MANAGEMENT_PORT = 10000                      # API port
DUMMY_HOST = "127.0.0.1"                     # DUMMY host
DUMMY_PORT = 9999                            # DUMMY port
PROXY_HOST = "192.168.1.239"                 # Proxy host
PROXY_PORT = 7777                            # Proxy port
ES_URL = "https://127.0.0.1:9200"            # Elasticsearch URL for threat raised
ES_AUTH = True                               # Elasticsearch authentication
ES_USERNAME = "user"                         # Elasticsearch authentication username
ES_PASSWORD = "password"                     # Elasticsearch authentication username
ES_TLS = True                                # Elasticsearch TLS encryption
ES_INDEX_PREFIX = "predator"                 # Elasticsearch index prefix (last part is current date, such predator-YYYY.MM.DD
IDS = True                                   # Module L4 enabling
PROXY = True                                 # Module L7 enabling (Proxy)
API = True                                   # Module API enabling
DUMMY = False                                # Module DUMMY enabling
SEND_TO_SYSLOG = False                       # Local syslog forward enabling
SEND_TO_ES = False                           # Elasticsearch forward enabling
```
