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
import hashlib
import base64

from hashlib import md5
from glob import glob
from datetime import datetime

def string2b64(string):
  return base64.b64encode(string.encode()).decode('utf-8')

def b642string(string):
  if string == "":
    return ""
  return base64.b64decode(string.encode()).decode('ascii')

def get_string_md5(string):
  return hashlib.md5(string.encode()).hexdigest() 

def parse_json_array(filename):
  ritorno = []
  with open(filename, 'r') as f:
    for data in f.read().split("\n"):
      if(data != ""):
        ritorno = json.loads(data)
  return ritorno

def parse_json(filename):
  ritorno = {}
  with open(filename, 'r') as f:
    for data in f.read().split("\n"):
      if(data != ""):
        ritorno.update(json.loads(data))
  return ritorno

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))

def clear_old_certificates():
  for old_csr in glob(os.path.join(config.CERT_DIR, "*.conf")):
    os.remove(old_csr)
  for old_cert in glob(os.path.join(config.CERT_DIR, "*.pem")):
    os.remove(old_cert)

def append_json_threat(thread_name, data):
  id_log = id_generator(30)
  with open("{}/{}_{}.json".format(config.PATH_LOCAL_JSON, thread_name, id_log), 'w') as f:
    data["@timestamp"] = datetime.utcnow().isoformat()
    json.dump({'_id': id_log, '_source': data}, f)

def get_curdatetime():
  now = datetime.now()
  return now.strftime("%Y-%m-%d %H:%M:%S")
