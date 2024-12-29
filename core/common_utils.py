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

from glob import glob

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
