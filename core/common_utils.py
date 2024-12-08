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
