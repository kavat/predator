import config

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from datetime import datetime

class Elk:

  def __init__(self):
    self.url = config.ES_URL
    self.auth = config.ES_AUTH
    self.tls = config.ES_TLS
    if self.auth:
      self.username = config.ES_USERNAME
      self.password = config.ES_PASSWORD
    self.client = self.create_client()

  def create_client(self):
    try:
      if self.auth:
        return Elasticsearch([self.url], basic_auth=(self.username, self.password), ca_certs=False, verify_certs=False)
      else:
        if self.tls == True:
          return Elasticsearch([self.url], ca_certs=False, verify_certs=False)
        else:
          return Elasticsearch([self.url])
    except Exception as e:
      print(e, exc_info=True)
      return 0

  def query(self, index, query):
    r = {}
    if self.client != 0:
      try:
        r['hits'] = scan(self.client, index=index, query=query, raise_on_error=False, preserve_order=True, size=10, scroll='2m')
        r['error'] = 'ok'
      except Exception as e:
        r['error'] = e
    return r
