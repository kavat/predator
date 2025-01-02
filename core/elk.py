import config

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from datetime import datetime

from core.utils import get_es_index_date

class Elk:

  def __init__(self, logger):
    self.url = config.ES_URL
    self.auth = config.ES_AUTH
    self.tls = config.ES_TLS
    if self.auth:
      self.username = config.ES_USERNAME
      self.password = config.ES_PASSWORD
    self.logger = logger
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
      self.logger.get_logger().critical(e, exc_info=True)
      return 0

  def query(self, index, query):
    r = {}
    if self.client != 0:
      try:
        r['hits'] = scan(self.client, index=index, query=query, raise_on_error=True, preserve_order=True, size=10, scroll='2m')
        r['error'] = 'ok'
      except Exception as e:
        r['error'] = e
    return r

  def write_threat_l7(self, src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload):
    try:
      document = {
        "@timestamp": datetime.utcnow().isoformat(),
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'proto': proto,
        'flags': flags,
        'content_whitelisted': content_whitelisted,
        'content_size': content_size,
        'content_session_id': content_session_id,
        'event': "{}_{}".format(type_threat, type_flow), 
        'reporting': reporting,
        'sni': sni,
        'host': host,
        'payload': payload
      }
      return self.client.index(index="{}-{}".format(config.ES_INDEX_PREFIX, get_es_index_date()), document=document)
    except Exception as e:
      self.logger.get_logger().critical(e, exc_info=True) 
      return False

  def write_threat_l4(self, src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host):
    try:
      document = {
        "@timestamp": datetime.utcnow().isoformat(),
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'proto': proto,
        'flags': flags,
        'content_whitelisted': content_whitelisted,
        'content_size': content_size,
        'content_session_id': content_session_id,
        'event': "{}_{}".format(type_threat, type_flow),
        'reporting': reporting,
        'sni': sni,
        'host': host
      }
      return self.client.index(index="{}-{}".format(config.ES_INDEX_PREFIX, get_es_index_date()), document=document)
    except Exception as e:
      self.logger.get_logger().critical(e, exc_info=True)
      return False

  def write_threat_dns(self, src_ip, sport, dst_ip, dport, proto, reporting, event, rdata, qname):
    try:
      document = {
        "@timestamp": datetime.utcnow().isoformat(),
        'src_ip': src_ip,
        'src_port': sport,
        'dst_ip': dst_ip,
        'dst_port': dport,
        'proto': proto,
        'reporting': reporting,
        'event': event,
        'rdata': rdata,
        'qname': qname
      }
      return self.client.index(index="{}-{}".format(config.ES_INDEX_PREFIX, get_es_index_date()), document=document)
    except Exception as e:
      self.logger.get_logger().critical(e, exc_info=True)
      return False
