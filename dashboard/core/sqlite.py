import sqlite3
import config

from core.common_utils import id_generator

class SQLite:

  def __init__(self):
    self.dbpath = config.PATH_SQLITE
    self.connect()

  def connect(self):
    try:
      self.sqliteConnection = sqlite3.connect("{}/predator.db".format(self.dbpath))
      self.sqliteConnection.row_factory = sqlite3.Row
      self.cursor = self.sqliteConnection.cursor()
      return True
    except sqlite3.Error as error:
      return False

  def get(self, sql):
    ret = []
    self.cursor.execute(sql)
    rows = self.cursor.fetchall()
    self.cursor.close()
    self.sqliteConnection.close()
    for row in rows:
      ret.append({'_id': row['id'], '_source': {
        'timestamp': row['timestamp'],
        'src_ip': row['src_ip'],
        'src_port': row['src_port'],
        'dst_ip': row['dst_ip'],
        'dst_port': row['dst_port'],
        'protocol': row['protocol'],
        'flags': row['flags'],
        'content_whitelisted': row['content_whitelisted'],
        'content_size': row['content_size'],
        'content_session_id': row['content_session_id'],
        'event': row['event'],
        'reporting': row['reporting'],
        'sni': row['sni'],
        'host': row['host'],
        'payload': row['payload'],
        'rdata': row['rdata'],
        'qname': row['qname']
      }})
    return ret
