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
      self.cursor = self.sqliteConnection.cursor()
      return True
    except sqlite3.Error as error:
      return False

  def write_threat_l4(self, src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host):
    ret = False
    try:
      sql = "insert into threats (id, src_ip, src_port, dst_ip, dst_port, protocol, flags, content_whitelisted, content_size, content_session_id, event, reporting, sni, host) VALUES ('{}', '{}', {}, '{}', {}, '{}', '{}', '{}', {}, '{}', '{}_{}', '{}', '{}', '{}')".format(id_generator(32), src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host)
      count = self.cursor.execute(sql)
      self.sqliteConnection.commit()
      self.cursor.close()
      self.sqliteConnection.close()
      ret = True
    except sqlite3.Error as error:
      print("Failed to insert data into sqlite table", error)
    finally:
      if self.sqliteConnection:
        self.sqliteConnection.close()
    return ret

  def write_threat_l7(self, src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload):
    ret = False
    try:
      sql = "insert into threats (id, src_ip, src_port, dst_ip, dst_port, protocol, flags, content_whitelisted, content_size, content_session_id, event, reporting, sni, host, payload) VALUES ('{}', '{}', {}, '{}', {}, '{}', '{}', '{}', {}, '{}', '{}_{}', '{}', '{}', '{}', '{}')".format(id_generator(32), src_ip, src_port, dst_ip, dst_port, proto, flags, content_whitelisted, content_size, content_session_id, type_threat, type_flow, reporting, sni, host, payload)
      count = self.cursor.execute(sql)
      self.sqliteConnection.commit()
      self.cursor.close()
      self.sqliteConnection.close()
      ret = True
    except sqlite3.Error as error:
      print("Failed to insert data into sqlite table", error)
    finally:
      if self.sqliteConnection:
        self.sqliteConnection.close()
    return ret

  def write_threat_dns(self, src_ip, src_port, dst_ip, dst_port, proto, reporting, event, rdata, qname):
    ret = False
    try:
      sql = "insert into threats (id, src_ip, src_port, dst_ip, dst_port, protocol, reporting, event, rdata, qname) VALUES ('{}', '{}', {}, '{}', {}, '{}', '{}', '{}', '{}', '{}')".format(id_generator(32), src_ip, src_port, dst_ip, dst_port, proto, reporting, event, rdata, qname)
      count = self.cursor.execute(sql)
      self.sqliteConnection.commit()
      self.cursor.close()
      self.sqliteConnection.close()
      ret = True
    except sqlite3.Error as error:
      print("Failed to insert data into sqlite table", error)
    finally:
      if self.sqliteConnection:
        self.sqliteConnection.close()
    return ret
