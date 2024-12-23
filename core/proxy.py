import asyncio
import glob
import gzip
import http.client
import http.server
import importlib
import json
import os
import re
import select
import socket
import ssl
import sys
import threading
import time
import urllib.request
import urllib.parse
import zlib
import string
import random
import config
import brotli
import websocket

from core.dummy import Dummy
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from subprocess import PIPE, Popen
from core.utils import id_generator, inspect_packet_content
from base64 import b64encode
from hashlib import sha1
from io import StringIO, BytesIO

FIN    = 0x80
OPCODE = 0xf
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

OPCODE_BINARY = 0x2
OPCODE_PING = 0x9
OPCODE_PONG = 0xa
OPCODE_CONTINUE = 0x0
OPCODE_TEXT = 0x1
CLOSE_CONN  = 0x8

_ws_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
#_opcode_continu = 0x0
#_opcode_text = 0x1
#_opcode_binary = 0x2
#_opcode_close = 0x8
#_opcode_ping = 0x9
#_opcode_pong = 0xa


class WebSocketError(Exception):
  pass

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
  address_family = socket.AF_INET
  daemon_threads = True

  def handle_error(self, request, client_address):
    # surpress socket/ssl related errors
    cls, e = sys.exc_info()[:2]
    if cls is socket.error or cls is ssl.SSLError:
      pass
    else:
      return HTTPServer.handle_error(self, request, client_address)


class HttpProxy(BaseHTTPRequestHandler):
  lock = threading.Lock()

  def __init__(self, *args, **kwargs):
    self.tls = threading.local()
    self.tls.conns = {}
    self.id_thread = id_generator()

    super().__init__(*args, **kwargs)

  def log_message(self, format, *args):
    pass
    #stringa_log = "%s %s - - [%s] %s\n" % (self.id_thread, self.address_string(), self.log_date_time_string(), format%args)
    #config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(stringa_log)

  def log_error(self, format, *args):
    # surpress "Request timed out: timeout('timed out',)"
    if isinstance(args[0], socket.timeout):
      return

    self.log_message(format, *args)

  def do_CONNECT(self):
    host, _ = self.path.split(":", 1)
    if (os.path.isfile(config.CA_KEY) and os.path.isfile(config.CA_CRT) and os.path.isfile(config.CERT_KEY) and os.path.isdir(config.CERT_DIR)):
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - HTTPS mitm enabled, Intercepting...")
      self.connect_intercept()
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - HTTPS relay only, NOT Intercepting...")
      self.connect_relay()

  def connect_intercept(self):
    hostname = self.path.split(":")[0]
    certpath = os.path.join(config.CERT_DIR, hostname + ".pem")
    confpath = os.path.join(config.CERT_DIR, hostname + ".conf")

    with self.lock:
      # stupid requirements from Apple: https://support.apple.com/en-us/HT210176
      if not os.path.isfile(certpath):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
          category = "IP"
        else:
          category = "DNS"
        with open(confpath, "w") as f:
          f.write(
            "subjectAltName=%s:%s\nextendedKeyUsage=serverAuth\n"
            % (category, hostname)
          )
        epoch = "%d" % (time.time() * 1000)
        # CSR
        p1 = Popen(
          [
            "openssl",
            "req",
            "-sha256",
            "-new",
            "-key",
            config.CERT_KEY,
            "-subj",
            "/CN=%s" % hostname,
            "-addext",
            "subjectAltName=DNS:%s" % hostname,
          ],
          stdout=PIPE,
        )
        # Sign
        p2 = Popen(
          [
            "openssl",
            "x509",
            "-req",
            "-sha256",
            "-days",
            "365",
            "-CA",
            config.CA_CRT,
            "-CAkey",
            config.CA_KEY,
            "-set_serial",
            epoch,
            "-out",
            certpath,
            "-extfile",
            confpath,
          ],
          stdin=p1.stdout,
          stderr=PIPE,
        )
        p2.communicate()

    self.send_response(200, "Connection Established")
    self.end_headers()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certpath, config.CERT_KEY)
    try:
      self.connection = context.wrap_socket(self.connection, server_side=True)
    except ssl.SSLEOFError:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Handshake refused by " + hostname)
      return
    self.rfile = self.connection.makefile("rb", self.rbufsize)
    self.wfile = self.connection.makefile("wb", self.wbufsize)

    conntype = self.headers.get("Proxy-Connection", "")
    if self.protocol_version == "HTTP/1.1" and conntype.lower() != "close":
      self.close_connection = False
    else:
      self.close_connection = True

  def connect_relay(self):
    address = self.path.split(":", 1)
    address = (address[0], int(address[1]) or 443)
    try:
      s = socket.create_connection(address, timeout=config.PROXY_TIMEOUT)
    except Exception:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Errore collegamento verso " + hostname + ", ritorno 502")
      self.send_error(502)
      return
    self.send_response(200, "Connection Established")
    self.end_headers()

    conns = [self.connection, s]
    self.close_connection = False
    while not self.close_connection:
      rlist, wlist, xlist = select.select(conns, [], conns, config.PROXY_TIMEOUT)
      if xlist or not rlist:
        break
      for r in rlist:
        other = conns[1] if r is conns[0] else conns[0]
        data = r.recv(8192)
        if not data:
          self.close_connection = True
          break
        other.sendall(data)

  def duplicate_packet(self, request_method, path, req_body, req_headers, res_code, res_body, res_headers, netloc, origin, conn):
    id_richiesta = id_generator(size=12) 
    config.HTTP_DUMMY_REQUESTS[id_richiesta] = Dummy(request_method, path, req_body, req_headers, res_code, res_body, res_headers, id_richiesta)
    try:
      if(request_method == "POST"):
        req = urllib.request.Request("http://" + config.DUMMY_HOST + ":" + str(config.DUMMY_PORT) + "/" + path, method=request_method)
        for header in req_headers:
          req.add_header(header, req_headers[header])
        req.add_header("X-Id-Predator-Request", id_richiesta)
        req.add_header("X-Id-Predator-SourceHost", self.client_address[0])
        req.add_header("X-Id-Predator-SourcePort", self.client_address[1])
        req.add_header("X-Id-Predator-DestinationHost", conn.host)
        req.add_header("X-Id-Predator-DestinationPort", conn.port)
        req.add_header("X-Id-Predator-Netloc", netloc)
        req.add_header("X-Id-Predator-Protocol", origin[0])
        req.add_header("X-Id-Predator-Origin", origin[1])
        r = urllib.request.urlopen(req, data=req_body)

      if(request_method == "GET"):
        req = urllib.request.Request("http://" + config.DUMMY_HOST + ":" + str(config.DUMMY_PORT) + "/" + path, method=request_method)
        for header in req_headers:
          req.add_header(header, req_headers[header])
        req.add_header("X-Id-Predator-Request", id_richiesta)
        req.add_header("X-Id-Predator-SourceHost", self.client_address[0])
        req.add_header("X-Id-Predator-SourcePort", self.client_address[1])
        req.add_header("X-Id-Predator-DestinationHost", conn.host)
        req.add_header("X-Id-Predator-DestinationPort", conn.port)
        req.add_header("X-Id-Predator-Netloc", netloc)
        req.add_header("X-Id-Predator-Protocol", origin[0])
        req.add_header("X-Id-Predator-Origin", origin[1])
        r = urllib.request.urlopen(req)

    except Exception as e:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().error(self.id_thread + " - Errore durante duplicazione pacchetto")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical(e, exc_info=True)
      config.HTTP_DUMMY_REQUESTS.pop(id_richiesta, None) 

  def do_GET(self):

    if self.path == config.LINK_DOWNLOAD_CA:
      self.send_cacert()
      return

    req = self
    content_length = int(req.headers.get("Content-Length", 0))
    req_body = self.rfile.read(content_length) if content_length else b""

    if req.path[0] == "/":
      if isinstance(self.connection, ssl.SSLSocket):
        req.path = "https://%s%s" % (req.headers["Host"], req.path)
      else:
        req.path = "http://%s%s" % (req.headers["Host"], req.path)

    u = urllib.parse.urlsplit(req.path)
    scheme = u.scheme
    netloc = u.netloc
    path = u.path + "?" + u.query if u.query else u.path
    assert scheme in ("http", "https")
    if netloc:
      req.headers["Host"] = netloc
    req.headers = self.filter_headers(req.headers)  # type: ignore

    origin = (scheme, netloc)
    try:
      if origin not in self.tls.conns:
        if scheme == "https":
          self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=config.PROXY_TIMEOUT, context = ssl._create_unverified_context())
        else:
          self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=config.PROXY_TIMEOUT)

      conn = self.tls.conns[origin]
      conn.request(self.command, path, req_body, dict(req.headers))
      res = conn.getresponse()

      # support streaming
      cache_control = res.headers.get("Cache-Control", "")
      if "Content-Length" not in res.headers and "no-store" in cache_control:
        res.headers = self.filter_headers(res.headers)
        self.relay_streaming(res)
        with self.lock:
          analyze_request(req, req_body, res, "", self, req.headers["Host"])
        return

      res_body = res.read()
      res.headers = self.filter_headers(res.headers)

      self.send_response_only(res.status, res.reason)

      for k, v in res.headers.items():
        self.send_header(k, v)

      self.end_headers()
      self.wfile.write(res_body)
      self.wfile.flush()
      
      analyze_request(req, req_body, res, res_body, self, req.headers["Host"])
      if config.DUMMY:
        self.duplicate_packet(self.command, path, req_body, dict(req.headers), res.status, res_body, dict(res.headers), netloc, origin, self.tls.conns[origin])

    except Exception as e:
      if type(e).__name__ != "socket.timeout" and type(e).__name__ != "timeout" and type(e).__name__ != "OSError" and type(e).__name__ != "BrokenPipeError":
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical(e, exc_info=True)
      if config.DUMMY:
        self.duplicate_packet(self.command, path, req_body, dict(req.headers), 200, "Richiesta bloccata", {}, netloc, origin, self.tls.conns[origin])
      if origin in self.tls.conns:
        del self.tls.conns[origin]
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical(self.id_thread + " - Errore su richiesta verso " + req.headers["Host"] + ", ritorno 502")
      self.send_error(502)

    try:
      # chiudo la connessione per evitare il loading infinito della pagina
      self.close_connection = True
    except:
      return

  def relay_streaming(self, res):
    self.send_response_only(res.status, res.reason)
    for k, v in res.headers.items():
      self.send_header(k, v)
    self.end_headers()
    try:
      while True:
        chunk = res.read(8192)
        if not chunk:
          break
        self.wfile.write(chunk)
      self.wfile.flush()
    except socket.error:
      # connection closed by client
      pass

  do_HEAD = do_GET
  do_POST = do_GET
  do_PUT = do_GET
  do_DELETE = do_GET
  do_OPTIONS = do_GET

  def filter_headers(self, headers: HTTPMessage) -> HTTPMessage:
    # http://tools.ietf.org/html/rfc2616#section-13.5.1
    hop_by_hop = (
      "connection",
      "keep-alive",
      "proxy-authenticate",
      "proxy-authorization",
      "te",
      "trailers",
      "transfer-encoding",
      "upgrade",
    )
    for k in hop_by_hop:
      del headers[k]

    # accept only supported encodings
    if "Accept-Encoding" in headers:
      ae = headers["Accept-Encoding"]
      filtered_encodings = [
        x
        for x in re.split(r",\s*", ae)
        if x in ("identity", "gzip", "x-gzip", "deflate", "br")
      ]
      headers["Accept-Encoding"] = ", ".join(filtered_encodings)

    return headers

  def encode_content_body(self, text: bytes, encoding: str) -> bytes:
    if encoding == "identity":
      data = text
    elif encoding in ("gzip", "x-gzip"):
      data = gzip.compress(text)
    elif encoding == "deflate":
      data = zlib.compress(text)
    elif encoding ==  "br":
      data = brotli.compress(text)
    else:
      raise Exception("Unknown Content-Encoding: %s" % encoding)
    return data

  def decode_content_body(self, data: bytes, encoding: str, id_thread: str, hostname: str) -> bytes:
    if encoding == "identity":
      text = data
    elif encoding in ("gzip", "x-gzip"):
      if isinstance(data, (bytes, bytearray)):
        text = gzip.decompress(data)
      else:
        text = gzip.decompress(str.encode(data))
    elif encoding == "deflate":
      try:
        text = zlib.decompress(data)
      except zlib.error:
        text = zlib.decompress(data, -zlib.MAX_WBITS)
    elif encoding == "br":
      if isinstance(data, (bytes, bytearray)):
        text = brotli.decompress(data)
      else:
        text = brotli.decompress(str.encode(data))
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().warn(id_thread + " - " + hostname + " Unknown Content-Encoding: " + encoding)
    if isinstance(text, (bytes, bytearray)):
      try:
        return text.decode() 
      except:
        return text
    return text

  def send_cacert(self):
    with open(config.CA_CRT, "rb") as f:
      data = f.read()

    self.send_response(200, "OK")
    self.send_header("Content-Type", "application/x-x509-ca-cert")
    self.send_header("Content-Length", str(len(data)))
    self.send_header("Connection", "close")
    self.end_headers()
    self.wfile.write(data)


class WsHttpProxy(HttpProxy):

  mutex = threading.Lock()

  def do_GET(self):
    if self.headers.get("Upgrade", None) == "websocket":
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Initiating websocket handshake")
      self._handshake()
      self._read_messages()
    else:
      HttpProxy.do_GET(self)

  def _read_messages(self):
    while self.connected == True:
      self._read_next_message()
      time.sleep(0.1)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Terminate connessione")
    self._ws_close()

  def read_bytes(self, num):
    bytes = self.rfile.read(num)
    if sys.version_info[0] < 3:
      return map(ord, bytes)
    else:
      return bytes

  def _read_next_message(self):

    b1, b2 = self.read_bytes(2)

    fin    = b1 & FIN
    self.opcode = b1 & OPCODE
    masked = b2 & MASKED
    payload_length = b2 & PAYLOAD_LEN

    if not b1:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Client closed connection")
      self.connected = False
      return
    if self.opcode == CLOSE_CONN:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Client asked to close connection")
      self.connected = False
      return
    if not masked:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Client must always be masked")
      self.connected = False
      return

    if payload_length == 126:
      payload_length = struct.unpack(">H", self.rfile.read(2))[0]
    elif payload_length == 127:
      payload_length = struct.unpack(">Q", self.rfile.read(8))[0]

    masks = self.read_bytes(4)
    decoded = ""
    for char in self.read_bytes(payload_length):
      char ^= masks[len(decoded) % 4]
      decoded += chr(char)
    self._on_message(decoded)

  def send_message(self, message):
    self.send_msg(message)

  def _read_next_message_old(self):
    try:
      self.opcode = ord(self.rfile.read(1)) & 0x0F
      length = ord(self.rfile.read(1)) & 0x7F
      if length == 126:
        length = struct.unpack(">H", self.rfile.read(2))[0]
      elif length == 127:
        length = struct.unpack(">Q", self.rfile.read(8))[0]
      masks = [byte for byte in self.rfile.read(4)]
      decoded = ""
      for char in self.rfile.read(length):
        decoded += chr(char ^ masks[len(decoded) % 4])
      self._on_message(decoded)
    except Exception as e:
      if self.connected:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().error(self.id_thread + " - Websocket read aborted while listening")
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().error(self.id_thread + " - _read_next_message aborted after closed connection")

  def send_msg(self, payload):
    frame = websocket.ABNF.create_frame(payload, websocket.ABNF.OPCODE_BINARY)
    data = frame.format()
    length = len(data)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - INVIO AL CLIENT: " + frame.__str__() + ", " + repr(data))
    with self.lock:
      while data:
        l = self.connection.send(data)
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - INVIATI AL CLIENT: " + str(l) + " bytes")
        data = data[l:]

  def send_close_message(self, message):
    msg = bytearray()
    msg.append(0x80 + self._opcode_close)
    msg.append(0x00)
    self.connection.send(msg)

  def _handshake(self):
    headers=self.headers
    if headers.get("Upgrade", None) != "websocket":
      return
    key = headers['Sec-WebSocket-Key']
    protocol = headers.get('Sec-WebSocket-Protocol')
    digest = b64encode(sha1((key + _ws_GUID).encode('utf-8')).digest()).strip().decode()

    self.send_response_only(101, 'Switching Protocols')
    self.send_header('Upgrade', 'websocket')
    self.send_header('Connection', 'Upgrade')
    self.send_header('Sec-WebSocket-Accept', digest)
    if protocol:
      self.send_header('Sec-WebSocket-Protocol', protocol)
    self.end_headers()
    self.connected = True
    #self.close_connection = 0 # INTERESTING, DO WE NEED TO UNCOMMENT THIS?
    self.on_ws_connected()

  def _ws_close(self):
    #avoid closing a single socket two time for send and receive.
    self.mutex.acquire()
    try:
      if self.connected:
        self.connected = False
        #Terminate BaseHTTPRequestHandler.handle() loop:
        self.close_connection = 1
        #send close and ignore exceptions. An error may already have occurred.
        try:
          self._send_close()
        except:
          pass
        self.on_ws_closed()
      else:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - _ws_close websocket in closed state. Ignore.")
        pass
    finally:
      self.mutex.release()

  def _on_message(self, message):
    if self.opcode == CLOSE_CONN:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - Gestisco chiusura arrivata da browser")
      self.connected = False
      #Terminate BaseHTTPRequestHandler.handle() loop:
      self.close_connection = 1
      try:
        self._send_close()
      except:
        pass
      self.on_ws_closed()
    elif self.opcode == OPCODE_PING:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - Gestisco PING arrivato da browser")
      self._send_message(self._opcode_pong, message)
    elif self.opcode == OPCODE_PONG:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - Gestisco PONG arrivato da browser")
      pass
    elif (self.opcode == OPCODE_CONTINUE or self.opcode == OPCODE_TEXT or self.opcode == OPCODE_BINARY):
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - Gestisco Messaggio arrivato da browser")
      self.on_ws_message(message)

  def _send_close(self):
    #Dedicated _send_close allows for catch all exception handling
    msg = bytearray()
    msg.append(0x80 + self._opcode_close)
    msg.append(0x00)
    self.connection.send(msg)

  def request_handler(self, req, req_body):
    """Override this handler to process incoming HTTP requests. (Return the modified body)"""
    pass

  def response_handler(self, req, req_body, res, res_body):
    """Override this handler to process outgoing HTTP responses. (Return the modified body)"""
    pass

  def save_handler(self, req, req_body, res, res_body):
    """Override this handler to log full HTTP REQ/RES pairs. Default action: print to console."""
    #self.print_info(req, req_body, res, res_body)
    pass

  def on_ws_message(self, message):
    """Override this handler to process incoming websocket messages."""
    pass

  def on_ws_connected(self):
    """Override this handler."""
    pass

  def on_ws_closed(self):
    """Override this handler."""
    pass


class ProxyRequestHandler(WsHttpProxy):
  _closed = False

  def on_ws_message(self, message):
    if message is None:
      message = b''
    # Send client message to remote
    try:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - CLIENT TO SERVER: " + str(message))
      self._remote_websocket.send_binary(message)
    except websocket._exceptions.WebSocketConnectionClosedException:
      self._remote_websocket.send_close() 

  def on_ws_connected(self):
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - websocket connected")

    # Called whenever a new connection is made to the server
    secure = True
    if secure:
      remote_url = "wss://" + self.headers['Host'] + self.path
    else:
      remote_url = "ws://" + self.headers['Host'] + self.path
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Connecting to remote websocket " + remote_url)

    self._remote_websocket = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    
    headers_ws = {} 
    headers_to_discard = ["Sec-WebSocket-Version", "Upgrade"]
    for k,v in self.headers.items():
      if k not in headers_to_discard:
        headers_ws[k] = v

    def forward_to_client(proxy_obj):
      # Send responses to client
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Starting thread to forward remote server messages to the client")
      while not proxy_obj._closed:
        try:
          message = proxy_obj._remote_websocket.recv()
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(self.id_thread + " - RICEVO DA SERVER: " + str(message) + " di tipo " + str(type(message)))
          proxy_obj.send_message(message)
        except websocket._exceptions.WebSocketConnectionClosedException:
          proxy_obj._closed = True  
      proxy_obj._remote_websocket.close()
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Remote websocket connection closed")

    try:
      self._remote_websocket.connect(remote_url, header=headers_ws) 
      threading.Thread(target=forward_to_client, args=(self,)).start()
    except TimeoutError:
      pass

  def on_ws_closed(self):
    self._closed = True
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(self.id_thread + " - Client websocket closed")


def parse_qsl(s):
  return "\n".join(
    "%-20s %s" % (k, v)
    for k, v in urllib.parse.parse_qsl(s, keep_blank_values=True)
  )


def log_record_req(buffer, req, suffix, proxy_request, hostname, log_level):
  if isinstance(buffer, (bytes, bytearray)) == False:
    for riga in buffer.split("\n"):
      if riga != "":
        if log_level == "debug":
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(proxy_request.id_thread + " - " + str(req.address_string()) + " " + hostname + " " + suffix + ": " + riga)
        else:
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(proxy_request.id_thread + " - " + str(req.address_string()) + " " + hostname + " " + suffix + ": " + riga)

def log_record_res(buffer, res, suffix, proxy_request, source, hostname, log_level):
  if isinstance(buffer, (bytes, bytearray)) == False:
    for riga in buffer.split("\n"):
      if riga != "":
        if log_level == "debug":
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().debug(proxy_request.id_thread + " - " + hostname + " " + source + " " + suffix + ": " + riga)
        else:
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info(proxy_request.id_thread + " - " + hostname + " " + source + " " + suffix + ": " + riga)

def analyze_request(req, req_body, res, res_body, proxy_request, hostname):
  req_header_text = "%s %s %s\n%s" % (
    req.command,
    req.path,
    req.request_version,
    req.headers,
  )
  version_table = {10: "HTTP/1.0", 11: "HTTP/1.1"}
  res_header_text = "%s %d %s\n%s" % (
    version_table[res.version],
    res.status,
    res.reason,
    res.headers,
  )

  log_record_req(req_header_text, req, "req_header_text", proxy_request, hostname, "debug")

  u = urllib.parse.urlsplit(req.path)
  if u.query:
    query_text = parse_qsl(u.query)
    log_record_req(query_text, req, "query_text", proxy_request, hostname, "debug")

  cookie = req.headers.get("Cookie", "")
  if cookie:
    cookie = parse_qsl(re.sub(r";\s*", "&", cookie))
    log_record_req(cookie, req, "cookie", proxy_request, hostname, "debug")

  auth = req.headers.get("Authorization", "")
  if auth.lower().startswith("basic"):
    token = auth.split()[1].decode("base64")
    log_record_req(token, req, "token", proxy_request, hostname, "debug")

  if req_body is not None:
    req_body_text = None
    content_type = req.headers.get("Content-Type", "")
    content_encoding = req.headers.get("Content-Encoding", "identity")
    req_body_text = proxy_request.decode_content_body(req_body, content_encoding, proxy_request.id_thread, hostname)

    if content_type.startswith("application/x-www-form-urlencoded"):
      req_body_text = parse_qsl(req_body)
    elif content_type.startswith("application/json"):
      try:
        json_obj = json.loads(req_body)
        json_str = json.dumps(json_obj, indent=2)
        if json_str.count("\n") < 50:
          req_body_text = json_str
        else:
          lines = json_str.splitlines()
          req_body_text = "%s\n(%d lines)" % (
            "\n".join(lines[:50]),
            len(lines),
          )
      except ValueError:
        req_body_text = req_body
    elif len(req_body) < 1024:
      req_body_text = req_body

    if req_body_text:
      log_record_req(req_body_text, req, "req_body_text", proxy_request, hostname, "debug")

  log_record_res(res_header_text, res, "res_header_text", proxy_request, req.address_string(), hostname, "debug")

  cookies = res.headers.get("Set-Cookie")
  if cookies:
    log_record_res(cookies, res, "cookies", proxy_request, req.address_string(), hostname, "debug")

  if res_body is not None:
    content_encoding = res.headers.get("Content-Encoding", "identity")
    res_body_text = proxy_request.decode_content_body(res_body, content_encoding, proxy_request.id_thread, hostname)
    content_type = res.headers.get("Content-Type", "")
    if content_type.startswith("application/json"):
      try:
        json_obj = json.loads(res_body)
        json_str = json.dumps(json_obj, indent=2)
        if json_str.count("\n") < 50:
          res_body_text = json_str
        else:
          lines = json_str.splitlines()
          res_body_text = "%s\n(%d lines)" % (
            "\n".join(lines[:50]),
            len(lines),
          )
      except ValueError:
        res_body_text = res_body
    elif content_type.startswith("text/html"):
      if isinstance(res_body, (bytes, bytearray)):
        m = re.search(rb"<title[^>]*>\s*([^<]+?)\s*</title>", res_body, re.I)
      else:
        m = re.search("<title[^>]*>\s*([^<]+?)\s*</title>", res_body, re.I)
      if m:
        log_record_res(m.group(1).decode(), res, "html_title", proxy_request, req.address_string(), hostname, "debug")
    elif content_type.startswith("text/plain"):
      log_record_res(res_body, res, "plain_text", proxy_request, req.address_string(), hostname, "debug")
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().warn(proxy_request.id_thread + " - Unknown Content-Type: " + content_type)

    if res_body_text:
      log_record_res(res_body_text, res, "res_body_text", proxy_request, req.address_string(), hostname, "debug")

  check_content_packet = inspect_packet_content(req_header_text)
  if check_content_packet != "":
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical("LOG=PREDATOR_THREAT SRC=" + str(req.address_string()) + " SPORT=0 DST=" + str(hostname) + " DPORT=0 PROTO=TLS FLAGS=PA PAYLOAD=" + str(check_content_packet) + " REPORTING=patterns EVENT=LAYER7")
  check_content_packet = inspect_packet_content(req_body)
  if check_content_packet != "":
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical("LOG=PREDATOR_THREAT SRC=" + str(req.address_string()) + " SPORT=0 DST=" + str(hostname) + " DPORT=0 PROTO=TLS FLAGS=PA PAYLOAD=" + str(check_content_packet) + " REPORTING=patterns EVENT=LAYER7")
  check_content_packet = inspect_packet_content(res_body_text)
  if check_content_packet != "":
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_THREATS"].get_logger().critical("LOG=PREDATOR_THREAT SRC=" + str(hostname) + " SPORT=0 DST=" + str(req.address_string()) + " DPORT=0 PROTO=TLS FLAGS=PA PAYLOAD=" + str(check_content_packet) + " REPORTING=patterns EVENT=LAYER7")

def encode_to_UTF8(data):
  try:
    return data.encode('UTF-8')
  except UnicodeEncodeError as e:
    print("Could not encode data to UTF-8 -- %s" % e)
    return False
  except Exception as e:
    raise(e)
    return False

def try_decode_UTF8(data):
  try:
    #return data.decode('utf-8').replace('\n','')
    return data.decode('utf-8')
  except UnicodeDecodeError:
    return False
  except Exception as e:
    raise(e)

def start_proxy(host, port, protocol):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info("Starting Proxy..")
    http.server.test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol=protocol, port=port, bind=host)
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical("Tra " + str(config.SLEEP_THREAD_RESTART) + " riavvio il thread")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("api() BOOM!!!")
      time.sleep(config.SLEEP_THREAD_SOCKET_RESTART)
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().critical("Riavvio thread")
      start_proxy(host, port, protocol)
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_PROXY"].get_logger().info("Server raggiungibile, riavvio del thread non necessario")
