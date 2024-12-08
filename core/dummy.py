import config
import threading
import logging

from http.server import BaseHTTPRequestHandler, HTTPServer
from http.server import BaseHTTPRequestHandler, HTTPServer
from core.utils import id_generator

class Dummy:

  def __init__(self, request_method, path, req_body, req_headers, res_code, res_body, res_headers, id_request):
    self.request_method = request_method
    self.path = path
    self.req_body = req_body
    self.req_headers = req_headers
    self.res_code = res_code
    self.res_body = res_body
    self.res_headers = res_headers
    self.id_request = id_request

class S(BaseHTTPRequestHandler):
  def _set_response(self, DummyRequest):
    self.send_response_only(200)
    for k, v in DummyRequest.res_headers.items():
      self.send_header(k, v)
    self.end_headers()
    if isinstance(DummyRequest.res_body, (bytes, bytearray)):
      self.wfile.write(DummyRequest.res_body)
    else:
      self.wfile.write(DummyRequest.res_body.encode())
    config.HTTP_DUMMY_REQUESTS.pop(DummyRequest.id_request, 'None')

  def do_GET(self):
    id_request = self.headers["X-Id-Predator-Request"]
    #config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().debug("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
    self._set_response(config.HTTP_DUMMY_REQUESTS[id_request])
    #self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

  def do_POST(self):
    id_request = self.headers["X-Id-Predator-Request"]
    content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
    post_data = self.rfile.read(content_length) # <--- Gets the data itself
    #config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().debug("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
    self._set_response(config.HTTP_DUMMY_REQUESTS[id_request])
    #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def start_dummy(host, port, server_class=HTTPServer, handler_class=S):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().info("Starting DUMMY..")
    server_address = (host, port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().critical("Tra " + str(config.SLEEP_THREAD_RESTART) + " riavvio il thread")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("dummy() BOOM!!!")
      time.sleep(config.SLEEP_THREAD_SOCKET_RESTART)
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().critical("Riavvio thread")
      start_dummy(host, port)
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_DUMMY"].get_logger().info("Server raggiungibile, riavvio del thread non necessario")
