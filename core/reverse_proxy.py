import ssl
import aiohttp
import json
import os
import ctypes
import logging
import pprint
import hypercorn.asyncio
import asyncio
import config
import time
import re
import gzip
import websockets

from quart import Quart, request, websocket, Response
from urllib.parse import unquote
from core.utils import check_tcp_conn
from multiprocessing import Process
from aiohttp import web

from core.proxy import encode_content_body, decode_content_body
from core.async_client import PredatorAsyncHttpClient
from core.client_ws import connect_ws_fixed

#logging.basicConfig(level=logging.DEBUG)

def analyze_paylod_statically(payloads):
  to_analyze_json = []
  to_analyze_text = []
  payloads_parsed = []

  def loop_array(obj, analysis_r):
    if isinstance(obj, dict):
      for key in obj:
        config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().debug("Key: {}".format(key))
        loop_array(obj[key], analysis_r)
    elif isinstance(obj, list):
      for value in obj:
        if isinstance(value, dict):
          loop_array(value, analysis_r)
        else:
          config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().debug("Value in list: {}".format(value))
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().debug("Value static : {} => {}".format(type(obj), obj))
      for regex in config.REVERSE_PROXY_REGEXP:
        match = re.findall(regex, str(obj))
        if len(match) > 0:
          #print("{}, detection: {}".format(str(obj), len(match)))
          analysis_r.append("{}, detection: {}".format(str(obj), len(match)))

  for payload_q in payloads:
    payload = unquote(payload_q)
    if payload.startswith('{') and payload.endswith('}'):
      try:
        to_analyze_json.append(json.loads(payload))
      except:
        payloads_parsed.append(payload)
    else:
      for payload_ in payload.split('&'):
        to_analyze_text.append(payload_)

  for payload in to_analyze_json:
    namespace = {}
    exec(f"result={payload}", {}, namespace)
    payloads_parsed.append(namespace['result'])

  for payload in to_analyze_text:
    if "=" in payload:
      payloads_parsed.append({payload.split("=")[0]: payload.split("=")[1]})
    else:
      payloads_parsed.append(payload)

  analysis_r = []

  for payload in payloads_parsed:
    loop_array(payload, analysis_r)

  return analysis_r

def create_path_context(upstream_https, upstream_wss):

  rp = Quart(__name__)

  ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  ssl_context.check_hostname = False
  ssl_context.verify_mode = ssl.CERT_NONE

  # Reverse proxy for websocket request
  @rp.websocket("/<path:path>")
  async def proxy_websocket(path):
    headers = {key: value for key, value in websocket.headers.items()}  # Copia degli header
    try:
      await websocket.accept()
      async with connect_ws_fixed(f"{upstream_wss}/{path}", extra_headers=headers, ssl=ssl_context) as ws:
        async def forward_client_to_server():
          while True:
            message = await websocket.receive()
            await ws.send(message)

        async def forward_server_to_client():
          while True:
            message = await ws.recv()
            await websocket.send(message)
        await asyncio.gather(forward_client_to_server(), forward_server_to_client())
    except websockets.exceptions.InvalidStatusCode as e:
      print(f"Errore nella connessione WebSocket: {e}")

  # Reverse proxy for HTTP request
  @rp.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
  async def proxy_http(path):
    headers = {key: value for key, value in request.headers.items() }
    method = request.method

    #data = await request.get_data()
    data = await request.data
    query_string = unquote(request.query_string.decode())
    payload = unquote(data.decode() if data else "")
    if isinstance(payload, (bytes, bytearray)):
      try:
        payload = payload.decode()
      except:
        return Response("Denied, unable decoding payload", status=403, content_type="text/html") 

    analysis_r = analyze_paylod_statically([query_string, payload])
    if len(analysis_r) == 0:
      http_status = 200
      response_data = {
        "message": "ok",
        "path": path
      }
    else:
      http_status = 403
      response_data = {
        "message": "ko",
        "path": path,
        "analysis": analysis_r
      }
    if http_status == 403:
      print("{} = denied for {}".format(path, analysis_r))
      return Response("Denied, {} {}".format(path, analysis_r), status=http_status, content_type="text/html")
    else:

      client = PredatorAsyncHttpClient(base_url=upstream_https, headers=headers)

      if method == "GET":
        if query_string != "":
          url_to_call = "/{}?{}".format(path, query_string)
        else:
          url_to_call = "/{}".format(path)
        resp = await client.get(url_to_call)
      else:
        if query_string != "":
          url_to_call = "/{}?{}".format(path, query_string)
        else:
          url_to_call = "/{}".format(path)
        resp = await client.request(method, url_to_call, data=payload)

      await client.close()

      content = resp.read()
      set_cookie_headers = resp.headers.get_list("set-cookie")
      content_encoded = encode_content_body(content, resp.headers.get("Content-Encoding", "identity"))
      response = Response(content_encoded, status=resp.status_code)
      for key, value in resp.headers.items():
        if key.lower() != "set-cookie":
          response.headers[key] = value

      response.headers['Content-Length'] = str(len(content_encoded))

      for cookie in set_cookie_headers:
        response.headers.add("Set-Cookie", cookie)

      if 'Origin' in headers:
        response.headers["Access-Control-Allow-Origin"] = headers['Origin']
        response.headers["Vary"] = 'Origin'

      return response

  return rp

def start_reverse_proxies(proxies):
  for proxy in proxies:
    Process(target=start_reverse_proxy, args=(proxy["host"], proxy["port"], proxy["ssl"], proxy["upstream_https"], proxy["upstream_wss"],)).start()

def start_reverse_proxy(host, port, ssl_arg, upstream_https, upstream_wss):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info("Starting Reverse Proxy {}:{} towards {}..".format(host, port, upstream_https, upstream_wss))
    config_rp = hypercorn.Config()

    config_rp.bind = "{}:{}".format(host, port)

    if ssl_arg != False:
      config_rp.certfile = ssl_arg["cert"]
      config_rp.keyfile = ssl_arg["key"]

    asyncio.run(hypercorn.asyncio.serve(create_path_context(upstream_https, upstream_wss), config_rp))

  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical("Wait " + str(config.SLEEP_THREAD_RESTART) + " to thread restart")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("api() BOOM!!!")
      time.sleep(config.SLEEP_THREAD_SOCKET_RESTART)
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical("Restarting thread")
      start_reverse_proxy(host, port, ssl_arg, upstream_https, upstream_wss)
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info("Server reachable, restart not needed")
