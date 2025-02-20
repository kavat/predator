import ssl
import aiohttp
import json
import os
import ctypes
import pprint
import hypercorn.asyncio
import asyncio
import config
import time
import re
import logging

from quart import Quart, request, websocket, Response
from urllib.parse import unquote
from core.utils import check_tcp_conn
from multiprocessing import Process

sni_map = {}

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

def create_path_context(upstream):

  rp = Quart(__name__)

  # Reverse proxy per richieste HTTP
  @rp.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
  async def proxy_request(path):
    async with aiohttp.ClientSession() as session:
      method = request.method
      url = f"{upstream}/{path}"
      headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
      data = await request.get_data()
      query_string = unquote(request.query_string.decode())
      payload = unquote(data.decode() if data else "")

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
      if config.REVERSE_PROXY_STATIC_JUMP == 1:
        return Response(json.dumps(response_data), status=http_status, content_type="application/json")
      else:
        if http_status == 403:
          print("{} = denied for {}".format(path, analysis_r))
          return Response("", status=http_status, content_type="text/html")
        else:
          async with session.request(method, url, headers=headers, data=data) as resp:
            return (await resp.read(), resp.status, resp.headers.items())

  # Reverse proxy per WebSocket
  @rp.websocket('/ws/<path:path>')
  async def proxy_websocket(path):
    ws_target_url = f"{upstream}/ws/{path}"
    async with aiohttp.ClientSession() as session:
      async with session.ws_connect(ws_target_url) as ws:
        # Funzione per inoltrare messaggi tra client e backend
        async def forward_messages(source, destination):
          async for message in source:
            if message.type == aiohttp.WSMsgType.TEXT:
              await destination.send(message.data)
            elif message.type == aiohttp.WSMsgType.BINARY:
              await destination.send_bytes(message.data)

        # Avvia inoltro bidirezionale
        await forward_messages(websocket, ws)
        await forward_messages(ws, websocket)

  return rp

def servername_callback(ssl_sock, servername, ssl_context):
  if servername in sni_map:
    certfile, keyfile = certs[servername]
    ssl_context.load_cert_chain(certfile, keyfile)

def start_reverse_proxies(proxies):
  for proxy in proxies:
    Process(target=start_reverse_proxy, args=(proxy["host"], proxy["port"], proxy["ssl"], proxy["upstream"],)).start()

def start_reverse_proxy(host, port, ssl_arg, upstream):
  try:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info("Starting Reverse Proxy {}:{} towards {}..".format(host, port, upstream))
    config_rp = hypercorn.Config()

    config_rp.bind = "{}:{}".format(host, port)
    if ssl_arg != False:
      config_rp.certfile = ssl_arg["cert"]
      config_rp.keyfile = ssl_arg["key"]

      #config_rp.loglevel = "DEBUG"
      #logging.basicConfig(level=logging.DEBUG)

    asyncio.run(hypercorn.asyncio.serve(create_path_context(upstream), config_rp))
  except Exception as e:
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MAIN"].get_logger().critical(e, exc_info=True)
    config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical("Wait " + str(config.SLEEP_THREAD_RESTART) + " to thread restart")
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_MASTER_EXCEPTIONS"].get_logger().critical("api() BOOM!!!")
      time.sleep(config.SLEEP_THREAD_SOCKET_RESTART)
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().critical("Restarting thread")
      start_reverse_proxy(host, port, ssl_arg, upstream)
    else:
      config.LOGGERS["RESOURCES"]["LOGGER_PREDATOR_REVERSE_PROXY"].get_logger().info("Server reachable, restart not needed")
