import ssl
import aiohttp
import json

import modsec._modsecurity as modsecurity
from quart import Quart, request, websocket, Response
from urllib.parse import unquote

import ctypes
import pprint

def init_modsec():
  modsec = modsecurity.msc_init()
  if not modsec:
    raise Exception("Errore nell'inizializzazione di ModSecurity")

  rules_file = "./modsec/rules.conf"
  rules = modsecurity.msc_create_rules_set()

  ret = modsecurity.msc_rules_add_file_py(rules, rules_file)

  if ret < 0:
    raise Exception("Errore nel caricamento delle regole")
  print("[✅] Regole caricate correttamente!")

  return (modsec, rules)

async def analyze_request(modsec, rules, path, method, headers, payload):

  # Crea una transazione
  transaction = modsecurity.msc_new_transaction(modsec, rules, None)
  if not transaction:
    raise Exception("Errore nella creazione della transazione")

  print("[✅] Transazione creata!")

  modsecurity.msc_process_uri(transaction, "http://example.com/{}".format(path), method, "HTTP/1.1")

  for header in headers:
    if header not in ["Accept-Language", "Accept"]:
      print("Carico header {} => {}".format(header, headers[header]))
      modsecurity.msc_add_request_header_py(transaction, header, headers[header])
  modsecurity.msc_process_request_headers(transaction)

  print("Carico il payload: {}".format(payload))
  modsecurity.msc_append_request_body_py(transaction, payload, len(payload))
  modsecurity.msc_process_request_body(transaction)

  return modsecurity.msc_intervention_py(transaction)
  #modsecurity.msc_transaction_cleanup(transaction)

# Configurazione del backend
TARGET_HTTP = "http://backend-server:8000"  # Modifica con il tuo server di destinazione

modsec, rules = init_modsec()
#modsecurity.msc_rules_cleanup(rules);
#modsecurity.msc_cleanup(modsec);

app = Quart(__name__)

# Reverse proxy per richieste HTTP
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(path):
  async with aiohttp.ClientSession() as session:
    method = request.method
    url = f"{TARGET_HTTP}/{path}"
    headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
    data = await request.get_data()
    query_string = request.query_string.decode()
    payload = unquote(data.decode() if data else query_string)

    #print(f"Metodo: {method}")
    #print(f"Path: {path}")
    #print(f"Query String: {query_string}")
    #print(f"Payload: {payload}")
    #print(headers)

    request_analyzed = await analyze_request(modsec, rules, path, method, headers, payload) 
    if request_analyzed['status'] == 403:
      http_status = 403
      response_data = {
        "message": request_analyzed['log'],
        "path": path
      }
    else:
      http_status = 200
      response_data = {
        "message": "ok",
        "path": path
      }
    return Response(json.dumps(response_data), status=http_status, content_type="application/json")
    #async with session.request(method, url, headers=headers, data=data) as resp:
    #  return (await resp.read(), resp.status, resp.headers.items())

# Reverse proxy per WebSocket
@app.websocket('/ws/<path:path>')
async def proxy_websocket(path):
  ws_target_url = f"{TARGET_HTTP}/ws/{path}"
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

# Certificati SSL
SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"

# Avvio del server con Hypercorn
if __name__ == "__main__":
  #ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  #ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)

  import hypercorn.asyncio
  import asyncio
  config = hypercorn.Config()
  config.bind = ["0.0.0.0:8080"]
  #config.bind = ["0.0.0.0:443"]
  #config.ssl = ssl_context

  asyncio.run(hypercorn.asyncio.serve(app, config))
