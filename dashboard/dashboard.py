from flask import Flask, request, render_template

from core.elk import Elk
from core.sqlite import SQLite

import traceback
import config
import os
import glob
import json

app = Flask(__name__)

def request_elk(query):
  results = {}
  search_body = {
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {
      "query_string": {
        "query": query
      }
    }
  }
  response = Elk().query("predator-*", search_body)
  if "hits" in response:
    results = response["hits"]
  return results

def request_local_db(query):
  rit = []
  files = list(filter(os.path.isfile, glob.glob(config.PATH_LOCAL_JSON + "/*.json")))
  files.sort(key=lambda x: os.path.getmtime(x))
  for _file in files:
    with open(_file) as f:
      content = f.read()
      if content != "":
        rit.append(json.loads(content))
  return rit

def request_sqlite(query):
  if query == "" or query == "*":
    query = "select * from threats order by timestamp desc;"
  return SQLite().get(query)

@app.route("/", methods=["GET", "POST"])
def dashboard():
  query = None
  results = {}

  if config.READ_THREATS_FROM_ES == True:
    title = "Elasticsearch threats archive"
    if request.method == "POST":
      results = request_elk(request.form.get("query", "*"))

  if config.READ_THREATS_FROM_LOCAL_DB == True:
    title = "Local DB threats archive"
    if request.method == "POST":
      results = request_local_db(request.form.get("query", "*"))

  if config.READ_THREATS_FROM_SQLITE == True:
    title = "SQLite threats archive"
    if request.method == "POST":
      results = request_sqlite(request.form.get("query", "*"))

  return render_template("index.html", title=title, query=query, results=results)

try:
  app.run(config.DASHBOARD_HOST, config.DASHBOARD_PORT)
except Exception as e:
  print(e)
  print(traceback.format_exc())
