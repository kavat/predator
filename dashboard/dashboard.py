from flask import Flask, request, render_template

from core.elk import Elk

import traceback
import config

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
  return render_template("index.html", host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)

@app.route("/query", methods=["GET", "POST"])
def dashboard():
  query = None
  results = []

  if request.method == "POST":
    query = request.form.get("query", "*")

    search_body = {
      "query": {
        "query_string": {
          "query": query
        }
      }
    }
    response = Elk().query("predator-*", body=search_body)
    results = response["hits"]["hits"]

  return render_template("dashboard.html", query=query, results=results)

try:
  app.run(config.DASHBOARD_HOST, config.DASHBOARD_PORT)
except Exception:
  print(traceback.format_exc())
