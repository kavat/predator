from flask import Flask, request, render_template

from core.elk import Elk

import traceback
import config

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def dashboard():
  query = None
  results = {}

  if request.method == "POST":
    query = request.form.get("query", "*")

    search_body = {
      "query": {
        "query_string": {
          "query": query
        }
      }
    }
    response = Elk().query("predator-*", search_body)
    if "hits" in response:
      results = response["hits"]

  return render_template("index.html", query=query, results=results)

try:
  app.run(config.DASHBOARD_HOST, config.DASHBOARD_PORT)
except Exception as e:
  print(e)
  print(traceback.format_exc())
