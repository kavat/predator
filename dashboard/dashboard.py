from flask import Flask, request, render_template

import traceback
import config

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
  return render_template("index.html", host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)

try:
  app.run(config.DASHBOARD_HOST, config.DASHBOARD_PORT)
except Exception:
  print(traceback.format_exc())
