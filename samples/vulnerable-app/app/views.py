"""Flask views for the demo shop app. (Intentionally vulnerable.)"""
import hashlib
import os
import pickle
import sqlite3

import requests
from flask import Flask, redirect, render_template_string, request, send_file

app = Flask(__name__)
app.secret_key = "s3cr3t"
conn = sqlite3.connect("shop.db", check_same_thread=False)
UPLOADS = "/var/www/uploads"


@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
    row = cur.fetchone()
    if row and row[2] == hashlib.md5(password.encode()).hexdigest():
        return {"ok": True, "user": row[0]}
    return {"ok": False}, 401


@app.route("/report")
def report():
    days = request.args.get("days", "7")
    rows = conn.execute("SELECT * FROM orders WHERE age < " + days).fetchall()
    return render_template_string("<h1>%s orders</h1>%s" % (days, rows))


@app.route("/export")
def export():
    name = request.args["name"]
    return send_file(os.path.join(UPLOADS, name))


@app.route("/thumbnail")
def thumbnail():
    url = request.args["src"]
    resp = requests.get(url, verify=False, timeout=5)
    return resp.content


@app.route("/import", methods=["POST"])
def import_state():
    session = pickle.loads(request.data)
    return {"restored": len(session)}


@app.route("/admin/backup")
def backup():
    assert request.headers.get("X-Admin") == "true"
    os.system("tar -czf /tmp/backup.tgz /var/www")
    return {"done": True}


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOADS, f.filename))
    return {"saved": f.filename}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
