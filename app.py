import sqlite3
import bcrypt
import re
from helpers import login_required, raise_err
from flask import Flask, session, redirect, request, render_template, g, url_for
from flask_session import Session

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("data/database.db")
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with open("data/schema.sql", "r", encoding="utf-8") as f:
        db.executescript(f.read())


with app.app_context():
    init_db()


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "GET":
        db = get_db()
        row = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        row_info = db.execute("SELECT name, email, phone FROM info WHERE user_id = ?", (session["user_id"], )).fetchone()

        name = row_info["name"]
        email = row_info["email"]
        phone = row_info["phone"]
        return render_template("index.html", username=row["username"], name=name, email=email, phone=phone)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirm_pass = request.form.get("confirm_password")

    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username, )).fetchone()
    if row is not None:
        return raise_err("This user already exists.")

    if password != confirm_pass:
        return raise_err("The passwords must match.")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hashed))
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
    db.execute("INSERT INTO info (user_id) VALUES (?)", (user_id,))
    db.commit()
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    db = get_db()
    row = db.execute("SELECT id, hash FROM users WHERE username = ?", (username, )).fetchone()

    if row is None:
        return raise_err("This user does not exists.")

    if not bcrypt.checkpw(password.encode(), row["hash"]):
        return raise_err("The passwords don't match")

    session["user_id"] = row["id"]
    return redirect("/")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.clear()
    return redirect("/login")


@app.route("/profiles", methods=["GET", "POST"])
@login_required
def profiles():
    db = get_db()
    row = db.execute("SELECT username FROM users").fetchall()

    if request.method == "GET":
        return render_template("profiles.html", profiles=row)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    db = get_db()
    
    row_users = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    row_info = db.execute("SELECT name, email, phone FROM info WHERE user_id = ?", (session["user_id"],)).fetchone()

    username = row_users["username"]
    name = row_info["name"]
    email = row_info["email"]
    phone = row_info["phone"]

    return render_template("settings.html", username=username, name=name, email=email, phone=phone)

@app.route("/settings/change_username", methods=["POST"])
@login_required
def change_username():
    db = get_db()
    new_username = request.form.get("username")
    exists = db.execute("SELECT id FROM users WHERE username = ?", (new_username, )).fetchone()

    if exists is not None:
        return raise_err("This username is already taken")

    db.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, session["user_id"]))
    db.commit()
    return redirect(url_for("settings"))
    

@app.route("/settings/change_password", methods=["POST"])
@login_required
def change_password():
    db = get_db()
    row = db.execute("SELECT hash FROM users WHERE id = ?", (session["user_id"], )).fetchone()
    hashed = row["hash"]

    input_password = request.form.get("password")

    if not bcrypt.checkpw(input_password.encode(), hashed):
        return raise_err("The password is wrong.")

    new_pass = request.form.get("newpass")
    new_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())

    db.execute("UPDATE users SET hash = ? WHERE id = ?", (new_hash, session["user_id"]))
    db.commit()
    return redirect(url_for("settings"))

@app.route("/settings/change_info", methods=["POST"])
@login_required
def change_info():
    db = get_db()

    name = request.form.get("name")
    email = request.form.get("email")

    email_verifier = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_verifier, email):
        return raise_err("Invalid email input")

    phone = request.form.get("phone")

    db.execute("UPDATE info SET name = ?, email = ?, phone = ? WHERE user_id = ?", (name, email, phone, session["user_id"]))
    db.commit()
    return redirect(url_for("settings"))

@app.route("/settings/remove_account", methods=["POST"])
@login_required
def remove_account():
    db = get_db()

    db.execute("DELETE FROM users WHERE id = ?", (session["user_id"], ))
    db.commit()
    return redirect(url_for("logout"))

@app.route("/profile/<username>", methods=["GET", "POST"])
@login_required
def profile(username):
    db = get_db()

    row = db.execute("SELECT id FROM users WHERE username = ?", (username, )).fetchone()
    if not row:
        return raise_err("This user does not exist")

    row_info = db.execute("SELECT * FROM info WHERE user_id = ?", (row["id"], )).fetchone()
    name = row_info["name"]
    email = row_info["email"]
    phone = row_info["phone"]
    return render_template("profile.html", username=username, name=name, email=email, phone=phone)

if __name__ == "__main__":
    app.run(debug=True)

