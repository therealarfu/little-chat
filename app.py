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
        row_info = db.execute("SELECT name, email, phone, desc FROM info WHERE user_id = ?", (session["user_id"], )).fetchone()

        name = row_info["name"]
        email = row_info["email"]
        phone = row_info["phone"]
        description = row_info["desc"]
        return render_template("index.html", username=row["username"], name=name, email=email, phone=phone, description=description)


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
    row_info = db.execute("SELECT name, email, phone, desc FROM info WHERE user_id = ?", (session["user_id"],)).fetchone()

    username = row_users["username"]
    name = row_info["name"]
    email = row_info["email"]
    phone = row_info["phone"]
    description = row_info["desc"]

    return render_template("settings.html", username=username, name=name, email=email, phone=phone, description=description)


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
    description = request.form.get("description")
    
    db.execute("UPDATE info SET name = ?, email = ?, phone = ?, desc = ? WHERE user_id = ?", (name, email, phone, description, session["user_id"]))
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
    desc = row_info["desc"]
    return render_template("profile.html", username=username, name=name, email=email, phone=phone, desc=desc)


@app.route("/send_request/<username>", methods=["POST"])
@login_required
def send_request(username):
    db = get_db()

    row = db.execute("SELECT id FROM users WHERE username = ?", (username, )).fetchone()
    if not row:
        return raise_err("This user does not exist")

    receiver_id = row["id"]
    sender_id = session["user_id"]

    exists_friendship = db.execute("SELECT id FROM friends WHERE user_id = ? AND friend_id = ?", (sender_id, receiver_id)).fetchone()
    if exists_friendship:
        return raise_err(f"You and this user are already friends")

    exists_pending = db.execute("SELECT id FROM friends_requests WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'", (sender_id, receiver_id)).fetchone()
    if exists_pending:
        return raise_err(f"You already sent a request to this user.")

    db.execute("INSERT INTO friends_requests (sender_id, receiver_id, status) VALUES (?, ?, 'pending')", (sender_id, receiver_id))
    db.commit()
    return redirect(url_for("profile", username=username))


@app.route("/requests", methods=["GET", "POST"])
@login_required
def friends_requests():
    db = get_db()

    requests = db.execute("""
        SELECT friends_requests.*, users.username AS sender_username
        FROM friends_requests
        JOIN users ON friends_requests.sender_id = users.id
        WHERE receiver_id = ?
    """, (session["user_id"],)).fetchall()

    requests.sort(key=lambda request: request["created_at"], reverse=True)

    return render_template("requests.html", requests=requests)


@app.route("/requests/accept_request/<id>", methods=["POST"])
@login_required
def accept_request(id):
    db = get_db()

    sent_request = db.execute("SELECT * FROM friends_requests WHERE id = ?", (id, )).fetchone()
    if not sent_request:
        return raise_err("Request not found.")

    friend_exists = db.execute("SELECT id FROM friends WHERE user_id = ? AND friend_id = ?", (sent_request["sender_id"], sent_request["receiver_id"])).fetchone()
    if friend_exists:
        return raise_err("You and this user are already friends.")

    db.execute("UPDATE friends_requests SET status='accepted' WHERE id = ?", (id, ))
    db.execute("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)", (sent_request["sender_id"], sent_request["receiver_id"]))
    db.execute("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)", (sent_request["receiver_id"], sent_request["sender_id"]))
    db.commit()

    return redirect(url_for("friends_requests"))


@app.route("/requests/decline_request/<id>", methods=["POST"])
@login_required
def decline_request(id):
    db = get_db()

    sent_request = db.execute("SELECT * FROM friends_requests WHERE id = ?", (id, )).fetchone()
    if not sent_request:
        return raise_err("Request not found.")

    friend_exists = db.execute("SELECT id FROM friends WHERE user_id = ? AND friend_id = ?", (sent_request["sender_id"], sent_request["receiver_id"])).fetchone()
    if friend_exists:
        return raise_err("You and this user are already friends.")

    db.execute("UPDATE friends_requests SET status='rejected' WHERE id = ?", (id, ))
    db.commit()

    return redirect(url_for("friends_requests"))  


@app.route("/requests_sent", methods=["GET", "POST"])
@login_required
def requests_sent():
    db = get_db()

    requests = db.execute("""SELECT friends_requests.*, users.username AS receiver_username FROM friends_requests
        JOIN users ON friends_requests.receiver_id = users.id WHERE sender_id = ?""", (session["user_id"], )).fetchall()

    requests.sort(key=lambda request: request["created_at"], reverse=True)

    return render_template("sent_requests.html", requests=requests)


@app.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    db = get_db()

    friends = db.execute("""SELECT friends.*, users.username AS friend_username
        FROM friends JOIN users ON friends.friend_id = users.id
        WHERE user_id = ?""", (session["user_id"], )).fetchall()

    return render_template("friends.html", friends=friends)


@app.route("/friends/remove_friend/<friend_username>", methods=["GET", "POST"])
@login_required
def remove_friend(friend_username):
    db = get_db()

    friend = db.execute("SELECT id FROM users WHERE username = ?", (friend_username, )).fetchone()
    if not friend:
        return raise_err("This user does not exist")
    friend_id = friend["id"]

    exists_friendship = db.execute("SELECT id FROM friends WHERE user_id = ? AND friend_id = ?", (session["user_id"], friend_id)).fetchone()
    if not exists_friendship:
        return raise_err("This friendship does not exist")

    db.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (session["user_id"], friend_id))
    db.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (friend_id, session["user_id"]))
    db.commit()

    return redirect(url_for("friends"))  

if __name__ == "__main__":
    app.run(debug=True)

