from flask import redirect, session, render_template
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


def raise_err(message, code=400):
    return render_template("error.html", top=code, bottom=message), code
