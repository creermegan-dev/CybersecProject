import os

from flask import Flask, redirect, render_template, request, session, url_for

from auth import get_connection, init_db, register_user, verify_user

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")


def _setup_database():
    try:
        init_db()
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM users")
                count = cur.fetchone()["n"]
        print(f"[OK] MySQL connected — users table has {count} accounts")
    except Exception as e:
        print(f"[WARN] Database not ready: {e}")


_setup_database()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, result = verify_user(username, password)
        if ok:
            session["user"] = result
            return redirect(url_for("login", status="success"))
        return redirect(url_for("login", status="error"))

    return render_template(
        "login.html",
        status=request.args.get("status"),
        user=session.get("user"),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("reg_pass", "")
        confirm_password = request.form.get("reg_pass_confirm", "")
        ok, message = register_user(username, password, confirm_password)
        if ok:
            return redirect(url_for("login", registered="1", user=username))
        return render_template(
            "register.html",
            error=message,
            username=username,
        )

    return render_template(
        "register.html",
        status=request.args.get("status"),
        error=request.args.get("error"),
    )


@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
