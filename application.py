from flask import Flask, redirect, render_template, request, session, abort
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
import os
import pathlib
from flask import redirect, session
from functools import wraps
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask(__name__)
app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "829670203166-62ljg3ndisvg775m57p0dhv5i249rh6n.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# def login_required(f):
#     """
#     Decorate routes to require login.
#     http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
#     """
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if session.get("user_id") is None:
#             return redirect("/login")
#         return f(*args, **kwargs)
#     return decorated_function

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine("postgresql://ltuncqvjqmernj:25ce551005ecc623c3dd0e6e311145830d4e4c118e84e0950d9c12c64ff2fe23@ec2-34-194-73-236.compute-1.amazonaws.com:5432/d248g083pk06ka")
db = scoped_session(sessionmaker(bind=engine))

#,methods=["GET", "POST"]
@app.route("/")
def index():
    return render_template("index.html")

# Login with flask Session
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # verificamos si el usuario nuevo ingreso en algo en los campos correspondientes
        if not username:
            return render_template("index.html")

        elif not password:
            return render_template("index.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchall()
        # print(f"{rows}")

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("index.html")

        # Remember which user has logged in
        session["name"] = rows[0]["username"]
        session["google_id"] = rows[0]["id"]
        session["email"] = "No Correo"

        return redirect("/Inicio")
    return render_template("login.html")


# Login with Google
@app.route("/login_google")
def login_google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# Register With Flask Session
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        confirmation = request.form.get("confirmation").strip()

        # verificamos si el usuario nuevo ingreso en algo en los campos correspondientes
        if not username:
            return render_template("register.html")

        elif not password:
            return render_template("register.html")

        elif password != confirmation:
            return render_template("register.html")


        # Verificamos si el nombre del usuario esta disponible
        consulta = db.execute("SELECT username FROM users WHERE username = :username", {"username": username}).fetchall()
        print(f"{consulta}")
        
        if len(consulta) != 0:
            print("Ho0la")
            return render_template("register.html")
        
        print("Hola")
        
        # insertamos al nuevo usuario
        rows = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash) RETURNING id",
                            {"username": username, "hash": generate_password_hash(password)}).fetchone()

        name = db.execute("SELECT username FROM users WHERE username = :username", {"username": username}).fetchone()
        db.commit()

        print(name)
        session["name"] = name[0]
        session["google_id"] = rows[0]
    
        session["email"] = "No Correo"
       

        return redirect("/Inicio")
    else:
       return render_template("register.html")

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    print(id_info)
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    return redirect("/Inicio")

@app.route("/Inicio")
@login_is_required
def Inicio():
    name = session["name"]
    email = session["email"]
    return render_template("inicio.html", name=name, email=email)

if __name__ == "__main__":
    app.run(debug=True)