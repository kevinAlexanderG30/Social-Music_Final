from flask import Flask, flash, jsonify, redirect, render_template, request, session, abort, url_for
from flask_session import Session
import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
import os
import pathlib
from functools import wraps
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.utils import secure_filename
from os import remove
#from flask_socketio import SocketIO, emit #join_room, leave_room
from datetime import datetime

app = Flask(__name__)
app = Flask("Google Login App")
app.secret_key = "kevin"


#carpetas 
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
#Perfil
UPLOAD_FOLDER = 'D:\\Desktop\\cs50w-project4\\cs50w-project4\\static\\img'
#publicaciones
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "829670203166-62ljg3ndisvg775m57p0dhv5i249rh6n.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

def login_required(f):
    """
    Decorate routes to require login.
    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("google_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

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
        email = request.form.get("email").strip()
        password = request.form.get("password").strip()

        # verificamos si el usuario nuevo ingreso en algo en los campos correspondientes
        if not email:
            return render_template("login.html")

        elif not password:
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchall()
        # print(f"{rows}")
        #print(f" is_verified {rows[0]['is_verified']}")
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
           return jsonify({"Error de conexion": "Verifique bien su email o password"})
        
        if rows[0]['is_verified'] == False:
            return jsonify({"Error de conexion": "Antes de acceder a esta ruta verifique su correo"})

        # Remember which user has logged in
        session["name"] = rows[0]["email"]
        session["google_id"] = rows[0]["id_users"]
        session["email"] =  rows[0]["email"]

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
        email = request.form.get("email").strip()
        name = request.form.get("name").strip()
        lastname = request.form.get("lastname").strip()
        nacimiento = request.form.get("nacimiento").strip()
        password = request.form.get("password").strip()
        confirmacion_password = request.form.get("confirmacion_password").strip()
        username = request.form.get("username").strip()
        # verificamos si el usuario nuevo ingreso en algo en los campos correspondientes
        if not email or not name or not lastname or not nacimiento or not password or not confirmacion_password or not username:
            return render_template("register.html")

        elif password != confirmacion_password:
            return render_template("register.html")

        # return jsonify({"email": email, 
        #                 "name": name, "lastname":lastname, 
        #                 "nacimiento":nacimiento, 
        #                 "password":password, 
        #                 "confirmacion_password": confirmacion_password   })
       
        # Verificamos si el nombre del usuario esta disponible
        consulta = db.execute("SELECT email FROM users WHERE email = :email", {"email": email}).fetchall()
        print(f"{consulta}")
        consulta2 = db.execute("SELECT username FROM users WHERE username = :username", {"username": username}).fetchall()
        
        if len(consulta2) != 0:
            return "nombre de usuario no disponible"

        if len(consulta) != 0:
            #print("Ho0la")
            return "Email no disponible"
        
        #print("Hola")
        
        # insertamos al nuevo usuario
        db.execute("INSERT INTO users (hash, name, lastname, email, nacimiento, is_verified, foto_google, username) \
                        VALUES (:hash, :name, :lastname, :email, :nacimiento, :is_verified, :foto_google, :username)",
                            {"hash": generate_password_hash(password), "name": name,
                             "lastname": lastname, "email": email, "is_verified": False,
                              "nacimiento": nacimiento, "foto_google": False, "username": username })
        #print(f"consulta: {rows}")
        #email = db.execute("SELECT email FROM users WHERE email = :email", {"email": email}).fetchone()
        db.commit()

        #print(name)
        #session["name"] = name[0]
        #session["google_id"] = rows[0]
        
        #create jwt
        payload_data = {
            "name": name,
            "email":email,
            "lastname": lastname,
            "nacimiento": nacimiento,
            "is_verified": True,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1000),

        }

        token= jwt.encode(
                            payload=payload_data, 
                            key="my_secret_key",  
                            algorithm="HS256"
                            )
        print(token)
        #print(f"Hora: {datetime.datetime.utcnow() + datetime.timedelta(minutes=1000) }")
        #session["email"] = "No Correo"
        
        #Envio de confirmacion
        message = Mail(
        from_email='tkxk3vin@gmail.com',
        to_emails=email,
        subject='Social Musci WEB50-FINAL',
        html_content= f'Confirmacion de email por parte de Social Music <a href="http://localhost:5000/is_verified/{token}">"Confirmar"</a> {token}')
        try:
            sg = SendGridAPIClient("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")
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(str(e))

        return redirect("/login")
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

    rows = db.execute("SELECT * FROM users WHERE email = :email", {"email": id_info.get("email")}).fetchall()
    print(rows)
    if len(rows):
        if rows[0]["email"] == id_info.get("email"):
            session["google_id"] = rows[0]['id_users']
            session["name"] = id_info.get("name")
            session["email"] = id_info.get("email")
            print("Entro en la parte para no registrar")
            return redirect("/Inicio")
    else:
        password = "123456"
        db.execute("INSERT INTO users (hash, name, lastname, email, url_perfil ,nacimiento, is_verified, foto_google) \
                    VALUES (:hash, :name, :lastname, :email, :url_perfil, :nacimiento, :is_verified, :foto_google)",
                            {"hash": generate_password_hash(password), "name": id_info.get("given_name"), 
                            "lastname": id_info.get("family_name"), "email": id_info.get("email"), 
                            "url_perfil": id_info.get("picture"),"is_verified": True, 
                            "nacimiento": "2003-08-30", "foto_google": True })
        
        #print(f"consulta: {rows}")
        #email = db.execute("SELECT email FROM users WHERE email = :email", {"email": email}).fetchone()
        db.commit()
        rows_id = db.execute("SELECT id FROM users WHERE email = :email", {"email": id_info.get("email")}).fetchall()
        #print(f"Id de usuario: {rows_id[0]['id']}")
        #Envio de confirmacion
        session["google_id"] = rows_id[0]['id_users']
        session["name"] =  id_info.get("email")
        session["email"] =  id_info.get("email")
        
        message = Mail(
        from_email='tkxk3vin@gmail.com',
        to_emails= id_info.get("email"),
        subject='Social Musci WEB50-FINAL',
        html_content= f'Bienvenido a Social Music, usted podra acceder mediante Google o el inicio rapido de la app con una contraseña proporcionada: 123456 luego podra cambiar usted la contraseña una vez ingresado en la app igualmente su informacion y nombre<a href="http://localhost:5000/login">"Confirmar"</a>')
        try:
            sg = SendGridAPIClient("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")
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(str(e))
        return redirect("/Inicio")

@app.route("/Inicio")
@login_is_required#a342c17486f965a89c3331ab5ff29e9f10a3aedb564aeae1208945cb602a24a9
def Inicio():
    name = session["name"]
    #resp = requests.get('http://ip-api.com/json/208.80.152.201')
    #json.loads(resp.content)
    #print(resp.content)
    #return jsonify(resp= "hola")
    email = session["email"]
    likes = db.execute("SELECT  likes.megusta, likes.id_like, likes.user_id,publication.id \
        FROM publication INNER JOIN likes ON  likes.publication_id_likes = publication.id").fetchall()
        
    
    
    rows = db.execute("SELECT * FROM users WHERE id_users=:id", {"id": session["google_id"]}).fetchall()
    #Imagenes de quien la publico dentro del inicio
    rows2 = db.execute("SELECT users.id_users, publication.id, publication.image_path, \
        publication.descripcion, publication.date, users.username \
        FROM users INNER JOIN publication ON  publication.user_id = users.id_users", \
                    {}).fetchall()

    #
    rows3 = db.execute("SELECT users.id_users, publication.id, commentary.id_comentario, \
        publication.date, users.url_perfil, users.username, commentary.comentario, commentary.date \
        FROM publication INNER JOIN users ON  users.id_users = publication.user_id \
        INNER JOIN commentary ON commentary.publication_id =  publication.id ", \
                    {}).fetchall()

    #print(f"rows2: {rows2[0]['id']}")
    print(f"Hola mundo {rows3}")
    #SELECT users.id,publication.image_path,publication.descripcion,publication.date,users.username FROM users INNER JOIN publication ON users.id = publication.user_id
    
    content = {
        #Usuario Actual
        "user_actual": rows[0]["id_users"],
        #perfil
        "name": rows[0]["name"],
        "lastname": rows[0]["lastname"],
        "url_perfil": rows[0]["url_perfil"],
        "descripcion": rows[0]["descripcion"],
        "nacimiento": rows[0]["nacimiento"],
        "permitir_foto_google": rows[0]["foto_google"],
        "username": rows[0]["username"],
        
    }
    
    
    return render_template("inicio.html", content=content,item=rows2, comentarios=rows3, likes=likes)

@app.route("/perfil")
@login_required
def perfil():
    likes = db.execute("SELECT  likes.megusta, likes.id_like, likes.user_id,publication.id \
        FROM publication INNER JOIN likes ON  likes.publication_id_likes = publication.id").fetchall()

    seguidores = db.execute("SELECT user_id_follows FROM follows WHERE user_id_follows=:id", 
    {"id": session["google_id"] }).fetchall()
    seguidores = len(seguidores)
    
    seguidos = db.execute("SELECT user_id FROM follows WHERE user_id=:id", 
    {"id": session["google_id"] }).fetchall()
    
    seguidos = len(seguidos)
    
    rows = db.execute("SELECT * FROM users WHERE id_users=:id", {"id": session["google_id"]}).fetchall()
    #Imagenes de quien la publico dentro del perfil
    rows2 = db.execute("SELECT users.id_users, publication.id, publication.image_path, \
        publication.descripcion, publication.date, users.username \
        FROM users INNER JOIN publication ON  publication.user_id = users.id_users  WHERE users.id_users = :id", \
                    {"id": session["google_id"]}).fetchall()

    #
    rows3 = db.execute("SELECT users.id_users, publication.id, commentary.id_comentario, \
        publication.date, users.url_perfil, users.username, commentary.comentario, commentary.date \
        FROM publication INNER JOIN users ON  users.id_users = publication.user_id \
        INNER JOIN commentary ON commentary.publication_id =  publication.id ", \
                    {}).fetchall()

    #print(f"rows2: {rows2[0]['id']}")
    print(rows3[0].id_users)
    #SELECT users.id,publication.image_path,publication.descripcion,publication.date,users.username FROM users INNER JOIN publication ON users.id = publication.user_id
    post = len(rows2)
    content = {
        #Usuario Actual
        "user_actual": rows[0]["id_users"],
        #perfil
        "name": rows[0]["name"],
        "lastname": rows[0]["lastname"],
        "url_perfil": rows[0]["url_perfil"],
        "descripcion": rows[0]["descripcion"],
        "nacimiento": rows[0]["nacimiento"],
        "permitir_foto_google": rows[0]["foto_google"],
        "username": rows[0]["username"],
        #Seguimiento
        "post": post,
        "seguidores": seguidores,
        "seguidos": seguidos,
        
    }
    
    
    return render_template("perfil.html", content=content,item=rows2, comentarios=rows3, likes=likes)

@app.route("/is_verified/<string:token>")
def is_verified(token):
    print(token) 
    SECRET_KEY = "my_secret_key"
    #token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1Ni...."
    try:
        decode_data = jwt.decode(jwt=token, \
                                key=SECRET_KEY, algorithms="HS256")
        print("token es: ")
        print(decode_data)
        #consulta = db.execute("SELECT * FROM users WHERE email = :email", {"email": decode_data["email"]}).fetchall()
        #print(consulta)
        #Actualizar al usuario que ha confirmado
        db.execute("UPDATE users SET is_verified = :is_verified WHERE email = :email", 
                    {"is_verified": decode_data["is_verified"], "email": decode_data["email"]})
        db.commit()
   #SELECT users.id,publication.image_path,publication.descripcion,publication.date,users.username FROM users INNER JOIN publication ON users.id = publication.user_id 
    except Exception as e:
        message = f"Token is invalid --> {e}"
        print({"message": message})

    return jsonify({"decode_data"
    : decode_data}) #render_template("verified.html")

@app.route("/configuraciones", methods=["GET", "POST"])
def configuraciones():
    if request.method == "POST":
        return render_template("configuraciones.html")
    return render_template("configuraciones.html")

@app.route("/change_data_profile", methods=["POST"])
def change_data_profile():
    username = request.form.get("username")
    name = request.form.get("name")
    lastname = request.form.get("lastname")
    descripcion = request.form.get("description")
    nacimiento = request.form.get("nacimiento")
    if  username == None:
        return "El valor que desea actualizar no es un valor permitido en el campo de username"
    if not username or not name or not lastname or not nacimiento:
        return "No ha introducido en los campos antes mostrado"
    db.execute("UPDATE users SET name = :name, lastname = :lastname, \
        nacimiento = :nacimiento, descripcion = :descripcion, username = :username WHERE id_users = :id",
         {"name": name, "lastname": lastname, 
         "lastname": lastname,
         "nacimiento": nacimiento, "descripcion":descripcion, "username": username,
         "id": session["google_id"]})
    
    #db.execute("UPDATE users SET url_perfil = :url_perfil WHERE id = :id", {"url_perfil": request.files['file'].filename, "id": rows[0]})
    db.commit()
    return redirect("/perfil")

@app.route("/change_perfil", methods=["POST"])
def change_perfil():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        rows = db.execute("SELECT id_users, url_perfil FROM users WHERE email = :email", {"email": session["email"]}).fetchone()
       #print(rows[1])
        delete_perfil = rows[1]

        try:
            remove(f"D:\\Desktop\\cs50w-project4\\cs50w-project4\\static\\img{delete_perfil}")

        except OSError:
            print("No hay que borrar nada")

        #cambiar nombre del perfil
        type_image = request.files['file'].content_type
        #'png', 'jpg', 'jpeg', 'gif'
        if type_image == "image/png":
            request.files['file'].filename = f"perfil_user{rows[0]}.png"
        elif type_image == "image/jpg":
            request.files['file'].filename = f"perfil_user{rows[0]}.jpg"
        elif type_image == "image/jpeg":
            request.files['file'].filename = f"perfil_user{rows[0]}.jpeg"
        elif type_image == "image/gif":
            request.files['file'].filename = f"perfil_user{rows[0]}.gif"
        
        #actulizar tabla del nombre de la foto de perfil
        db.execute("UPDATE users SET url_perfil = :url_perfil \
        WHERE id_users = :id", {"url_perfil": request.files['file'].filename, "id": rows[0]})
        db.commit()

        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return "El archivo que esta tratando de subir no es una imagen"
        return redirect("/perfil")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/submit_post", methods=["POST"])
def submit_post():
    if request.method == 'POST':
        descripcion = request.form.get("descripcion")
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        rows = db.execute("SELECT id_users, publicaciones_incremental FROM users WHERE email = :email", {"email": session["email"]}).fetchone()
        
        publicacion_incremental = rows[1]

        if publicacion_incremental == None:
            publicacion_incremental = 0

        else:
            publicacion_incremental = rows[1]
        print(publicacion_incremental)
        publicacion_incremental2= int(publicacion_incremental)+1

        db.execute("UPDATE users SET publicaciones_incremental = :publicaciones_incremental \
        WHERE id_users = :id", {"publicaciones_incremental": str(publicacion_incremental2), "id": rows[0]})
        db.commit()

        rows2 = db.execute("SELECT * FROM publication WHERE user_id = :user_id", {"user_id": session["google_id"]}).fetchall()

        #cambiar nombre del perfil
        type_image = request.files['file'].content_type
        #'png', 'jpg', 'jpeg', 'gif'
        if type_image == "image/png":
            request.files['file'].filename = f"{publicacion_incremental}post_profile{rows[0]}.png"
        elif type_image == "image/jpg":
            request.files['file'].filename = f"{publicacion_incremental}post_profile{rows[0]}.jpg"
        elif type_image == "image/jpeg":
            request.files['file'].filename = f"{publicacion_incremental}post_profile{rows[0]}.jpeg"
        elif type_image == "image/gif":
            request.files['file'].filename = f"{publicacion_incremental}post_profile{rows[0]}.gif"
        now = datetime.now()
        #actulizar tabla del nombre de la foto de perfil
        db.execute("INSERT INTO publication (image_path, user_id, descripcion, date) \
                        VALUES (:image_path, :user_id, :descripcion, :date)",
                            {"image_path": request.files['file'].filename, "user_id": session["google_id"],                            
                              "descripcion": descripcion, "date": now.strftime("%Y/%m/%d")  })
        db.commit()

        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return "El archivo que esta tratando de subir no es una imagen"
        return redirect("/perfil")

@app.route("/EditarPublicacion/<string:id>", methods=["GET","POST"])
def EditarPublicacion(id):
    if request.method == "POST":
        descripcion = request.form.get("descripcion")
        db.execute("UPDATE publication SET descripcion = :descripcion \
        WHERE id = :id", {"descripcion": descripcion, "id": id})
        db.commit()

        return redirect("/perfil")

    rows=db.execute("SELECT * FROM publication WHERE id=:id", {"id": id}).fetchone()
    print(rows)
    return render_template("EditPublicacion.html", rows=rows)

@app.route("/EliminarPublicacion/<string:id>")
def EliminarPublicacion(id):
    rows = db.execute("SELECT image_path FROM publication WHERE id=:id", {"id": id}).fetchall()
    print(rows)
    try:
        remove(f"D:\\Desktop\\cs50w-project4\\cs50w-project4\\static\\img{rows[0]['image_path']}")

    except OSError:
            print("No hay que borrar nada")

    db.execute("DELETE FROM publication WHERE id=:id", {"id": id})
    db.commit()
    return redirect("/perfil")

@app.route("/search", methods=["GET"])
def search():
    busqueda = request.args.get("search") 
    busqueda = (f"%{busqueda}%")
    resultado = db.execute("SELECT * FROM users WHERE lower(name) LIKE lower(:busqueda)  OR \
        lower(lastname) LIKE lower(:busqueda) \
        OR lower(username) ILIKE lower(:busqueda)", 
            {"busqueda": busqueda }).fetchall()
    print(resultado)
    return render_template("search.html", resultados=resultado)

@app.route("/searchprofile/<string:id>", methods=["GET","POST"])
def searchprofile(id):
    return render_template("profile_user_search.html", id=id)

@app.route("/add_comment/<string:id>", methods=["POST"])
def add_comment(id):
    comentario = request.form.get("comment")
    if not comentario:
        return "No agrego el comentario"
    now = datetime.now()
    db.execute("INSERT INTO commentary (publication_id, user_id, comentario, date) \
                        VALUES (:publication_id, :user_id, :comentario, :date)",
                            {"publication_id": id, "user_id": session["google_id"],                            
                              "comentario": comentario, "date": now.strftime("%Y/%m/%d")  })
    db.commit()
    
    """ SELECT users.id, publication.id, publication.image_path, 
        publication.descripcion, publication.date, users.username, commentary.comentario, commentary.date
        FROM users INNER JOIN publication ON  publication.user_id = users.id 
        INNER JOIN commentary ON commentary.user_id =  users.id  WHERE users.id = 23"""
    return redirect("/perfil")

@app.route("/EditarComentario/<string:id>", methods=["GET","POST"])
def EditarComentario(id):
    if request.method == "POST":
        comentario = request.form.get("comentario")
        db.execute("UPDATE commentary SET comentario = :comentario \
        WHERE id_comentario = :id", {"comentario": comentario, "id": id})
        db.commit()

        return redirect("/perfil")

    rows=db.execute("SELECT id_comentario, comentario FROM commentary WHERE id_comentario=:id", {"id": id}).fetchone()
    print(rows)
    return render_template("EditarComentario.html", rows=rows)

@app.route("/EliminarComentario/<string:id>")
def EliminarComentario(id):

    db.execute("DELETE FROM commentary WHERE id_comentario=:id", {"id": id})
    db.commit()#like
    return redirect("/perfil")

#Agrega y elimina el like 
@app.route("/add_like/<string:id>", methods=["GET"])
def add_like(id):
    print(id)
    rows=db.execute("SELECT megusta FROM likes WHERE publication_id_likes=:id and user_id=:user_id", 
    {"id": id,"user_id": session['google_id']}).fetchall()

    print(rows)
    if bool(rows) == False:
        db.execute("INSERT INTO likes (user_id, publication_id_likes, megusta) VALUES (:user_id, :publication_id_likes, :megusta)",
                            { "user_id": session["google_id"], 
                              "publication_id_likes": id,                            
                              "megusta": True})
        db.commit()
        print("entro y se inserto")
    if bool(rows) == True:
        rows2=db.execute("SELECT megusta,publication_id_likes FROM likes WHERE publication_id_likes=:id and user_id=:user_id", 
        {"id": id,"user_id": session['google_id']}).fetchone()
        #print(f"registro de me gusta {rows2[0]}")

        if rows2[0] == True:
            print("lo cambio a falso")
            db.execute("UPDATE likes SET megusta = :megusta \
            WHERE user_id = :id and publication_id_likes=:publication_id_likes", 
            {"megusta": False, "id": session["google_id"], "publication_id_likes":id})
            db.commit()
        else:
            print("es verdadero")
            db.execute("UPDATE likes SET megusta = :megusta \
            WHERE user_id = :id and publication_id_likes=:publication_id_likes", 
            {"megusta": True, "id": session["google_id"], "publication_id_likes":id})
            db.commit()
        # db.execute("DELETE FROM likes WHERE publication_id_likes=:id and user_id=:user_id", 
        # {"id": id, "user_id": session['google_id']})
        # print("entro y se elimino")
   
    
    return redirect("/perfil")

#Inicio Pagina
@app.route("/add_comment_inicio/<string:id>", methods=["POST"])
def add_comment_inicio(id):
    print(f"Username google_id {session['google_id']}")
    comentario = request.form.get("comment")
    if not comentario:
        return "No agrego el comentario"
    now = datetime.now()
    db.execute("INSERT INTO commentary (publication_id, user_id, comentario, date) \
                        VALUES (:publication_id, :user_id, :comentario, :date)",
                            {"publication_id": id, "user_id": session["google_id"],                            
                              "comentario": comentario, "date": now.strftime("%Y/%m/%d")  })
    db.commit()
    
    """ SELECT users.id, publication.id, publication.image_path, 
        publication.descripcion, publication.date, users.username, commentary.comentario, commentary.date
        FROM users INNER JOIN publication ON  publication.user_id = users.id 
        INNER JOIN commentary ON commentary.user_id =  users.id  WHERE users.id = 23"""
    return redirect("/Inicio")


@app.errorhandler(404)
# inbuilt function which takes error as parameter
def not_found(e):
# defining function
  return "404" #render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True)