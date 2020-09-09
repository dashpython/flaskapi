from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app = Flask(__name__)

app.config['MYSQL_USER'] = 'shailu'
app.config['MYSQL_PASSWORD'] = 'Shailu*123'
app.config['MYSQL_DB'] = 'login1'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['JWT_SECRET_KEY'] = 'secret'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

@app.route('/')
def home():
    return "hello world"

@app.route('/users/register', methods=['POST'])
def register():
    cur = mysql.connection.cursor()
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.now()
    res = ""

    cur.execute("SELECT * FROM users where email = '" + str(email) + "'")
    rv = cur.fetchone()
    if rv:
        if (rv['email'],email):
            res = jsonify({"result":"User Exists"})

        else:
            res = jsonify({'result' : "Invalid Register"})
    else:
        cur.execute("INSERT INTO users (first_name, last_name, email, password, created) VALUES ('" + 
		        str(first_name) + "', '" + 
		        str(last_name) + "', '" + 
		        str(email) + "', '" + 
		        str(password) + "', '" + 
		        str(created) + "')")
        mysql.connection.commit()
	
   # result = {
#		'first_name' : first_name,
#		'last_name' : last_name,
#		'email' : email,
#		'password' : password,
#		'created' : created
#	}
        res = jsonify({'result' : "User Registered Succesfully"})
    return res


@app.route('/users/login', methods=['POST'])
def login():
    cur = mysql.connection.cursor()
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    cur.execute("SELECT * FROM users where email = '" + str(email) + "'")
    rv = cur.fetchone()

    if rv:
        if bcrypt.check_password_hash(rv['password'], password):
            access_token = create_access_token(identity = {
                'first_name': rv['first_name'],
                'last_name': rv['last_name'],
                'email': rv['email']})
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid username and password"})
    else:
        result = jsonify({"result":"No results found"})
    return result
	
if __name__ == '__main__':
    app.run(debug=True)