from flask import Flask, render_template, jsonify, redirect, request
from passlib.hash import sha512_crypt as sha
import json, database, base64
from random import choice
from datetime import datetime
import person
import os, binascii
import serial
import mysql.connector

app = Flask(__name__)

logged_in = {}
api_loggers = {}
mydb = database.db('root', 'localhost', 'Kaveri@1', 'arms')

@app.route("/register", methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = sha.hash(request.form['password'])  
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        api_key = request.form['api_key']  
        result = mydb.add_user(username, password, first_name, last_name, email, phone_number, api_key)
        if result == "success":
            return redirect('/login')  
        else:
            error = "Failed to register. Please try again."
    return render_template('register.html', error=error)


@app.route("/login", methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        user = person.user(request.form['username'], request.form['password'])
        if user.authenticated:
            user.session_id = str(binascii.b2a_hex(os.urandom(15)))
            logged_in[user.username] = {"object": user}
            return redirect('/overview/{}/{}'.format(request.form['username'], user.session_id))
        else:
            error = "wrong Username or Passowrd"
       
    return render_template('Login.htm', error=error)


#this links is for device 1 
@app.route('/device1/<string:username>/<string:session>', methods=["GET", "POST"])
def Dashoboard():
    user = {
        "username" : "Aman Singh",
        "image":"static/images/amanSingh.jpg"
    }

    devices = [
        {"Dashboard" : "device1",
        "deviceID": "Device1"
        }
    ]
    return render_template('device_dashboard.htm', title='Dashobard', user=user, devices=devices)


#this link is for the main dashboard of the website
@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.htm', title='HOME - Landing Page')

@app.route('/overview/<string:username>/<string:session>', methods=['GET', 'POST'])
def overview(username, session):
    
    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username" : username,
            "image":"/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session" : session
        }

        devices = [
            {"Dashboard" : "device1",
            "deviceID": "Device1"
            }
        ]
        return render_template('overview.htm', title='Overview', user=user, devices=devices)
    
    else:
        return redirect('/login')
        
#this location will get to the api setting
@app.route('/apisettings/<string:username>/<string:session>', methods=['GET', 'POST'])
def apisettings(username, session):
    
    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username" : username,
            "image":"/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session" : session
        }

        devices = [
            {"Dashboard" : "device1",
            "deviceID": "Device1"
            }
        ]
        return render_template('api_settings.htm', title='API-Settings', user=user, devices=devices)
    
    else:
        return redirect('/login')


#this part is for the profile view
@app.route('/profile/<string:username>/<string:session>', methods=['GET', 'POST'])
def profile(username, session):
    
    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        user = {
            "username" : username,
            "image":"/static/images/amanSingh.jpg",
            "api": logged_in[username]["object"].api,
            "session" : session,
            "firstname": logged_in[username]["object"].first,
            "lastname": logged_in[username]["object"].last,
            "email":logged_in[username]["object"].email,
            "phone":logged_in[username]["object"].phone,
            "lastlogin":logged_in[username]["object"].last_login,
        }

        devices = [
            {"Dashboard" : "device1",
            "deviceID": "ARMS12012"
            }
        ]
        return render_template('profile.htm', title='API-Settings', user=user, devices=devices)
    
    else:
        return redirect('/login')


@app.route('/logout/<string:username>/<string:session>', methods=['GET', 'POST'])
def logout(username, session):
    
    global logged_in

    if username in logged_in and (logged_in[username]['object'].session_id == session):
        logged_in.pop(username)
        # print("logged out")
        return redirect('/')
    else:
        return redirect('/login')



#this is the testing for api 
@app.route("/api/<string:apikey>/test", methods=["GET", "POST"])
def apitest (apikey):
    return {"data":"working Fine Connected to the api server"}


#get all the devices information from the user
@app.route("/api/<string:apikey>/listdevices", methods=['GET', 'POST'])
def listdevices(apikey):
    global api_loggers
    global mydb
    if not(apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            devices_list = apiuser.get_devices()
            api_loggers[apikey] = {"object" : apiuser}
            return jsonify(devices_list)
        except Exception as e:
            print (e)
            return jsonify({"data":"Oops Looks like api is not correct"})
    
    else:
        data = api_loggers[apikey]["object"].get_devices()
        return jsonify (data)

randlist = [i for i in range(0, 100)]

@app.route('/api/<string:apikey>/deviceinfo/<string:deviceID>', methods=['GET', 'POST'])
def device_info (apikey, deviceID):
    global api_loggers
    global mydb
    if not(apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            data = apiuser.dev_info(deviceID)
            api_loggers[apikey] = {"object" : apiuser}
            #this part is hard coded so remove after fixing the issue
            return jsonify(data)
        except Exception as e:
            print (e)
            return jsonify({"data":"Oops Looks like api is not correct"})
    
    else:
        data = api_loggers[apikey]["object"].dev_info(deviceID)

        #this part is hard coded so remove after fixing the issue
        return jsonify (data)

@app.route('/api/<string:apikey>/fieldstat/<string:fieldname>', methods=['GET', 'POST'])
def fieldstat (apikey, fieldname):
    
    global api_loggers
    global mydb
    if not(apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()
            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            data = apiuser.field_values(fieldname)
            api_loggers[apikey] = {"object" : apiuser}
            return jsonify(data)
        except Exception as e:
            print (e)
            return jsonify({"data":"Oops Looks like api is not correct"})
    
    else:
        data = api_loggers[apikey]["object"].field_values(fieldname)
        return jsonify (data)


@app.route('/api/<string:apikey>/devicestat/<string:fieldname>/<string:deviceID>', methods=['GET', 'POST'])
def devicestat (apikey, fieldname, deviceID):
    
    global api_loggers
    global mydb
    if not(apikey in api_loggers):
        try:
            query = "select username from users where api_key = '{}'".format(apikey)
            mydb.cursor.execute(query)
            username = mydb.cursor.fetchall()

            username = username[0][0]
            apiuser = person.user(username, "dummy")
            apiuser.authenticated = True
            data = apiuser.device_values(fieldname, deviceID)
            api_loggers[apikey] = {"object" : apiuser}
            return jsonify(data)
        except Exception as e:
            print (e)
            return jsonify({"data":"Oops Looks like api is not correct"})
    
    else:
        data = api_loggers[apikey]["object"].device_values(fieldname, deviceID)
        return jsonify (data)

@app.route('/api/<string:apikey>/update/<string:data>', methods=['GET','POST'])
def update_values(apikey, data):
    global mydb
    try:
        data = decode(data)
        output = mydb.get_apikeys()
        if apikey in output:
            if (len(data) == 6) and (type(data) is list):
                fieldname = data[0]
                deviceID = data[1]
                temp = data[2]
                humidity = data[3]
                moisture = data[4]
                light = data[5]
                mydb.update_values(apikey, fieldname, deviceID, temp, humidity, moisture, light)
                return ("Values Updated")
            else:
                return "Data Decoding Error!"
        else:
            return "Api key invalid"

    except Exception as e:
        print (e)
        return jsonify({"data":"Oops Looks like api is not correct"})


# @app.route("/api/testapi/temperature", methods=["GET", "POST"])
# def get_temperature(apikey):
    
#     randData = choice(randlist)
#     time = datetime.now()
#     time = time.strftime("%H:%M:%S")
#     response = [time, randData]
#     return jsonify(response)


# @app.route("/api/<string:apikey>/moisture", methods=["GET", "POST"])
# def get_moisture(apikey):
    
#     randData = choice(randlist)
#     time = datetime.now()
#     time = time.strftime("%H:%M:%S")
#     response = [time, randData]
#     return jsonify(response)

# @app.route("/api/<string:apikey>/humidity", methods=["GET", "POST"])
# def get_humidity(apikey):
    
#     randData = choice(randlist)
#     time = datetime.now()
#     time = time.strftime("%H:%M:%S")
#     response = [time, randData]
#     return jsonify(response)


# @app.route("/api/<string:apikey>/light", methods=["GET", "POST"])
# def get_light(apikey):
    
#     randData = choice(randlist)
#     time = datetime.now()
#     time = time.strftime("%H:%M:%S")
#     response = [time, randData]
#     return jsonify(response)


# Function to check if the API key is valid
def get_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",   
            password="Kaveri@1",  
            database="arms"
        )
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

def is_valid_api_key(api_key):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()  # Correct connection usage
        if connection is None:
            return False

        cursor = connection.cursor(dictionary=True)  # Initialize cursor if connection is successful

        # Query to fetch user details based on API key
        cursor.execute("SELECT * FROM users WHERE api_key = %s", (api_key,))
        user = cursor.fetchone()
        return user is not None  # Return True if user is found, False otherwise

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False  # Handle the case where the database connection or query fails

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/api/data', methods=['POST'])
def receive_data():
    
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            api_key = auth_header.split(" ")[1]  # Extract API key after 'Bearer'
            print(f"API Key: {api_key}")  # Debugging
        except IndexError:
            return jsonify({"error": "Invalid Authorization header format"}), 400
    else:
        return jsonify({"error": "Authorization header is missing"}), 401

    if is_valid_api_key(api_key):
        data = request.get_json()

        device_id = data.get('deviceId')
        field_name = data.get('field_name')
        username = "testuser" 
        temperature = data.get('temperature')
        humidity = data.get('humidity')

        if device_id and field_name and (temperature is not None or humidity is not None):
            connection = None
            cursor = None
            try:
                connection = get_db_connection()  
                if connection is None:
                    return jsonify({"error": "Database connection failed"}), 500

                cursor = connection.cursor() 

                # Log the values before executing the query
                print(f"Inserting values: Device ID: {device_id}, Username: {username}, Field Name: {field_name}, Temperature: {temperature}, Humidity: {humidity}")

                insert_data_query = """
                INSERT INTO node (deviceId, username, field_name, temperature, humidity, moisture, light)
                VALUES (%s, %s, %s, %s, %s, NULL, NULL)
                """
                cursor.execute(insert_data_query, (device_id, username, field_name, temperature, humidity))
                connection.commit() 

                return jsonify({"message": "Data received and stored successfully"}), 200
            except mysql.connector.Error as err:
                print(f"Error storing data: {err}")  # Print full MySQL error for debugging
                return jsonify({"error": f"Failed to store temperature and humidity data. {err}"}), 500
            finally:
                if cursor:  
                    cursor.close()
                if connection:  
                    connection.close()
        else:
            return jsonify({"error": "Missing required data: deviceId, field_name, temperature, or humidity."}), 400
    else:
        return jsonify({"error": "Unauthorized"}), 401


def encode(data):
    data = json.dumps(data)
    message_bytes = data.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return json.loads(message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port = "80",debug=True)
