from flask import *
import time
import os
import sys
import sqlite3
import random
import string
from itsdangerous import *
import base64

app = Flask(__name__)
app.debug = True

#Creating Database
conn = sqlite3.connect('Database.db')
c = conn.cursor()
c.execute('PRAGMA foreign_keys = ON;')

#Global Variables
recordID = 0

#Creating tablesdd

@app.route('/')
@app.route('/index')
def index():
	email = request.cookies.get("email")
	email1 = "s@sa"
	email2 = base64.b64encode(email1)
	random_id = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(19))
	salt1 = Signer(random_id)
	interim = salt1.sign(email2)
	answer = base64.b64encode(interim)
	ans = salt1.unsign(interim)
	ans2 = base64.b64decode(ans)
	print email2
	print salt1
	print interim
	print answer
	print ans
	print email1
	print ans2
	if email==None:
		resp = make_response(render_template("index.html"))
		resp.set_cookie('email', '', expires=0)
		return resp
	else:
		return render_template("dashboard.html")

@app.route('/login')
def login():
    return render_template("login.html", errorVar="")

@app.route('/logout')
def logout():
    resp = make_response(render_template("index.html"))
    resp.set_cookie('email', '', expires=0)
    return resp

@app.route('/loggedin', methods=['POST'])
def loggedin():
	email = request.form["email"]
	password = request.form["password"]
	conn = sqlite3.connect('Database.db')
	c = conn.cursor()
	c.execute('PRAGMA foreign_keys = ON;')
	result = c.execute('select count(*) from data where email = ? and password = ?', (email, password,))
	for row in result:
		if row[0] == 1:
			conn.close()
			resp = make_response(render_template("dashboard.html"))
			resp.set_cookie("email", email, 1800)
			return resp
		else:
			conn.close()
			return render_template("login.html", errorVar="""Record not found. Try again.""")

@app.route('/app1', methods=['POST'])
def app1():
	email = request.cookies.get("email")
	if email==None:
		resp = make_response(render_template("index.html"))
		resp.set_cookie('email', '', expires=0)
		return resp
	else:
		return render_template("dashboard.html")

@app.route('/registration')
def registration():
    return render_template("registration.html", errorVar="")

@app.route('/register', methods=['POST'])
def register():
	name = request.form["name"]
	email = request.form["email"]
	password = request.form["password"]
	dob = request.form["dob"]
	address = request.form["address"]
	contact = request.form["contact"]

	conn = sqlite3.connect('Database.db')
	c = conn.cursor()
	c.execute('PRAGMA foreign_keys = ON;')
	result = c.execute('select count(*) from data where email = ?', (email,))
	for row in result:
		if row[0]==1:
			conn.close()
			return render_template("registration.html", errorVar="Email address already in use.")
		else:
			c.execute('INSERT INTO data VALUES (?,?,?,?,?,?)', (name, email, password, dob, address, contact))
			emailEncode = base64.b64encode(email)
			random_id = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(19))
			c.execute('INSERT INTO secure VALUES (?,?,?)', (date, random_id, email))
			salt = TimestampSigner(random_id)
			interim = salt.sign(emailEncde)
			cookie = base64.b64encode(interim)
			resp = make_response(render_template("dashboard.html"))
			resp.set_cookie(cookie, value, 1800)
			conn.commit()
			conn.close()
			return resp

if __name__ == '__main__':
    app.run(threaded=True)
