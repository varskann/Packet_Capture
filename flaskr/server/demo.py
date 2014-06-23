from flask import *
import time
import os
import sys
import sqlite3
import random
import string
from itsdangerous import *
import base64
import urllib2
import webbrowser

app = Flask(__name__)
app.debug = True

conn = sqlite3.connect('newdb.db')
c = conn.cursor()
	
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')
   
@app.route('/tribute', methods=['POST'])
def tribute():
	url = request.form["url"]
	if "http://" in url:
		webbrowser.open(url)
	else:
		url = "http://" + url
		webbrowser.open(url)
	return "1"
	
@app.route('/register', methods=['POST'])
def register():
	url = request.form["url"]
	#url = "www.google.co.in/url?sa=t&rct=j&q=&esrc=s&source=web&cd=2&ved=0CDIQFjAB&url=http%3A%2F%2Fstackoverflow.com%2Fquestions%2F21147110%2Freading-a-pcap-file-in-c&ei=JLaFU7f-JM_98QW85oLQAQ&usg=AFQjCNFZ5D8UbEsUgFcc3Om2FfwxIIDwVA&sig2=DKi2PpYmsvhKKd8iFQzpVA&bvm=bv.67720277,d.dGc"
	conn = sqlite3.connect('newdb.db')
	c = conn.cursor()
	req = url
	c.execute('''SELECT Response_Payload FROM http WHERE Request = ?''', (req,))
	for rwo in c:
		print rwo
	return "1"
	
if __name__ == '__main__':
    app.run()
