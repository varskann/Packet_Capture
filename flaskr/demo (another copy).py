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

conn = sqlite3.connect('database.db')
c = conn.cursor()

	
@app.route('/')
@app.route('/index')
def index():
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute('''SELECT Pcap_name, Count, Request, Response, Content_type, Content_length FROM http''')
    result = cur.fetchall()
    cur.execute('''SELECT Pcap_name FROM http''')
    pcap_names = cur.fetchall() 
    checked = []
    for e in pcap_names:
        if str(e[0]) not in checked:
            checked.append(str(e[0]))

    return render_template('index.html', name = result, pcap = checked)
   
@app.route('/browse', methods=['POST'])
def browse():
	
	packet_no = request.form["Packet"]
	pcap_file = request.form["pcap_file"]
	con = sqlite3.connect('database.db')
	cur = con.cursor()
	cur.execute('''SELECT Request FROM http WHERE Count = ? AND Pcap_name = ?''', (packet_no,pcap_file,))
	url = cur.fetchone()
	
	#print url
	if url != None:
		url = url[0]
		if "http://" in url:
			webbrowser.open_new_tab(url)
		else:
			url = "http://" + url
			webbrowser.open_new_tab(url)
		print "response received"
		return "Response received"
	else:
		return render_template('troll.html')
	
@app.route('/register', methods=['POST'])
def register():
	url = request.form["Packet"]
	print ">>>>", url
	
	return url

@app.route('/delete', methods = ['POST'])
def delete():
	packet_no = request.form["Packet"]
	pcap_file = request.form["pcap_file"]
	con = sqlite3.connect('database.db')
	cur = con.cursor()
	if packet_no == '*':
		cur.execute('''DELETE FROM http WHERE Pcap_name = ?''', (pcap_file,))
	else:
		cur.execute('''DELETE FROM http WHERE Count = ? AND Pcap_name = ?''', (packet_no, pcap_file,))
	con.commit()
	cur.execute('''SELECT Pcap_name, Count, Request, Response FROM http''')
    	result = cur.fetchall()
        cur.execute('''SELECT Pcap_name FROM http''')
        pcap_names = cur.fetchall() 
        checked = []
        for e in pcap_names:
            if str(e[0]) not in checked:
                checked.append(str(e[0]))
    	return render_template('index.html', name = result, pcap = checked)
if __name__ == '__main__':
    app.run(host = '0.0.0.0')
