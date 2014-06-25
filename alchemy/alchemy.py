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
from math import ceil
import time
import threading

b = []
page_no = 1
def open_link(url):
	print "came here"
	if url != None:
		if "http://" in url:
			webbrowser.open(url)
		else:
			url = "http://" + url
			webbrowser.open(url)

app = Flask(__name__)
app.debug = True
app.secret_key = 'some_secret'
conn = sqlite3.connect('database.db')
c = conn.cursor()

PER_PAGE = 20
#@app.route('/log', methods = ['GET', 'POST'])
def url_for_other_page(page):
    check_box = request.form.getlist('check')
    #print "Ye kya ho rha haiasdasd "
    #print check_box
    args = request.view_args.copy()
    args['page'] = page
    return url_for(request.endpoint, **args)
app.jinja_env.globals['url_for_other_page'] = url_for_other_page

@app.route('/refresh', methods = ['GET', 'POST'])
def refresh():
	global b
	global page_no
	b = []
	return redirect(url_for('index'))


@app.route('/', defaults={'page': 1})
@app.route('/page/<int:page>')
def index(page):
    global PER_PAGE
    global b
    global page_no

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute('''SELECT COUNT(*) FROM http''')
    total_items = cur.fetchone()[0]
    pages = int(ceil(total_items/float(PER_PAGE)))
    start_num = (page-1)*PER_PAGE
    if start_num+20 <= total_items:
	end_num = start_num+20
    else:
        end_num = total_items
    cur.execute('''SELECT Request_Method, Pcap_name, Count, Request, Response, Content_type, Content_length, Item FROM http''')
    result = cur.fetchall()
    cur.execute('''SELECT Pcap_name FROM http''')
    pcap_names = cur.fetchall() 
    checked = []
    for e in pcap_names:
        if str(e[0]) not in checked:
            checked.append(str(e[0]))
    c = b
    #con.close()
    return render_template('index.html', name = result, pcap = checked, pages = pages, start = start_num, end = end_num, current = page, searched = c)
   
@app.route('/browse', methods=['GET', 'POST'])
def browse():
	global b
	check_box = request.form.getlist('check')
	#packet_no = request.form["Packet"]
	#pcap_file = request.form["pcap_file"]
	con = sqlite3.connect('database.db')
	cur = con.cursor()
	print ">>>",check_box
	if check_box != None:
		threads = []
		for item in check_box:
			
			item_no = int(item)
			print "===>>", item_no
			cur.execute('''SELECT Request, Content_length FROM http WHERE Item = ?''', (item_no,))
			url = cur.fetchone()
			print url
			url_to_open = url[0]
			t = threading.Thread(target=open_link, args = (url_to_open,))
			threads.append(t)
			t.start()

			for t in threads:
				t.join()
			content_length = int(url[1])
			wait_time = int(ceil(content_length/float(10000)))
			
			time.sleep(wait_time)
	#con.close()
	return redirect('')
@app.route('/register/', methods=['GET', 'POST'])
def register():
	global b
	#print urlname
	query = request.form["Packet"]
	con = sqlite3.connect('database.db')
	cur = con.cursor()
	cur.execute('''SELECT Request FROM http WHERE Content_length = ?''', (query, ))
	a = cur.fetchall()
	b = []
	for i in a:
		b.append(str(i[0]))
	#con.close()
	return redirect('')

@app.route('/delete', methods = ['GET', 'POST'])
def delete():
	global PER_PAGE
	global b
	b = []
	check_box = request.form.getlist('check')
	#packet_no = request.form["Packet"]
	#pcap_file = request.form["pcap_file"]
	con = sqlite3.connect('database.db')
	cur = con.cursor()
	if check_box != None:
		for item in check_box:
			item_no = int(item)
			cur.execute('''DELETE FROM http WHERE Item = ?''', (item_no,))
		con.commit()
	#con.close()
	return redirect(url_for('index'))
if __name__ == '__main__':
    app.run(host = '0.0.0.0')
