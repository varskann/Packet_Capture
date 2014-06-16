import cherryproxy
import sys
import os
import create_db
import urlparse, urllib2, httplib, sys, threading, logging
from cherryproxy import wsgiserver
import sqlite3
create_db.main("capture2.pcap")
#__version__ = '0.13'

#SERVER_NAME = 'CherryProxy/%s' % __version__

request_uri = ""
req_method = ""
req_uri = ""
count_index = 0
class CherryProxy_tcpreplay(cherryproxy.CherryProxy):
    global request_uri
    global req_method
    global req_uri
    global conunt_index
    global req_path
    global req_host
    def filter_request(self):
        pass
    def filter_request_headers(self):
        global request_uri
        global req_method
        global req_uri
        global conunt_index
        global req_path
        global req_host
        req_method = self.req.method
        req_path = self.req.path
        req_host = self.req.netloc
        req_uri = req_host + req_path
        request_uri = self.req.full_url
        #print request_uri
        #print req_uri
    def filter_response_headers(self):
        pass
    def filter_response(self):
        global request_uri
        global req_method
        global req_uri
        global conunt_index
        global req_path
        global req_host
        #print "**********"
        #print ">>>" + request_uri
        #print "##########"
        sys.stdout.flush()
        con = sqlite3.connect('newdb.db')
        cur = con.cursor()
        cur.execute('''SELECT Count, Response FROM http WHERE Request = ?''', (request_uri, ))
        a = cur.fetchone()
        con.close()
        if a != None:
            count_get = a[0]
            status_get = a[1]
            data_get = fry.responses[a[0]-1]
            type_get = fry.responses_headers[a[0]-1]['content-type']
            self.set_response(int(status_get), "Response", data = data_get, content_type = type_get)
            
        else:
            self.set_response(200, "Response", data = "madmax", content_type='text/plain')

cherryproxy.main(CherryProxy_tcpreplay)

