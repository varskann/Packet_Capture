import dpkt
import sys
import socket
import urllib2 
from StringIO import StringIO
import gzip
import sqlite3

snaplen = 1516
i = 0
c = 0
count  = 0
size_payload = 0
req = []
res = []
payload = []

result = open('result.txt', 'w')
f = open('tom.pcap', 'rb')

con = sqlite3.connect('newdb.db')
cur = con.cursor()
cur.execute('''DROP TABLE http''')
## Create table and push data
cur.execute('''CREATE TABLE if not exists http(Request_Method text, Request text, Request_Payload text, Response text, Response_Payload text)''')
cur.execute('''CREATE INDEX packet ON http(Request)''')

pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type!=2048:    ## For ipv4, dpkt.ethernet.Ethernet(buf).type =2048        
        continue
    ip = eth.data

    if ip.p!=6:
           continue
    tcp=ip.data
    count += 1
    size_payload = ip.len - 40
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    print "*****", count, "******\n"
    print tcp.seq
    print tcp.ack

##    print "%s ---> %s" % (src, dst)
##    print len(tcp.data)
##    print tcp.sport, "--->", tcp.dport
    if tcp.sport == 80 or tcp.dport == 80 and len(tcp.data) > 0:                ##filter tcp port == 80
        if tcp.dport == 80:                                                     ## Parse HTTP request
            try:
                http = dpkt.http.Request(tcp.data)
                print "Request"
                if http.method == "GET":
                    rqst = ["GET", http.headers['host']+http.uri, tcp.sport, tcp.dport, src, dst, tcp.seq, tcp.ack, http.body]
                    
                    if 'accept-encoding' in http.headers:
                        rqst.append(http.headers['accept-encoding'])
                    req.append(rqst)

                elif http.method == "POST":
                    rqst = ["POST", http.headers['host']+http.uri, tcp.sport, tcp.dport, src, dst, tcp.seq, tcp.ack, http.body]
                    if 'accept-encoding' in http.headers:
                        rqst.append(http.headers['accept-encoding'])
                    req.append(rqst)
            except:
                pass
        elif tcp.sport == 80:                                                     ## Parse HTTP response
            try:
                http2 = dpkt.http.Response(tcp.data)
                print "Response"
                if http2.status == str(200):
                    a = http2.body
                    pload = gzip.GzipFile(fileobj=StringIO(a)).read()
                    for j in range(0, len(req)):
                        if (tcp.dport == req[j][2]) and (src == req[j][5]) and (dst == req[j][4]) and (tcp.seq == req[j][7]):
                            result.write("\nRequest: " + req[j][0] + " " + req[j][1])
                            requests = req[j][1]
                            result.write("\nRequest Payload: "+req[j][8])
                            result.write("\nResponse: HTTP/1.1 200 OK")
                            result.write("\nResponse Payload: "+pload)
                            result.write("\n_________________\n")
                            cur.execute('''INSERT INTO http(Request_Method, Request, Request_Payload, Response, Response_Payload) VALUES(?, ?, ?, ?, ?)''', (req[j][0], requests, req[j][8], "HTTP/1.1 200 OK", pload))
                              

                                
                                   
            except:
                print "Response"

con.commit()

#cur.execute('''SELECT * FROM http''')
#for row in cur:
    ## row[0] returns the first column in the query (name), row[1] returns email column.
    #print('{0}, {1}, {2}, {3}, {4}'.format(row[0], row[1], row[2], row[3], row[4]))
    #print("********************************************************************************************************************")
result.close()
con.close()
