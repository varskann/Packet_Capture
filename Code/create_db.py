import os, pwd
import sys
import nids
import gzip
import dpkt
import sqlite3
from StringIO import StringIO
import re
count = 0
NOTROOT = "nobody"   # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

con = sqlite3.connect('newdb.db')
con.text_factory = str
cur = con.cursor()
cur.execute('''DROP TABLE http''')		## Comment out this line if DB is not already created 
## Create table and push data
cur.execute('''CREATE TABLE if not exists http(Request_Method text, Request text, Request_Payload text, Response text, Count integer)''')
cur.execute('''CREATE INDEX packet ON http(Request)''')
result = open('using_pynids.txt', 'w')
con.commit()
con.close()

resources = []
responses_headers = []
openstreams = {}
responses = []

def handleTcpStream(tcp):
    global count
    global responses
    global responses_headers
    #print responses
    #print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        
        if dport == 80:
            tcp.client.collect = 1
            tcp.server.collect = 1

            openstreams[tcp.addr] = tcp
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)

        openstreams[tcp.addr] = tcp
    elif tcp.nids_state in end_states:
        del openstreams[tcp.addr]
        
        processTcpStream(tcp)
                

def processTcpStream(tcp):
        global count
        global responses
        global responses_headers
        ((src, sport), (dst, dport)) = tcp.addr

        # data to server
        server_data= tcp.server.data[:tcp.server.count]
        # data to client
        client_data = tcp.client.data[:tcp.client.count]
    
        # extract *all* the requests in this stream
        req = ""
        while len(req) < len(server_data):
            req = dpkt.http.Request(server_data)
            #print req
            host_hdr = req.headers['host']
            full_uri = req.uri if req.uri.startswith("http://") else \
                "http://%s%s" % (host_hdr, req.uri)

            try:
                res = dpkt.http.Response(client_data)
                data = res.body
		resources.append(res.body)
                try:
                    pload = gzip.GzipFile(fileobj=StringIO(data)).read()
                    #print pload
                    count += 1
                    result.write("\nRequest Method: " + req.method)
                    result.write("\nRequest: "+ full_uri)
                    result.write("\nRequest Payload: "+req.body)
                    result.write("\nResponse: "+ res.status)
                    result.write("\nResponse Payload: "+pload)
                    result.write("\n_________________\n\n\n\n\n")
                    con = sqlite3.connect('newdb.db')
                    con.text_factory = str
                    cur = con.cursor()
                    cur.execute('''select * from http''')
                    cur.execute('''INSERT INTO http(Request_Method, Request, Request_Payload, Response, Count) VALUES(?, ?, ?, ?, ?)''', (req.method, full_uri, req.body, res.status, count))
                    responses.append(pload)
                    responses_headers.append(res.headers)
                    con.commit()
                    con.close()
                    
                except:

                    if 'content-encoding' not in res.headers:
                        pload = data
                        count += 1
                        result.write("\nRequest Method: " + req.method)
                        result.write("\nRequest: "+ full_uri)
                        result.write("\nRequest Payload: "+req.body)
                        result.write("\nResponse: "+ res.status)
                        result.write("\nResponse Payload: "+pload)
                        result.write("\n_________________\n\n\n\n\n")
                        con = sqlite3.connect('newdb.db')
                        con.text_factory = str
                        cur = con.cursor()
                        cur.execute('''select * from http''')
                        cur.execute('''INSERT INTO http(Request_Method, Request, Request_Payload, Response, Count) VALUES(?, ?, ?, ?, ?)''', (req.method, full_uri, req.body, res.status, count))
                        responses.append(pload)
                        responses_headers.append(res.headers)
                        con.commit()
                        con.close()
                        break
             
                if res.headers.has_key("content-length"):
                    body_len = int(res.headers["content-length"])
                    hdr_len = client_data.find('\r\n\r\n')
                    client_data = client_data[body_len + hdr_len + 4:]
                else:
                    hdr_body_len = client_data.find("HTTP/1")
                    client_data = client_data[hdr_body_len]
            
                if not resources.has_key(full_uri):
                    resources[full_uri] = []
                resources[full_uri].append(res)

                server_data = server_data[len(req):]
            except:
                pass



def main(arg1):
    global count
    global responses
    global responses_headers
    #nids.param("pcap_filter", "tcp")       # bpf restrict to TCP only, note
                                            # libnids caution about fragments

    nids.param("scan_num_hosts", 0)         # disable portscan detection

    #if len(sys.argv) == 2:                  # read a pcap file?
    nids.param("filename", arg1)
  

    nids.init()

   
    nids.register_tcp(handleTcpStream)
    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error:", e
    except Exception, e:
        print "misc. exception (runtime error in user callback?):", e
        
    for c, stream in openstreams.items():
        processTcpStream(stream)
    
    result.close()

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))

