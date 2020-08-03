import threading
import socket
import argparse
import sys

screenlock = threading.Semaphore(value=1)
def scan(ip,port):
	try:
		conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		conn.connect((ip,port))
		screenlock.acquire()
		print("[+] port {} is open".format(port))
	except:
		print('[+] port {} is closed'.format(port))
	finally:
		screenlock.release()
		conn.close()
	
		

def call_scan(ip,port):
	try:
		socket.inet_aton(ip)
		
	except:
		argip = False
	if argip == False:
		try:
			ip = socket.gethostbyname(ip)
			
		except:
			print('cannot resolve host {}'.format(ip))
			exit(0)
	for tgtPort in port:
		t = threading.Thread(target=scan,args=(ip,int(tgtPort)))
		t.start()

def main():
	parser = argparse.ArgumentParser(description='Port Scanner.')
	required = parser.add_argument_group('Required arguments')
	required.add_argument('-H',dest='ip',help='Specify target host')
	required.add_argument('-p',dest='port',help='Specify target port[s] separated by comma.')
	options= parser.parse_args()
	ip = options.ip
	tgtPorts = str(options.port).split(',')
	if (ip == None) | (tgtPorts[0] == None):
		parser.print_help()
		sys.exit()
	call_scan(ip,tgtPorts)
	

if __name__ == '__main__':
	main()