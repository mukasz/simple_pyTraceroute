import socket
import random
import re
import struct
import sys

def prepare_sockets( ttl, port, timeout ):
	sock_icmp = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp') )
	sock_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
	sock_sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
	t = struct.pack("ll", t, 0)
	sock_icmp.setsockopt( socket.SOL_SOCKET, socket.SO_RCVTIMEO, t )
	sock_sender.bind( ("", port) )
	return sock_icmp, sock_sender
	
def tracepath( dest, maxHop=35, timeout=3 ):
	ttl = 1
	port = random.randint(33434, 33535)
	ip = socket.gethostbyname( dest )
	print( "Route to " + str(ip) + ":")
	while True:
		sock_icmp, sock_sender = prepare_sockets( ttl, port,timeout )
		try:
			sock_sender.sendto("", (ip, port))
		except socket.error as e:
			print e
		try:
			_, ip_current = sock_icmp.recvfrom(512)
			ip_current = ip_current[0]; #port not needed
			print(str(ttl) + ": " + str(ip_current))
		except socket.error:
			print(" *** ");
		except KeyboardInterrupt:
			sock_sender.close()
			sock_icmp.close()
			print("KeyboardInterupt!\n")
			sys.exit()
		except Exception as e:
			print("unknown error: " + str(e))
			break
		sock_sender.close()
		sock_icmp.close()
		if ttl > maxHop or str( ip ) == str( ip_current ):
			print("Trace Complete")
			break
        ttl += 1

def main(args):
	try:
		ip = args[1]
	except IndexError:
		print("No IP given!")
		return -1;
	ip_pattern = r'\A(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\z'
	if not re.match(ip_pattern, ip, flags=0):
		print("wrong ip format!")
		return -1
	tracepath( ip )
	return 0 
if __name__ == '__main__':
	sys.exit(main(sys.argv))

