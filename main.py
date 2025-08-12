import socket

target = input("Enter your target Ip adrr")

ports = range(1, 1025) #can be expanded later
print(f"\n Scanning Port  {target}...\n")

for port in ports:
	sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socket.setdefaulttimeout(1)
	result = sock.connect_ex((target, port))
	if result == 0:
		print(f"[OPEN] Port {port}")
	sock.close()
