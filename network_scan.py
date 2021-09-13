
# Network Scanner
 
#!/usr/bin/python3
import nmap

def menu():
	print("...................Main Menu.......................")
	print("1.Scan single host")
	print("2.Scan range")
	print("3.Scan network")
	print("4.Agressive scan")
	print("5.Scan ARP packet")
	print("6.Scan all port only")
	print("7.Scan in verbose mode")
	print("8.Exit")



def scan_single_host():
	print("..........................Scan single host....................")
	nm = nmap.PortScanner()
	ip = input("Enter the IP")
	print("wait.............")
	try:
		scan = nm.scan(hosts=ip,ports="1-100",arguments="-sS -O -v -Pn")
		print(scan["scan"][ip]["addresses"]["ipv4"],"Scanning single host")
		for host in scan["scan"][ip]['tcp'].items():
			print("..............Details................")
			print("Tcp Port :",host[0])
		#	print(host[1])
			print("State :",host[1]['state'])
			print("Reason :",host[1]['reason'])
			print("Name :",host[1]['name'])
	except:
		print("Use root privilige")
def scan_range():
	print("....................Scan Range......................")
	nm = nmap.PortScanner()
	ip = input("Enter the IP")
	print("wait..............")
	try:
		scan = nm.scan(hosts=ip,arguments="-sS -O -Pn")
		#print(scan)
		print("................Host Range..............")
		for host in scan["scan"]:
			print("Ip range :",host)
	except:
		print("Use root privilige")

def scan_network():
	nm = nmap.PortScanner()
	ip = input("Enter the ip address")
	print("wait.....................")
	try:
		scan = nm.scan(hosts=ip,arguments="-sS -O -Pn")
		for  i in scan["scan"][ip]["osmatch"]:
			print(".........Scan Network.............")
			print("Name :",i['name'])
			for j in i['osclass']:
				print(f"Os-type :",{j['type']})
				print(f"Vendor :",{j['vendor']})
	except:
		print("Use root priviliege")

def aggressive_scan():
	nm = nmap.PortScanner()
	ip = input("\tEnter the IP")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip]['osmatch']:
			print("...............Agressive Scan......................")
			print(f"Name : {i['name']}")
			print(f"Accuracy : {i['accuracy']}")
			for j in i['osclass']:
				print(f"Os-type :,{j['type']}")
				print(f"Vendor :,{j['vendor']}")
		
	except:
		print("Use root priviliege")
	

def arp_packet():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("wait.............")
		try:
			scan = nm.scan(hosts=ip,arguments = "-sS -O -PR")
			#print(scan)
			for i in scan["scan"][ip]['osmatch']:
				print("..........ARP Packet...................")
				print(f"Name : {i['name']}")
				print(f"Accuracy : {i['accuracy']}")
		except:
			print("Use root privilige")

def scan_all_ports():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("wait.............")
		try:
			scan = nm.scan(hosts=ip,ports="1-4",arguments="-sS -O -Pn")
			#print(scan)
			for host in scan["scan"][ip]['tcp'].items():
				print("..............Port Details................")
				print("Tcp Port :",host[0])
		#		print(host[1])
				print("State :",host[1]['state'])
				print("Reason :",host[1]['reason'])
				print("Name :",host[1]['name'])
			
		except:
			print("Use root privilige")
	
def verbose_scan():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("Wait........................")
		try:
			scan = nm.scan(hosts = ip,arguments = "-sS -O -Pn -v")
			for i in scan["scan"][ip]["osmatch"]:
				print("...............Verbose Scan.............")
				print(f"Name : {i['name']}")
				print(f"Accuracy : {i['accuracy']}")
				for j in i["osclass"]:
					print(f"Os-type : {j['type']}")		
		except:
			print("Use root priviliege")
		
			

while True:
	menu()
	ch = int(input("Enter your choice"))
	if ch == 1:
		scan_single_host()
	elif ch == 2:
		scan_range()
	elif ch == 3:
		scan_network()

	elif ch == 4:
		aggressive_scan()
	elif ch == 5:
		arp_packet()
	elif ch == 6:
		scan_all_ports()
	elif ch == 7:
		verbose_scan()
	elif ch == 8:
		break
	else:
		print("Invalid")

