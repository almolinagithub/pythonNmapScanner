#!/usr/bin/python3

import nmap
scanner = nmap.PortScanner()

print("namp automation tool")
print("<---------------------------->")

ip_addr = input("entert Ip add: ")
print(f"The ip entered is {ip_addr}")
type(ip_addr)

resp = input("""\nPlease enter the scantype you want to run
                1) SynAck Scan
                2) UDP Scan
                3) Comprehensive Scan
                : """)
print(f"selected option is {resp}")

if resp == "1":
    print(f"Nmap Version: {scanner.nmap_version()}")
    scanner.scan(ip_addr, '1-1024', '-v -sS' )
    print(scanner.scaninfo())
    print(f"ip status :", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports: " , scanner[ip_addr]['tcp'].keys())
elif resp == "2":
        print(f"Nmap Version: {scanner.nmap_version()}")
        scanner.scan(ip_addr, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        print(f"ip status :", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("open ports: ", scanner[ip_addr]['udp'].keys())
