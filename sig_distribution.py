#! /usr/bin/python3
from scapy.all import *
import sys, os

sta_list = []
counter = []
print("\nstarting to sniff")
addr = ''

sniffed = ".pcapng"
count = 0
for x in range(1,27):
	count = 0
	sniffed_name = "tmp/" + str(x) + sniffed
	cap = sniff(offline=sniffed_name)
	for packet in cap:
		addr = packet.addr2
		if addr not in sta_list:
			sta_list.append(addr)
			name = "captures/captures" + str(x) + "/cap" + str(count) + ".pcap"
			wrpcap(name, packet)
			count = count + 1
	counter.append(count)

print("\nstarting to make signatures")

for y in range(len(counter)):
	for x in range(counter[y]):
		name = "captures/captures" + str(y+1) + "/cap" + str(x) + ".pcap"
		signature_name = "signatures/signatures" + str(y+1) + "/" + str(x) + ".txt"
		os.system("./wifi_signature -f " + name + " >> " + signature_name)

print("\nstarting to count differences")

final_teams = []
teams = []
for y in range(len(counter)):
	single_team = []
	for x in range(counter[y]):
		single_team.append(1)
	teams.append(single_team)

signatures_number = 1
for sing_team in teams:
	num_of_devices = len(sing_team)
	for x in range(len(sing_team)-1):
		if sing_team[x] != 0:
			for y in range(x+1, len(sing_team)):
				if sing_team[y] != 0:
					sig1 = "signatures/signatures" + str(signatures_number) + "/" + str(x) + ".txt"
					sig2 = "signatures/signatures" + str(signatures_number) + "/" + str(y) + ".txt"
					ret = os.system("diff " + sig1 + " " + sig2 + " >> /dev/null")
					if ret == 0:
						sing_team[x] += 1
						sing_team[y] = 0
	sing_team[:] = [num for num in sing_team if num != 0]
	print("\nout of " + str(num_of_devices) + " devices:")
	print("the number of teams in signatures" + str(signatures_number) + " is: " + str(len(sing_team)))
	print("the teams are: " + str(sing_team))
	signatures_number += 1

print("\nall done, cya!\n")
