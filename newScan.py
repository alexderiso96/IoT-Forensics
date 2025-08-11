import pyshark
import math
udpDictCount={}
display_filter='udp'
import traceback
def addUDP(key):
	if(key in udpDictCount):
		udpDictCount[key]+=1
	else:
		udpDictCount[key]=1


def print_callback(pkt):
	if(hasattr(pkt, 'udp')):
		key = math.floor(float(pkt.frame_info.time_relative))
		print("SERVE : "+str(pkt.frame_info.time_relative))
		print(str(key))
		addUDP(key)
def Scanner():
	pcap_in_filename= 'CaptureFile.pcap'
	capture = pyshark.FileCapture(pcap_in_filename, display_filter=display_filter)

	try:
		capture.apply_on_packets(print_callback)
	except:
		traceback.print_exc()