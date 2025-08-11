import pyshark
import sys
from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError
from datetime import datetime
import asyncio
import math
import traceback
import logging
import JsonFile
import networkAnalysis

logging.basicConfig(format='%(levelname)s - %(message)s',level=logging.ERROR)
logger = logging.getLogger(__name__)

#-----------------------------------------------VARIABILI--------------------------------------------------------#
UDPCount=0
AzioniEseguite = 0
TLSCount = 0
totpkt=0
countReteEsterna=0
countReteInterna=0
timeChartStart=0
timeChartEnd=0


#########################variabili d'appoggio########################################
filename= None


outputQueue=None
luogo=""
udpDictCount={}
tlsDictCount={}

#########################LOADING VARIABILI############################################
iterloading = 0
printLoading=50

def getUDPCount():
	return udpDictCount

def getTLSCount():
	return tlsDictCount
def getTotPktCount():
	return totpkt

def addTLS(key):
	if(key in tlsDictCount):
		tlsDictCount[key]+=1
	else:
		tlsDictCount[key]=1

def addUDP(key):
	if(key in udpDictCount):
		udpDictCount[key]+=1
	else:
		udpDictCount[key]=1

def UDPControl(formlist):
    global UDPCount
    global AzioniEseguite
    UDPCount+=1
    info = "Controllo UDP"
    key = math.floor(float(formlist[1]))
    addUDP(key)
    #print(formlist[0])
    #JsonFile.create(info, formlist[1], formlist[0])


def TLSControl(formlist,pkt, capture):
    global AzioniEseguite
    global TLSCount
    global countReteEsterna
    global countReteInterna

    valoreNum = formlist[0]
    try:
        valoreNumInt = int(valoreNum)
        valoreAggiornato = valoreNumInt - 1
        pkt2 = capture[valoreAggiornato]
        line2 = str(pkt2)
        formlist2 = line2.split(" ")
        #print(str(formlist[0]) + " " +str(formlist2[0]))
        key = math.floor(float(formlist[1]))
        addTLS(key)

    except:
        formlist2 = None

    if (formlist[7] == "Hello"):
        if (formlist[6] == "Client"):
            info = "Apertura app"
            #(info)
           # print("src: " + formlist[2] + " dest: " + formlist[3])
            luogo = "Apertura"
            #JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
            key = math.floor(float(formlist[1]))
            #addTLS(key)

    if (formlist[4] == "TLSv1.2"):
        if (formlist[5] == "123"):
            #print(formlist[0])

            if (formlist2 is not None and formlist2[4] == 'TLSv1.2'):

                if (formlist2[5] == "123"):
                    info = " Pacchetto di controllo TLS"
                    #print(formlist2[1] + " Pacchetto di controllo TLS")
                    #print("src: " + formlist[2] + " dest: " + formlist[3])
                    TLSCount = TLSCount + 1
                    #print("------------------------")
                    #JsonFile.create(info, formlist[1], formlist[0])
                    key = math.floor(float(formlist[1]))
                    addTLS(key)

    #Controllo della lunghezza del pacchetto TLS 235 (in uesto caso può essere sia rete esterna che interna varie operazioni)
    if (formlist[4] == "TLSv1.2"):
        valoreNum = formlist[0]
        valoreNumInt = int(valoreNum)
        #print("ValoreInt 1 : "+str(valoreNumInt))
        valoreAggiornatoPrec = valoreNumInt - 3
        pkt2 = capture[valoreAggiornatoPrec]
        line2 = str(pkt2)
        formlist2 = line2.split(" ")
        #print("valorePrec " + formlist2[0])
        key = math.floor(float(formlist[1]))
        addTLS(key)
        if (formlist[5] == "235" and (formlist2[4]=="TCP" or formlist2[4]=="UDP")):

            valoreNum=formlist[0]
            valoreNumInt = int(valoreNum)
            #print("ValoreInt 1 : "+str(valoreNumInt))
            valoreAggiornato=valoreNumInt-1
            pkt2 = capture[valoreAggiornato]
            line2 = str(pkt2)
            formlist2 = line2.split(" ")
            #print("ValoreNO : "+ formlist2[0])
            if (formlist2[4] == "TLSv1.2"):
                key = math.floor(float(formlist2[1]))
                addTLS(key)
                if (formlist2[5] == "235"):
                    luogo="Esterna"
                    info= " RETE ESTERNA: E' stata eseguita una di queste azioni: Ipostazione Timer, Cambio Scheda, Accensione/Spegnimento"
                    print("------------------------")
                    print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: "+formlist[4] + " len1: "+formlist[5]+ " PROT2: "+formlist2[4] + " len2: "+formlist2[5])
                    print("------------------------")

                    luogo="Esterna"
                    JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
                    AzioniEseguite = AzioniEseguite + 1
                    countReteEsterna+=1

                elif(formlist2[5] == "123"):

                    info= " RETE INTERNA: E' stata eseguita una di queste azioni: Ipostazione Timer, Cambio Scheda, Accensione/Spegnimento"
                    print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                    print("------------------------")
                    luogo = "Interna"
                    JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)

                    AzioniEseguite = AzioniEseguite + 1
                    countReteInterna+=1

    # Controllo della lunghezza del pacchetto TLS 251 per il cambio colore Interna
    if (formlist[4] == "TLSv1.2"):
        key = math.floor(float(formlist[1]))
        addTLS(key)
        if (formlist[5] == "251"):
            valoreNum = formlist[0]
            valoreNumInt = int(valoreNum)
            # print("ValoreInt 1 : "+str(valoreNumInt))
            valoreAggiornato = valoreNumInt - 1
            pkt2 = capture[valoreAggiornato]
            line2 = str(pkt2)
            formlist2 = line2.split(" ")
            if (formlist2[4] == "TLSv1.2"):
                key = math.floor(float(formlist2[1]))
                addTLS(key)
                if (formlist2[5] == "123"):
                    valoreNum = formlist[0]
                    valoreNumInt = int(valoreNum)
                    # print("ValoreInt 1 : "+str(valoreNumInt))

                    valoreAggiornatoPre = valoreNumInt - 3
                    pkt3 = capture[valoreAggiornatoPre]
                    line3 = str(pkt3)
                    formlist3 = line3.split(" ")
                    if(formlist3[5]!="267"):
                        info = " RETE INTERNA: Cambio colore/Scadenza Timer "
                        print( info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " +formlist2[5])
                        print("------------------------")
                        luogo = "Interna"
                        JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
                        countReteInterna+=1

                        AzioniEseguite = AzioniEseguite + 1
    # Controllo della lunghezza del pacchetto TLS 267 per il cambio scena Interna

    if (formlist[4] == "TLSv1.2"):
        key = math.floor(float(formlist[1]))
        addTLS(key)
        if (formlist[5] == "267"):
            valoreNum = formlist[0]
            valoreNumInt = int(valoreNum)
            # print("ValoreInt 1 : "+str(valoreNumInt))
            valoreAggiornato = valoreNumInt - 1
            pkt2 = capture[valoreAggiornato]
            line2 = str(pkt2)
            formlist2 = line2.split(" ")
            if (formlist2[4] == "TLSv1.2"):
                key = math.floor(float(formlist2[1]))
                addTLS(key)
                if (formlist2[5] == "123"):
                    valoreNum = formlist[0]
                    valoreNumInt = int(valoreNum)
                    # print("ValoreInt 1 : "+str(valoreNumInt))
                    valoreAggiornato = valoreNumInt - 3
                    pkt3 = capture[valoreAggiornato]
                    line3 = str(pkt3)
                    formlist3 = line3.split(" ")
                    if (formlist3[5] != "267"):
                        key = math.floor(float(formlist3[1]))
                        addTLS(key)
                        info = " RETE INTERNA: Cambio Scena"
                        print( info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[ 4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " +formlist2[5])
                        print("------------------------")
                        luogo = "Interna"
                        JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
                        countReteInterna += 1

                        AzioniEseguite = AzioniEseguite + 1








    # Controllo della lunghezza del pacchetto TLS 331 per il cambio scena
    if (formlist[4] == "TLSv1.2"):
        key = math.floor(float(formlist[1]))
        addTLS(key)
        if (formlist[5] == "267"):
            if (formlist2[4] == "TLSv1.2"):
                key = math.floor(float(formlist2[1]))
                addTLS(key)
                if (formlist2[5] == "267"):
                    info = " RETE ESTERNA: Cambio Scena"
                    print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                    print("------------------------")
                    luogo = "Esterna"
                    JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
                    AzioniEseguite = AzioniEseguite + 1
                    countReteEsterna+=1

    # Controllo della lunghezza del pacchetto TLS 251 per il cambio colore
    if (formlist[4] == "TLSv1.2"):
        key = math.floor(float(formlist[1]))
        addTLS(key)
        if (formlist[5] == "267" and formlist2[4] == "TLSv1.2"):
            valoreNum = formlist[0]
            valoreNumInt = int(valoreNum)
            valoreAggiornato = valoreNumInt - 1
            pkt2 = capture[valoreAggiornato]
            line2 = str(pkt2)
            formlist2 = line2.split(" ")
            if (formlist2[4] == "TLSv1.2"):
                key = math.floor(float(formlist2[1]))
                addTLS(key)
                if (formlist2[5] == "251"):
                    info = " RETE ESTERNA: Cambio colore"
                    print( info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " +formlist2[5])
                    print("------------------------")
                    luogo = "Esterna"
                    JsonFile.create(info=info, timestamp=formlist[1], id=formlist[0], luogo=luogo)
                    AzioniEseguite = AzioniEseguite + 1
                    countReteEsterna+=1





def print_callback(pkt, capture):
    '''Questa funzione viene chiamata su ogni pacchetto.
    Si occupa di invocare varie funzioni in base al tipo di pacchetto. '''
    global iterloading
    global printLoading
    line = str(pkt)
    formlist = line.split(" ")

    if (printLoading == 50):
        points = '.' * iterloading + ' ' * (10 - iterloading)
        print("\rLoading " + points, end="\r")
        iterloading = (iterloading + 1) % 10
        printLoading = 1
    else:
        printLoading += 1

    '''if (not hasattr(pkt, 'ip')):
        return'''
    if (formlist[4] == "UDP"):
        UDPControl(formlist)
    if(formlist[4]=="TLSv1.2"):
        TLSControl(formlist,pkt, capture, )






def Scanner(ip_to_scan, pcap_in_filename, outQueue=None):
    global ip
    global ip2
    global outputQueue
    global countReteInterna
    global countReteEsterna
    global filename
    global totpkt
    global timeChartStart
    global timeChartEnd



    udpDictCount = {}
    stunDictCount = {}
    ip = ip_to_scan
    outputQueue = outQueue
    filename=pcap_in_filename

    capture = pyshark.FileCapture(pcap_in_filename,only_summaries=True)
    #print(str(capture[0]))

    try:
        for pkt in capture:
            totpkt+=1
            print_callback(pkt, capture)
    except:
        traceback.print_exc()

    print("\r                          ", end="\r")



    #if (outQueue is not None):
        #for c in chiamate:
            #outQueue.put(repr(c))

    if (outputQueue is not None):
        outputQueue.put(repr(stunDictCount))
        outputQueue.put(repr(udpDictCount))

    print("------------------------------------------------")
    return countReteInterna, countReteEsterna
