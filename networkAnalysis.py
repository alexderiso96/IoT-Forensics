import pyshark
import json
import JsonFile
import ReportFile


def analisi(ip= None, inputfile=None):


    c = pyshark.FileCapture(inputfile, only_summaries=True)
    list=[]
    cont=0
    UDPcontrol=0
    TLSControl=0
    AzioniEseguite = 0
    packetinfo = {}
    valoreAggiornato=0
    valoreNumInt=0
    valoreNum=0





    for p in c:
        line = str(p)
        formlist = line.split(" ")
        valoreNum = formlist[0]
        try:
            valoreNumInt = int(valoreNum)
            valoreAggiornato = valoreNumInt - 1
            pkt = c[valoreAggiornato]
            line2 = str(pkt)
            formlist2 = line2.split(" ")
        except:
            formlist2 = None


        if(formlist[2]==ip or formlist[3]==ip):

            if(formlist[7]=="Hello"):
                if(formlist[6]=="Client"):
                    info = "Apertura app"
                    print(info)
                    print("src: " + formlist[2]+" dest: "+formlist[3])
                    AzioniEseguite= AzioniEseguite+1
                    JsonFile.create(info, formlist[1], formlist[0])



            if (formlist[4] == "UDP"):
                UDPcontrol = UDPcontrol + 1
                info = "Controllo UDP"
                JsonFile.create(info, formlist[1],formlist[0])

            #Pacchetti di controllo TLS
            if (formlist[4] == "TLSv1.2"):
                if (formlist[5] == "123"):
                    if (formlist2[4] == "TLSv1.2"):
                       if (formlist2[5] == "123"):
                            info = " Pacchetto di controllo TLS"
                            print(formlist2[1] + " Pacchetto di controllo TLS")
                            print("src: " + formlist[2] + " dest: " + formlist[3])
                            TLSControl=TLSControl+1
                            print("------------------------")
                            JsonFile.create(info, formlist[1],formlist[0])

            #Controllo della lunghezza del pacchetto TLS 235 (in uesto caso può essere sia rete esterna che interna varie operazioni)
            if (formlist[4] == "TLSv1.2"):
                valoreNum = formlist[0]
                valoreNumInt = int(valoreNum)
                #print("ValoreInt 1 : "+str(valoreNumInt))
                valoreAggiornatoPrec = valoreNumInt - 3
                pkt = c[valoreAggiornatoPrec]
                line2 = str(pkt)
                formlist2 = line2.split(" ")
                #print("valorePrec " + formlist2[0])
                if (formlist[5] == "235" and (formlist2[4]=="TCP" or formlist2[4]=="UDP")):

                    valoreNum=formlist[0]
                    valoreNumInt = int(valoreNum)
                    #print("ValoreInt 1 : "+str(valoreNumInt))
                    valoreAggiornato=valoreNumInt-1
                    pkt = c[valoreAggiornato]
                    line2 = str(pkt)
                    formlist2 = line2.split(" ")
                    #print("ValoreNO : "+ formlist2[0])
                    if (formlist2[4] == "TLSv1.2"):
                        if (formlist2[5] == "235"):

                            info= " RETE ESTERNA: E' stata eseguita una di queste azioni: Ipostazione Timer, Cambio Scheda, Accensione/Spegnimento"
                            print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: "+formlist[4] + " len1: "+formlist[5]+ " PROT2: "+formlist2[4] + " len2: "+formlist2[5])
                            print("------------------------")
                            JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0])
                            AzioniEseguite = AzioniEseguite + 1

                        elif(formlist2[5] == "123"):
                            info= " RETE INTERNA: E' stata eseguita una di queste azioni: Ipostazione Timer, Cambio Scheda, Accensione/Spegnimento OR RETE ESTERNA: Scadenza Timer"
                            print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                            print("------------------------")
                            JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0])
                            AzioniEseguite = AzioniEseguite + 1

            # Controllo della lunghezza del pacchetto TLS 331 per il cambio colore Interna
            if (formlist[4] == "TLSv1.2"):
                if (formlist[5] == "251" and (formlist2[4]=="TCP" or formlist2[4]=="UDP")):
                    if (formlist2[4] == "TLSv1.2"):
                        if (formlist2[5] == "123"):
                            info= " RETE INTERNA: Cambio colore/Scadenza Timer || Azione non riconosciuta perfettamente"
                            print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                            print("------------------------")
                            JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0])

                            AzioniEseguite = AzioniEseguite + 1

            # Controllo della lunghezza del pacchetto TLS 331 per il cambio scena
            if (formlist[4] == "TLSv1.2"):
                if (formlist[5] == "331"):
                    if (formlist2[4] == "TLSv1.2"):
                        if (formlist2[5] == "315"):
                            info = " RETE ESTERNA: Cambio Scena"
                            print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[
                                4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                            print("------------------------")
                            JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0])
                            AzioniEseguite = AzioniEseguite + 1

            # Controllo della lunghezza del pacchetto TLS 251 per il cambio colore
            if (formlist[4] == "TLSv1.2"):
                if (formlist[5] == "267" and formlist2[4]=="TLSv1.2"):
                    valoreNum = formlist[0]
                    valoreNumInt = int(valoreNum)
                    valoreAggiornato = valoreNumInt - 1
                    pkt = c[valoreAggiornato]
                    line2 = str(pkt)
                    formlist2 = line2.split(" ")
                    if (formlist2[4] == "TLSv1.2"):
                        if (formlist2[5] == "123"):
                            info = " RETE ESTERNA: Cambio colore"
                            print(info + "\n" "src: " + formlist[2] + " dest: " + formlist[3] + " PROT1: " + formlist[4] + " len1: " + formlist[5] + " PROT2: " + formlist2[4] + " len2: " + formlist2[5])
                            print("------------------------")
                            JsonFile.create(info= info, timestamp=formlist[1], id=formlist[0])
                            AzioniEseguite = AzioniEseguite + 1

            """#Controllo solo sotto rete interna (Cambio Scena)
            if (formlist[4] == "TLSv1.2"):
                if (formlist[5] == "267"):
                    print(formlist[1] + " RETE INTERNA: E' stata cambiata la scena")
                    print("src: " + formlist[2] + " dest: " + formlist[3])
                    print("------------------------")
            """
            cont=cont+1




    print("PACCHETTI DI CONTROLLO UDP: "+str(UDPcontrol))
    print("PACCHETTI DI CONTROLLO TLS: "+str(TLSControl))
    print("AZIONI ESEGUITE: " +  str(AzioniEseguite))

