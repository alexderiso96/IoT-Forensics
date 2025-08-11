
import sys, getopt
import ipaddress
import os.path
import networkAnalysis
import ReportFile
import time
import Analysis
import CreateGraph
import newScan

import JsonFile




def main(argv):
    usage = ("Usage: \n-i <inputfile> -a <ip>" +
             "\n\nOptions:\n  " +
             "-h,\t--help\t\tShow help.\n  " +
             "-i,\t--ifile <path>\tPath to the input .pcap or .pcapng file.\n  " +
             "-a,\t--ip \t\tThe target Ip to analyze for.\n  "+
             "-s,\t--start \t Additional information file.\n  "+
		     "-e,\t--end \t Ip target of the additional file\n  "
             )
    inputfile = ""
    ip = ""
    #print(usage)
    try:

        opts, args = getopt.getopt(argv, "hi:r:ws:e:a:",["ifile=", "help", "ip=","start=", "end="])
        #print(args)

    except getopt.GetoptError:
        print(usage)
        sys.exit(2)

        # parsing degli argomenti in input e controllo sui valori
    for opt, arg in opts:
        if (opt in ("-h", "--help")):
            print(usage)
            sys.exit()
        elif (opt in ("-i", "--ifile")):
            inputfile = arg
        elif (opt in ("-a", "--ip")):
            ip = arg
        elif (opt in ("-r", "--report")):
            reportDir = arg


    if(ip=="" or inputfile==""):
	    print("Error: missing argument required.")
	    print(usage)
	    sys.exit(2)
    try:
        ipaddress.ip_address(ip)
    except:
        print('Error bad IP Format')
        sys.exit(2)

    if (not os.path.isfile(inputfile) and not inputfile.endswith('.pcap') and not inputfile.endswith('.pcapng')):
        print('Error: insert a valid .pcap or pcapng file.')
        sys.exit(2)
    if (not reportDir == "" and os.path.isdir(reportDir)):
        print( 'Inalid Directory Name: Directory already exixsts. Report can\'t be saved in an existing directory.' )
        sys.exit(2)
    timestampStart = time.time()
    count = Analysis.Scanner(ip_to_scan=ip,pcap_in_filename=inputfile)
    print("Scansione Effettuata ....")
    #newScan.Scanner()
    #JsonFile.CreateGraph(count)
    print("Generazione Grafico ...")
    CreateGraph.BarGraph(count)

    #networkAnalysis.analisi(ip = ip, inputfile= inputfile)
    timestampEnd = time.time()
    print("Generazione Report ...")
    ReportFile1.saveReport(countTuple=count, reportDir=reportDir,timestampStart=timestampStart,timestampEnd=timestampEnd,inputFile= inputfile, ip=ip, tlsPkt=LibreriaPacchetti.getTLSCount(), udpPkt=LibreriaPacchetti.getUDPCount(),totPkt=LibreriaPacchetti.getTotPktCount())
    print("Report Salavto ...")




if __name__ == '__main__':
    main(sys.argv[1:])

