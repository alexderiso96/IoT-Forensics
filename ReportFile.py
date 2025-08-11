import json
import os.path
from distutils.dir_util import copy_tree
import time
import subprocess
import re

import datetime

class ExistingDirectory(Exception):
    def __init__(self, msg):
       self.message=msg



def saveReport(countTuple = None, reportDir = None,timestampStart = None,timestampEnd = None, inputFile = None,ip = None ,tlsPkt=None, udpPkt=None,totPkt=None):
    tempoImpiegato= timestampEnd-timestampStart
    timestampGenerazione = time.time()
    #reportName = 'C:\Users\Alex\PycharmProjects\ProgettoTesi\OutputPage'
    graphPath = "C:\\Users\\Alex\\PycharmProjects\\ProgettoTesi\\GraficoBarre.png"
    #infos = subprocess.run(['capinfos', '-a', '-e', inputFile], stdout=subprocess.PIPE).stdout.decode('utf-8')
    #infosTimes = re.findall("[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+,[0-9]+", infos)
    #totPkt=0
    countReteInterna =countTuple[0]
    countReteEsterna = countTuple[1]



    datasetTLS = "["
    appoggioTLS = 0
    for key in tlsPkt:
        for i in range(appoggioTLS, key):
            datasetTLS += "0,"
        datasetTLS += str(tlsPkt[key]) + ","
        appoggioTLS = key + 1
    datasetTLS = datasetTLS[0:-1] + "]"

    #totPkt = 0
    datasetUDP = "["
    appoggioUDP = 0
    for key in udpPkt:
        for i in range(appoggioUDP, key):
            datasetUDP += "0,"
        datasetUDP += str(udpPkt[key]) + ","
        appoggioUDP = key + 1
        #totPkt += udpPkt[key]
    datasetUDP = datasetUDP[0:-1] + "]"

    labels = "["
    for i in range(max(appoggioTLS, appoggioUDP)):
        labels += str(i) + ","

        #print("LABEL")
        #print(i)
    labels = labels[0:-1] + "]"
    #print("Full Label")
    #print(labels)


    graphString = '''var ctxL = document.getElementById("lineChart").getContext('2d');
    		var myLineChart = new Chart(ctxL, {type: 'line',
    			   data: { labels:''' + labels + ''',
    						datasets: [{ label: "UDP",
    									 data: ''' + datasetUDP + ''' ,
    									 backgroundColor:'rgba(236, 64, 122, 1)',
    									 borderColor:'rgba(236, 64, 122, 1)',
    									 pointBackgroundColor:'rgba(236, 64, 122, 0.4)',
    									 pointBorderColor:'rgba(236, 64, 122, 0.4)',
    									 borderWidth: 3,
    									 fill:false},
    									{ label: "TLS",
    									  data:''' + datasetTLS + ''',
    									 pointBackgroundColor: 'rgba(92, 107, 192, 0.4)',
    									 pointBorderColor: 'rgba(92, 107, 192, 0.4)',
    									 backgroundColor:  'rgba(92, 107, 192, 1)',
    									 borderColor: 'rgba(92, 107, 192, 1)',
    									 borderWidth: 3,
    									 fill:false}]},
    				options: {responsive: true,
    						  legend:{position:'bottom'}}});'''

    #------------------------------------------------------------------------

    with open('data.json') as json_file:

        data = json.load(json_file)

        '''
        datasetInfo = "["
        for key in data['packet']:
            datasetInfo += str(key['Info']) + ","

        datasetInfo = datasetInfo[0:-1] + "]"

        label = "["
        for key in data['packet']:
            label += str(key['Timestamp']) + ","
            totPkt+=1
        label = label[0:-1] + "]"
'''
#---------------------------------------------------



        packetString=''''''
        Timestamp = [i['Timestamp'] for i in data["packet"]]

        packetString += '''
                    <div class = "row align-items-left" style="margin: 15px" >
                        <h5> Summary table </h5>
                        <table class ="table table-bordered" >
                         <thead>
                            <tr>
                                <th>ID</th>
                                <th>TimeStamp</th>
                                <th>Network</th>
                                <th>Command</th>
                            </tr>
                       </thead>
                            <tbody>'''




        for i in data["packet"]:

            packetString += '''
                        <tr>
                            <td class='''+str(i['luogo'])+'''> '''+i['id']+''' </td>
                            <td class='''+str(i['luogo'])+'''> '''+i['Timestamp']+''' </td>
                            <td class='''+str(i['luogo'])+'''>'''+i['luogo']+''' </td>
                            
                                    
                            
                            <td class='''+str(i['luogo'])+'''> '''+i['Info']+'''
                        </tr>
                    '''
        packetString += '''</tbody>
                </table>
            </div>
            
            
            '''
        strHTML = '''<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Report</title>
		<link href="css/bootstrap.min.css" rel="stylesheet">
		<link rel="stylesheet" type="text/css" href="css/indexStyle.css">
	</head>
	<body>
		<div class="container-fluid h-100" style="padding: 0px">
			<div class="row d-flex align-items-center" style="margin: 0px; border-bottom: 1px solid #bdbdbd;">
				<div>
				</div>
				<div>
					<h2 class="goleft mainColor" > IoT Forensics </h2>	
				</div>
			</div>
			<div class = "row d-flex align-items-center" >
				<div class="col-lg-12 col-md-12 col-sm-12 col-xs-12"style="padding-top:1em; width:100%;">
					<div class="text-center">
						<h2>Packet Analysis Report </h2>
					</div>
				</div>
			</div>
			<div class = "row align-items-left" style="margin: 15px; margin-bottom: 0px;" >
				<h3> Sniffing Informations</h3>
			</div>
			<div class = "row align-items-left" style="margin: 15px; margin-bottom: 0px;" >
				<p>"In this section the general information about the analysis are shown.</p>
				
			</div>
			<div class = "row align-items-left col-lg-6 col-md-12 col-sm-12 col-xs-12" style="margin: 15px" >
					<table class="table table-bordered" >
						<tbody>
							<tr>
								<th >Time spent on scanning</th>
								<td> sec.'''+ str(tempoImpiegato) +''' </td>
							</tr>
							<tr>
								<th >Report generation time</th>
								<td>'''+ str(datetime.datetime.fromtimestamp(timestampGenerazione).strftime('%Y-%m-%d %H:%M:%S')) +''' </td>
							</tr>
						</tbody>
					</table>
				</div>
				
			<div class = "row align-items-left" style="margin: 15px; margin-top: 0px;" >
				<div class="list-group col-lg-4 col-md-12 col-sm-12 col-xs-12" style="margin-top: 2em">
					<h5>Scan Detail:</h5>
					<div>
						<a class="list-group-item flex-column align-items-start">
							<h6 class="mb-1"><b>Analyzed File:</b></h6>
							<p class="mb-1"> '''+str(inputFile)+'''</p>
						</a>
						<a class="list-group-item flex-column align-items-start">
							<h6 class="mb-1"><b>Number Analyzed Packet</b></h6>
							<p class="mb-1">'''+str(totPkt)+'''</p>
						</a>
						<a class="list-group-item flex-column align-items-start">
							<h6 class="mb-1"><b>Target IP</b></h6>
							<p class="mb-1">'''+ip+'''</p>
						</a>
				'''

        strHTML += '''	</div>
					</div>
					
					<div class="col-lg-8 col-md-12 col-sm-12 col-xs-12" style="margin-top: 2em">
						<h5>Packets Graph:</h5>
						<div class="col-lg-8 col-md-12 col-sm-12 col-xs-12" style="margin-top: 2em">
					<h5>Packets Per Second:</h5>
					<canvas id="lineChart"></canvas>
				</div>
					
					
					
					
					
				</div>
				<div class = "row align-items-left" style="margin: 15px" >
					<h3> Packet Informations</h3>
				</div>
				<div class = "row align-items-left" style="margin: 15px" >
					<p>In this section all the information about the operation found are reported. There is a table for each operation. These are the possible fields:</p>
					<ul>
					<li><b>ID</b>: It represents the id of the command </li>
		            <li><b>Timestamp l</b>: It represents the time of the command.  </li>
		            <li>Network</b>: Describes whether a device is on an internal or external network</li>
	            	<li><b>Command</b>: Description of the recognized command</li>
	            	</li>
        		</ul>
					
					'''



        strHTML += '''
        		</div>
        	''' + packetString + '''
        		</div> 
        		
        		
        		
        		

        		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
        		<script src="js/bootstrap.min.js"></script>
        		<script src="js/charts.js"></script>
        		<script src="js/graph.js"></script>
        	</body>
        	</html>'''

        if (os.path.isdir(reportDir)):
            raise ExistingDirectory(reportDir)
        copy_tree('./Output_Page', reportDir)
        #copy_tree('Output_Page', reportName)

        graph_file = open(reportDir + "/js/graph.js", "w")
        graph_file.write(graphString)
        graph_file.close()


        Html_file = open(reportDir + "/index.html", "w")
        Html_file.write(strHTML)
        Html_file.close()