import json
import pandas as pd
import matplotlib.pyplot as plt

packetinfo={}
packetinfo["packet"] = []
def create(info=None, timestamp=None, id=None, luogo=None):

    global packetinfo
    #packetinfo[id] = [timestamp , info]
    packetinfo["packet"].append({
        'id' : id,
        'Timestamp' : timestamp,
        'Info' : info,
        'luogo' : luogo
    })
    with open('data.json', 'w') as f:
        json.dump(packetinfo, f)



'''
   with open('data.json') as json_file:
       data = json.load(json_file)

       Timestamp = [i['Timestamp'] for i in data["packet"]]
       Info = [i['Info'] for i in data["packet"]]

       df = pd.DataFrame({'Timestamp':Timestamp, 'Info':Info})
       #df['Timestamp'] = [pd.to_datetime(i) for i in df['Timestamp']]
       plt.plot(Timestamp, Info)
       #plt.bar(Timestamp,Info)
       plt.title("Analisi dei pacchetti")
       plt.xlabel("Timestamp")
       plt.ylabel("Info")
       #plt.show()
       plt.savefig("Grafico.png", dpi=100)
'''




'''
    a_file = open("data.json","r")
    a_json = json.load(a_file)
    pretty_json = json.dumps(a_json, indent=4)
    a_file.close()

    print(pretty_json)

    packetinfo = {}
    packetinfo['TimeStamp'] = 123
    packetinfo['info'] = 124
    with open('data.json', 'a') as f:
        json.dump(packetinfo, f)

'''