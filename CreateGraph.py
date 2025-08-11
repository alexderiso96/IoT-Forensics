import json
import pandas as pd
import matplotlib.pyplot as plt


def BarGraph(count):
    countInterna = count[0]
    countEsterna = count[1]

    names = ['Rete Intena', 'Rete esterna']
    values = [countInterna, countEsterna]
    plt.bar(names, values)
    plt.xlabel("Operazioni")
    plt.ylabel("N.Operazioni")
    plt.suptitle('Azioni Eseguite')
    plt.savefig("GraficoBarre", dpi=100)
    #plt.show()