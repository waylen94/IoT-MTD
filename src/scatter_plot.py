'''
Created on 2019年9月19日

@author: Administrator
'''
from matplotlib.ticker import FuncFormatter
import matplotlib.pyplot as plt
import numpy as np

label = ["0.1", '0.2', '0.3', '0.4', '0.5', '0.6', 
         '0.7', '0.8', '0.9']
measure = [461.7544512542883, 491.30219602813054, 597.1000837171088, 519.190230720889, 586.2227430152152, 569.3417238352005, 688.6843926194017, 560.6507223309969, 883.9151117483901]


def plot_measure(measure, ylabel, mark):
    _, ax = plt.subplots(figsize=(20, 10.0))
    index = np.arange(len(label))
    print(index)
    plt.plot(index, measure, color='grey', zorder=1, lw=3)
    plt.scatter(index, measure,  marker=mark, s=800, zorder=2)

    plt.xlabel('SSL Threshold', fontsize=35)
    plt.ylabel(ylabel, fontsize=35)

    plt.xticks(index, label, fontsize=20)
    plt.yticks(fontsize=20)
    plt.ylim(0, 1500)
    ax.margins(0.01)
    plt.grid()
    plt.show()
    #plt.savefig(ylabel.replace(" ", "")+'.png')
    #plt.close()

    return None

plot_measure(measure, 'MTTSF', 'o')



