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


def plot_measure_single(measure, ylabel, mark):
    _, ax = plt.subplots(figsize=(20, 10.0))
    index = np.arange(len(label))
    print(index)
    plt.plot(index, measure, color='orange', zorder=1, lw=3)
    
    plt.scatter(index, measure,  marker=mark, s=800, zorder=2,color='orange')

    plt.xlabel('SSL Threshold', fontsize=35)
    plt.ylabel(ylabel, fontsize=35)

    plt.xticks(index, label, fontsize=20)
    plt.yticks(fontsize=20)
#     plt.ylim(0)
#     ax.margins(x = 0.01,y = 0.01)
    plt.grid()
#     plt.show()
    plt.savefig("Sensitivity_analysis_MTTSF"+".png")
    #plt.close()

    return None


def plot_measure_multiple(measure, ylabel, mark,file_name,list_color):
    _, ax = plt.subplots(figsize=(20, 10.0))
    index = np.arange(len(label))
    for i in range(len(measure)):
        
        print(index)
#         plt.plot(index, measure[i], color='grey', zorder=1, lw=3,label = ylabel[i])
        plt.plot(index, measure[i], zorder=1, lw=3,label = ylabel[i], color = list_color[i])
        
        plt.scatter(index, measure[i],  marker=mark, s=800, zorder=2, color = list_color[i])
    
        plt.xlabel('SSL Threshold', fontsize=20)
#         plt.ylabel(ylabel, fontsize=35)
    
        plt.xticks(index, label, fontsize=20)
        plt.yticks(fontsize=30)
        
#     plt.ylim(0)
    ax.margins(x = 0.01)
    ax.legend(fontsize=20);
    plt.grid()
#     plt.show()
    plt.savefig("Mix_4_Metrics1"+".png")
    #plt.close()

    return None



'''
[504.30837884331436, 602.8543048723462, 603.9514213849671, 552.7436460781322, 622.0640127339617, 943.2420340767725, 556.3376129997313, 707.4392221228187, 609.1845993466703]

[0.74, 0.8059701492537313, 0.7976171054257817, 0.7977842945584882, 0.7884399551066217, 0.7869258623975606, 0.7813736574335783, 0.7988095238095239, 0.7515326361341508]
[0.132, 1.1340000000000001, 0.44882779708658993, 0.12838999069994314, 0.35961579988266906, 0.42358333333333337, 0.5226072697870275, 0.6883333333333334, 0.11677028928198788]
[17.405000000000026, 15.848000000000019, 15.716666666666688, 17.660666666666696, 15.34500000000002, 15.944666666666691, 16.78900000000003, 15.522000000000016, 15.933500000000024]
[7.572999999999997, 7.156999999999999, 7.919666666666668, 8.464, 7.475666666666663, 6.2983333333333364, 7.529999999999999, 6.805500000000002, 7.131499999999996]
'''

#single file
#[504.30837884331436, 602.8543048723462, 603.9514213849671, 552.7436460781322, 622.0640127339617, 943.2420340767725, 556.3376129997313, 707.4392221228187, 609.1845993466703]

# plot_measure(measure, 'MTTSF', 'o')


#multiple scatter graph
list_measure = [[0.74, 0.8059701492537313, 0.7976171054257817, 0.7977842945584882, 0.7884399551066217, 0.7869258623975606, 0.7813736574335783, 0.7988095238095239, 0.7515326361341508]
,[0.132, 1.1340000000000001, 0.44882779708658993, 0.12838999069994314, 0.35961579988266906, 0.42358333333333337, 0.5226072697870275, 0.6883333333333334, 0.11677028928198788]
,[17.405000000000026, 15.848000000000019, 15.716666666666688, 17.660666666666696, 15.34500000000002, 15.944666666666691, 16.78900000000003, 15.522000000000016, 15.933500000000024]
,[7.572999999999997, 7.156999999999999, 7.919666666666668, 8.464, 7.475666666666663, 6.2983333333333364, 7.529999999999999, 6.805500000000002, 7.131499999999996]
]
list_y_label = ['Average PDP', 'Average DC ',
                    'Average AIM', 'Average AE']
list_file_name = ["Proportion_of_decoy_paths_among_attack_paths","Average_MTTSF","Average_defense_cost_per_time_unit",
                      "Average_degree_of_attack_impact","Average_attack_exploitability"]

prefix = "sensitivity_1"
list_color = ["dodgerblue","brown","darkseagreen","crimson"]


# plot_measure_multiple(list_measure, list_y_label , 'o',file_name = "MIX", list_color = list_color)

plot_measure_single([504.30837884331436, 602.8543048723462, 603.9514213849671, 552.7436460781322, 622.0640127339617, 943.2420340767725, 556.3376129997313, 707.4392221228187, 609.1845993466703]
, "Average MTTSF" , 'o')
 



