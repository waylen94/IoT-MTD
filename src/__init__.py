from SDIoTGen import *
import json
import attackTree
from RandomShufflingOptimization import randomShuffling

import numpy as np
import matplotlib.pyplot as plt

import plotly.tools as tls

import plotly.graph_objects as go
from test.bisect import list_cases




def parse_solution_set(net, solution_set):
    
    laptop_num, thermostat_num, tv_num, server_num = add_solution_set(solution_set)#number of decoynodes
    iot_num = getIoTNum(net) #IoT numbe except "server"
    decoy_iot_num = laptop_num + thermostat_num + tv_num
    
    info = {"diot_dimension": laptop_num + thermostat_num + tv_num,  # number of decoy node indicating the scale of the decoys
            "dserver_dimension": server_num,    #number of decoy servers
            "decoy_list": ["decoy_laptop", "decoy_thermostat", "decoy_tv", "decoy_server"],  #list of decoy node name 
            "decoy_num": [laptop_num, thermostat_num, tv_num, server_num],  #number of decoy nodes
            "attackerIntelligence": {'emulated': 0.9, 'real': 1.0}, 
            #indicate the probability of the attacker to proceed using the decoy 
            #(distinguished by node type for this moment emulated 0.9 and real 1
            "threshold": float(1.0/3.0), #indication for security analysis such as MTTSF 
            "server_decoy_type": "real", #indicate the decoy server node type
            "riot_num": iot_num, #real node number
            "sslThreshold": 0.1, 
            #especially for adaptive interval function explanation: when the next time shuffling SSL value larger than the devised sslThreshold then stop, which means SFC have been reached
            "weights": [0.5, 0.5],#for GA runcase especially for normalization value
            "previous_solution": [0] * ((decoy_iot_num + server_num) * iot_num), #storing previous_solution for GA based network topology optimization procedure
            "simulation": 100, #simulating 100 times for getting ecpected_mttsf
            "sslThreshold_checkInterval": 0.01,  #change should be for the better way in a certain degree, other wise break 
            "detectionPro": 0.95 #for adaptive interval function SSL the coefficient whether the attacker can detect the node is decoy node
            }
    return info

def draw_diagram(y_label,file_name,draw_color,performance,prefix):
    
    objects = ('FS-RNT(S)','AS-RNT(S)','FS-RNT(M)','AS-RNT(M)')
    y_pos = [2,4,6,8]
    performance = [performance[0],performance[1],performance[2],performance[3]]
    plt.figure(figsize=(6,6))
    plt.bar(y_pos, performance, width = 0.6, color = draw_color, align = "center")
    plt.xticks(y_pos, objects,fontsize=10)
    plt.xlabel('Schemes',fontsize=15)
    plt.ylabel(y_label,fontsize=17)
    plt.savefig(prefix+file_name)
     
    
def network_diagram_generation():
    num = {"laptop":2, "thermostat":2, "tv":2, "server":1}  #number of decoy nodes
    solution_set = {'laptop':num["laptop"], 'thermostat':num["thermostat"], 'tv':num["tv"], 'server':num["server"]}
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    net = createRealSDIoT(node_vlan_list)
    info = parse_solution_set(net, solution_set)
    net, decoy_list = add_decoy_deployment(net, info)
    add_attacker(net)
     
#     decoy_net1, cost = randomShuffling(decoy_net, 0)
    #creating corresponded json file for generating the network graph
    label_list = []
    edge_list = []
    for node in net.nodes:
        for conNode in node.con:
            edge_list.append((node.id,conNode.id))
        label_list.append((node.id, node.name))
    data = {'node':label_list,
            'edge':edge_list
            }
    #writng json file into "data network json"
    with open('data_network.json', 'w') as f:
        json.dump(data, f)
         
#     print("cost: "+str(cost))
    print(data)    #print generated network
    #printNet(net)
    #printNetWithVul(net)
    
    #dodgeblue orange brown darkseagreen crimson
        
if __name__ == '__main__':
    """
    Json generator
    
    """
#     network_diagram_generation()
    
    
    list_y_label = ['Average PDP','Average MTTSF', 'Average DC per time unit',
                    'Average AIM', 'Average AE']
    list_file_name = ["Proportion_of_decoy_paths_among_attack_paths","Average_MTTSF","Average_defense_cost_per_time_unit",
                      "Average_degree_of_attack_impact","Average_attack_exploitability"]
    list_color = ["dodgerblue","orange","brown","darkseagreen","crimson"]
     
    performance = [[0.791,0.794,0.795,0.795],[478,579,507,634],[2.04,0.63,2.08,0.58],[15.96,16.35,16.46,17.15],[7.61,7.95,7.86,7.74]]
    prefix = "R5_1_comparison_"
     
    for i in range(0,5):
        draw_diagram(list_y_label[i], list_file_name[i], list_color[i], performance[i],prefix)

"""



0. only one target with real-os under low attacker intelligence
[[0.791,0.794],[478,579],[2.04,0.63],[15.96,16.35],[7.61,7.95]]


1. multiple target with real-os under low attacker intelligence
[[0.795,0.795],[507,634],[2.08,0.58],[16.46,17.15],[7.86,7.74]]


2.multiple target with real-os and emulated under low attacker intelligence
[[0.795,0.800],[495,585],[2.06,0.25],[16.45,17.34],[7.88,8.20]]


3.multiple target with real-os under medium attacker intelligence
[[0.796,0.805],[460,534],[1.95,0.53],[16.45,16.06],[7.85,7.67]]

4.only one target with real-os under medium attakcer intelligence
[[0.798,0.806],[432,557],[1.97,1.00],[15.99,14.85],[7.62,6.05]]


-------------------------------------------------------------------------------
tiltle:  Proportion_of_decoy_paths_with_attack_paths    
y:  percentage of decoy paths with all attack paths

color = "dodgerblue"
plt.ylabel('Proportion of decoy paths among attack paths')
plt.savefig("Proportion_of_decoy_paths_among_attack_paths")

plt.title('Proportion of decoy paths among attack paths')
-------------------------------------------------------------------------------
title:  Average MTTSF       orange    
y:  Mean time to security failure

color = "orange"
plt.ylabel('Average MTTSF')
plt.savefig("Average_MTTSF")
plt.title('Average MTTSF')
-------------------------------------------------------------------------------
title:  Average defense cost per time unit      brown
y:  Cost per unit time (hour)

color = "brown"
plt.ylabel('Average defense cost per time unit')
plt.savefig("Average_defense_cost_per_time_unit")
    
plt.title('Average defense cost per time unit')
-------------------------------------------------------------------------------
title:  Average attack impact       darkseagreen
y:  Average degree of attack impact

color = "darkseagreen"
plt.ylabel('Average degree of attack impact')    
plt.savefig("Average_degree_of_attack_impact")

plt.title('Average attack impact')
-------------------------------------------------------------------------------
title:  Average attack exploitability    crimson
y:  Average degree of attack exploitability

color = "crimson"
plt.ylabel('Average attack exploitability')
plt.savefig("Average_attack_exploitability")

plt.title('Average attack exploitability')

"""
    
    
#     
#     decoy_net2, cost = randomShuffling(decoy_net1, 0)
#     #creating corresponded json file for generating the network graph
#     label_list = []
#     edge_list = []
#     for node in decoy_net2.nodes:
#         for conNode in node.con:
#             edge_list.append((node.id,conNode.id))
#         label_list.append((node.id, node.name))
#     data = {'node':label_list,
#             'edge':edge_list
#             }
#     #writng json file into "data network json"
#     with open('data_network.json', 'w') as f:
#         json.dump(data, f)
#     print("cost: "+str(cost))
#     print(data)

    