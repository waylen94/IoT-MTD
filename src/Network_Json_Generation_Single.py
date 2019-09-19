from SDIoTGen import *
import json

def parse_solution_set(net, solution_set):
    
    laptop_num, thermostat_num, tv_num, server_num = add_solution_set(solution_set)#number of decoynodes
    iot_num = getIoTNum(net) #IoT numbe except "server"
    info = {"diot_dimension": laptop_num + thermostat_num + tv_num,  # number of decoy node indicating the scale of the decoys
            "dserver_dimension": server_num,    #number of decoy servers
            "decoy_list": ["decoy_laptop", "decoy_thermostat", "decoy_tv", "decoy_server"],  #list of decoy node name 
            "decoy_num": [laptop_num, thermostat_num, tv_num, server_num],  #number of decoy nodes
            "attackerIntelligence": {'emulated': 0.9, 'real': 1.0}, #indicate the probability of the attacker to proceed using the decoy
            "server_decoy_type": "real", #indicate the decoy server node type
            "riot_num": iot_num, #real node number
            }
    return info
    
    
    
    
def case1_original_network():
    print("Initializing original network")
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    net = createRealSDIoT(node_vlan_list)
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
    with open('data_network_origin.json', 'w') as f:
        json.dump(data, f)
    print("Total items:"+str(len(edge_list)+len(label_list)))     
    #testing for printing generated network json-format
    print("origin network json:")
    print(data)    
    
def case2_network_with_attacker():
    print("Initializing original network with attcker")

    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    net = createRealSDIoT(node_vlan_list)
    add_attacker(net)  
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
    with open('data_network_attacker.json', 'w') as f:
        json.dump(data, f)
    print("Total items:"+str(len(edge_list)+len(label_list)))     
    #testing for printing generated network json-format
    print("network with attacker json:")
    print(data)    
    
    
def case3_current_network():
    print("Initializing current network")
    num = {"laptop":2, "thermostat":2, "tv":2, "server":1}  #number of decoy nodes
    solution_set = {'laptop':num["laptop"], 'thermostat':num["thermostat"], 'tv':num["tv"], 'server':num["server"]}
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    net = createRealSDIoT(node_vlan_list)
    info = parse_solution_set(net, solution_set)
    net, decoy_list = add_decoy_deployment(net, info)
    add_attacker(net)  
#    decoy_net1, cost = randomShuffling(decoy_net, 0)
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
    with open('data_network_current.json', 'w') as f:
        json.dump(data, f)
    print("Total items:"+str(len(edge_list)+len(label_list)))     
    #testing for printing generated network json-format
    print("current network json:")
    print(data)    
     
    
def case4_simulated_medium_scale_network():
    print("Initializing medium scale network")
    num = {"laptop":20, "thermostat":20, "tv":20, "server":5}  #number of decoy nodes
    solution_set = {'laptop':num["laptop"], 'thermostat':num["thermostat"], 'tv':num["tv"], 'server':num["server"]}
    vlan1, vlan2, vlan3 = [],[],[]
    for x in range(10):
        vlan1.append('mri'+str(x))
        vlan1.append('ct'+str(x))
        vlan2.append('thermostat'+str(x))
        vlan2.append('meter'+str(x))
        vlan2.append('camera'+str(x))
        vlan3.append('tv'+str(x))
        vlan3.append('laptop'+str(x))
    vlan4 = ['server1''server2','server3','server4','server5']
    node_vlan_list = [vlan1,vlan2,vlan3,vlan4]
    
    net = createRealSDIoT(node_vlan_list)
    info = parse_solution_set(net, solution_set)
    net, decoy_list = add_decoy_deployment(net, info)
    add_attacker(net)

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
    print("Total items:"+str(len(edge_list)+len(label_list)))
    #writng json file into "data network json"
    with open('data_network_medium_scale.json', 'w') as f:
        json.dump(data, f)
        
    #testing for printing generated network json-format
    print("medium scale network json:")     
    print(data)    
    
    
if __name__ == '__main__':
    
    case1_original_network()
    case2_network_with_attacker()
    case3_current_network()
    case4_simulated_medium_scale_network()


    