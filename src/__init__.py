from SDIoTGen import *
import json
import attackTree
def parse_solution_set(net, solution_set):
    
    ct_num, camera_num, tv_num, server_num = add_solution_set(solution_set)#number of decoynodes
    iot_num = getIoTNum(net) #IoT numbe except "server"
    decoy_iot_num = ct_num + camera_num + tv_num
    
    info = {"diot_dimension": ct_num + camera_num + tv_num,  # number of decoy node indicating the scale of the decoys
            "dserver_dimension": server_num,    #number of decoy servers
            "decoy_list": ["decoy_ct", "decoy_camera", "decoy_tv", "decoy_server"],  #list of decoy node name 
            "decoy_num": [ct_num, camera_num, tv_num, server_num],  #number of decoy nodes
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


if __name__ == '__main__':
    num = {"ct":2, "camera":2, "tv":2, "server":1}  #number of decoy nodes
    solution_set = {'ct':num["ct"], 'camera':num["camera"], 'tv':num["tv"], 'server':num["server"]}
    node_vlan_list = [['mri000', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    net = createRealSDIoT(node_vlan_list)
    info = parse_solution_set(net, solution_set)
    decoy_net, decoy_list = add_decoy_deployment(net, info)
    add_attacker(decoy_net)
    
    #creating corresponded json file for generating the network graph
    label_list = []
    edge_list = []
    for node in decoy_net.nodes:
        for conNode in node.con:
            edge_list.append((node.id,conNode.id))
        label_list.append((node.id, node.name))
    data = {'node':label_list,
            'edge':edge_list
            }
    #writng json file into "data network json"
    with open('data_network.json', 'w') as f:
        json.dump(data, f)
    
    print(data)
    #print generated network
    #printNet(net)
#     printNetWithVul(net)

    