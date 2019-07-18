'''
Created on 2018.10.13

@author: Mengmeng Ge
'''
from SDIoTGen import *

from SecurityEvaluator import *
from RandomShufflingOptimization import *
from attackTree import *

#-----------------------------------------------------------------------------
# Parse solution, save output, calculate metrics
#-----------------------------------------------------------------------------

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
            "sslThreshold": 0.3, 
            #especially for adaptive interval function explanation: when the next time shuffling SSL value larger than the devised sslThreshold then stop, which means SFC have been reached
            "weights": [0.5, 0.5],#for GA runcase especially for normalization value
            "previous_solution": [0] * ((decoy_iot_num + server_num) * iot_num), #storing previous_solution for GA based network topology optimization procedure
            "simulation": 100, #simulating 100 times for getting expected_mttsf
            "sslThreshold_checkInterval": 0.01,  #change should be for the better way in a certain degree, other wise break 
            "detectionPro": 0.95 #for adaptive interval function SSL the coefficient whether the attacker can detect the node is decoy node
            }
    return info

def saveOutput(file_name, open_mode, metrics):
    file = open('D:/{}.txt'.format(file_name), open_mode)
    file.writelines(" ".join(metrics))
    file.writelines('\n')
    file.close()
    return None

def cacluateMetrics(initial_net, net, initial_info,model):
    """
        initial_net: the initial network
        net: decoy network
        initial info: initial information
    """
    #having a deep copy of the decoy network
    shuffled_net = copyNet(net)
    #adding attacker and defined the server node within the function
    add_attacker(shuffled_net)
    #Construct HARM and calculate metrics
    h = constructHARM(shuffled_net)
    #rebuild the attack graph path
    if model =='conjunction':
        h.model.travelAg_multitarget(model)
    elif model == 'disjunction':
        h.model.travelAg_multitarget(model)  
    else:
        h.model.travelAg_multitarget(model) 
        
#     h.model.printPath()
    #print attack graph network
    #h.model.printAG()
    #h.model.tree_AGAT_print()
    #calculate number of decoy path
    dpath = decoyPath(h)
    
    #initiate expected_mttsf
    expected_mttsf = 0.0
    for i in range(0, initial_info["simulation"]):
        #expected_mttsf += computeMTTSF(h, initial_net, initial_info["threshold"])
        expected_mttsf += computerMTTSF_multitarget(h, initial_net, initial_info["threshold"],model)

        
#     print(expected_mttsf)
    return dpath, float(expected_mttsf/initial_info["simulation"])


#-----------------------------------------------------------------------------
# Before shuffling
#-----------------------------------------------------------------------------

def beforeShuffle(num, file_name,model):
    #Create a real network list of IoT nodes
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    #list of decoy nodes such as {name:number} => {'ct':2}
    solution_set = {'laptop':num["laptop"], 'thermostat':num["thermostat"], 'tv':num["tv"], 'server':num["server"]}
    #create real IoT network
    net = createRealSDIoT(node_vlan_list)
    #printNet(net)

    #Add initial decoy deployment
    info = parse_solution_set(net, solution_set)
    #implement cyber deception mechanism
    decoy_net, decoy_list = add_decoy_deployment(net, info)
    
#     printNet(decoy_net)
    dpath, average_expected_mttsf = cacluateMetrics(net, decoy_net, info,model)
    
    saveOutput(file_name, 'w', [str(dpath), str(average_expected_mttsf), str(0.0)])
    return net, decoy_net, decoy_list, info

#-----------------------------------------------------------------------------
# Fixed interval
#-----------------------------------------------------------------------------



def fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, file_name, times,model):
    total_dp = 0
    total_mtssf = 0
    total_dc = 0
    i = 0
    while i < times:
        #print("Shuffle time:",  i+1)
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        defense_cost = cost/interval
        #print("Shuffled net:")
        #printNet(shuffled_net)
        dpath, average_expected_mttsf = cacluateMetrics(initial_net, shuffled_net, initial_info,model)
        total_dp += dpath
        total_mtssf += average_expected_mttsf
        total_dc += defense_cost
        if i == 0:
            saveOutput(file_name, 'w', [str(interval*(i+1)), str(dpath), str(average_expected_mttsf), str(defense_cost)])
        else:
            saveOutput(file_name, 'a+', [str(interval*(i+1)), str(dpath), str(average_expected_mttsf), str(defense_cost)])
        
        decoy_net = copyNet(shuffled_net)
        i += 1
    #getting the average number through the shuffling times
    print([str(total_dp/times), str(total_mtssf/times), str(total_dc/times)])
    return None

#-----------------------------------------------------------------------------
# Adaptive interval
#-----------------------------------------------------------------------------

def adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, file_name, model):

    newnet = copyNet(decoy_net)
    newnet = add_attacker(newnet)
    h = constructHARM(newnet)
    
    if model =='conjunction':
        h.model.travelAg_multitarget(model)
    elif model == 'disjunction':
        h.model.travelAg_multitarget(model)  
    else:
        h.model.travelAg_multitarget(model) 
    previous_ssl = 0
    
    compNodes = []
    totalMTTC = 0.0
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while (model == "conjunction" and previous_ssl <2) or (model == "disjunction" and previous_ssl < 3) or (model == "dynamic" and previous_ssl < 0.5):
        if model =='conjunction':
            ssl, mttc, compNodes, new_decoy_net = computeSSL_multi_conjunction(h, initial_net, decoy_net, initial_info["sslThreshold"], initial_info["sslThreshold_checkInterval"], 
                               initial_info["threshold"], initial_info["detectionPro"], 
                               initial_info["weights"][0], initial_info["weights"][1], 
                               previous_ssl, compNodes)
        elif model == 'disjunction':
            ssl, mttc, compNodes, new_decoy_net = computeSSL_multi_disjunction(h, initial_net, decoy_net, initial_info["sslThreshold"], initial_info["sslThreshold_checkInterval"], 
                               initial_info["threshold"], initial_info["detectionPro"], 
                               initial_info["weights"][0], initial_info["weights"][1], 
                               previous_ssl, compNodes) 
        else:
            ssl, mttc, compNodes, new_decoy_net = computeSSL_multi_dynamic(h, initial_net, decoy_net, initial_info["sslThreshold"], initial_info["sslThreshold_checkInterval"], 
                               initial_info["threshold"], initial_info["detectionPro"], 
                               initial_info["weights"][0], initial_info["weights"][1], 
                               previous_ssl, compNodes)
        
        totalMTTC += mttc
        
        
        if (model == "conjunction" and ssl <2) or (model == "disjunction" and ssl < 3) or (model == "dynamic" and ssl < 0.5):
            shuffled_net, cost = randomShuffling(new_decoy_net, pro)
            
            defense_cost = cost/mttc

            dpath, average_expected_mttsf = cacluateMetrics(initial_net, shuffled_net, initial_info, model)
            
            print([str(dpath), str(average_expected_mttsf), str(defense_cost)])
            
            if previous_ssl == 0:
                saveOutput(file_name, 'w', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost)])
            else:
                saveOutput(file_name, 'a+', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost)])
                
            decoy_net = copyNet(shuffled_net)
            newnet = copyNet(decoy_net)
            newnet = add_attacker(newnet)
            h = constructHARM(newnet)                           
        
        previous_ssl = ssl
        
    return None

 
if __name__ == '__main__':
    
    #multitarget_model = "conjunction"
    #multitarget_model = "disjunction"
    multitarget_model = "dynamic"


    num = {"thermostat":2, "laptop":2, "tv":2, "server":1}  #number of decoy nodes
    #initiate network, decoy net, initial information
    initial_net, decoy_net, decoy_list, initial_info = beforeShuffle(num, "init_decoy_net_metrics",multitarget_model)
    
    interval = 12           #(interval) defense_cost = shuffle cost/interval the simulated interval shuffling time 
    pro = 0.5                #deciding the frequency of random shuffling (shuffle cost)
    times_of_interval = 30  # shuffling times
    

    
    
    #fix interval random shuffling 
    fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, "fix_rs", times_of_interval,multitarget_model)
    #adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, "adaptive_rs",multitarget_model)
    

    