'''
Created on 2018.10.13
@author: Mengmeng Ge
'''
from SDIoTGen import *

from SecurityEvaluator import *
from RandomShufflingOptimization import *
from attackTree import *
from Metrics import attack_exploitability, attack_impact
from notebook.base.handlers import non_alphanum

#-----------------------------------------------------------------------------
# Parse solution, save output, calculate metrics
#-----------------------------------------------------------------------------

def parse_solution_set(net, solution_set):
    
    laptop_num, thermostat_num, tv_num, server_num = add_solution_set(solution_set)
    iot_num = getIoTNum(net)
    decoy_iot_num = laptop_num + thermostat_num + tv_num    
    
    info = {"diot_dimension": laptop_num + thermostat_num + tv_num, "dserver_dimension": server_num, 
            "decoy_list": ["decoy_laptop", "decoy_thermostat", "decoy_tv", "decoy_server"], 
            "decoy_num": [laptop_num, thermostat_num, tv_num, server_num], 
            "attackerIntelligence": {'emulated': 0.95, 'real': 1.0},
            "threshold": float(1.0/3.0), 
            "server_decoy_type": "real", "riot_num": iot_num, 
            "previous_solution": [0] * ((decoy_iot_num + server_num) * iot_num), 
            "simulation": 100, 
            "weights":[0.5,0.5],
            "sslThreshold_checkInterval": 0.01, 
            "detectionPro": 0.95,
            "sslThreshold": 0.8,
            }
    return info

def saveOutput(file_name, open_mode, metrics):
    file = open('D:/{}.txt'.format(file_name), open_mode)
    file.writelines(" ".join(metrics))
    file.writelines('\n')
    file.close()
    return None

def cacluateMetrics(initial_net, net, initial_info):
    
    shuffled_net = copyNet(net)
    #Construct HARM and calculate metrics
    add_attacker(shuffled_net)
    h = constructHARM(shuffled_net)
    dpath, rsum= decoyPath(h)
    expected_mttsf = 0.0
    expected_ai = 0.0
    expected_ae = 0.0
    total_attack_count = 0
    times = initial_info["simulation"]
#     print(rsum)
#     h.model.printAG()
    for i in range(0, initial_info["simulation"]):
#         print("simulation times:", i )
        newnet = copyNet(net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet)
        """clean up the compromise items"""
        MTTSF, attack_exploitability, attack_impact , flag, attackcount = computeMTTSF(h, initial_net, initial_info["threshold"])
        
        expected_mttsf +=MTTSF
        expected_ae +=attack_exploitability
        expected_ai +=attack_impact
        total_attack_count += attackcount
        
#         print(str(attack_impact) +"  "+ "MTTSF     "+ str(MTTSF) + str(flag))
#         print(expected_ai)
        
#     print(total_attack_count)
    return float(dpath/(dpath+rsum)), float(expected_mttsf/times), float(expected_ai/times),float(expected_ae/times)

#-----------------------------------------------------------------------------
# Before shuffling
#-----------------------------------------------------------------------------

def beforeShuffle(num, file_name):
    #Create a real network
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server1']]
    solution_set = {'laptop':num["laptop"], 'thermostat':num["thermostat"], 'tv':num["tv"], 'server':num["server"]}
    net = createRealSDIoT(node_vlan_list)
    #printNet(net)

    #Add initial decoy deployment
    info = parse_solution_set(net, solution_set)
    decoy_net, decoy_list = add_decoy_deployment(net, info)
    
    dpath, average_expected_mttsf, average_expected_ai, average_expected_ae = cacluateMetrics(net, decoy_net, info)
    
    saveOutput(file_name, 'w', [str(dpath), str(average_expected_mttsf), str(0.0), str(average_expected_ai), str(average_expected_ae)])
    return net, decoy_net, decoy_list, info

#-----------------------------------------------------------------------------
# Fixed interval
#-----------------------------------------------------------------------------



def fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, file_name, times):
    total_dp = 0
    total_mtssf = 0
    total_dc = 0
    total_ai = 0
    total_ae = 0
    i = 0
    attack_exploitability = 0  #sum the attack exploitability
    attack_impact = 0      #sum the attack impact
    print("Attacker intelligence: " + str(initial_info["attackerIntelligence"]["emulated"]) +" "+ str(initial_info["attackerIntelligence"]["real"]))
    
    
    while i < times:
#         print("Shuffle time:",  i+1)
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        defense_cost = cost/interval
#         print("Shuffled net:")
#         printNetWithVul(shuffled_net)
        
        dpath, average_expected_mttsf, average_expected_ai, average_expected_ae = cacluateMetrics(initial_net, shuffled_net, initial_info)

        total_dp += dpath
        total_mtssf += average_expected_mttsf
        total_dc += defense_cost
        total_ai += average_expected_ai
        total_ae +=average_expected_ae
        
        if i == 0:
            saveOutput(file_name, 'w', [str(interval*(i+1)), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
        else:
            saveOutput(file_name, 'a+', [str(interval*(i+1)), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
        
        decoy_net = copyNet(shuffled_net)
        i += 1
    
    print([str(total_dp/times), str(total_mtssf/times), str(total_dc/times), str(total_ai/times), str(total_ae/times)])
    return None
#-----------------------------------------------------------------------------
# Adaptive interval
#-----------------------------------------------------------------------------

def adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, file_name):
    total_dp = 0
    total_mtssf = 0
    total_dc = 0
    times = 0
    total_ai = 0
    total_ae = 0
    
    attack_exploitability = 0  #sum the attack exploitability
    attack_impact = 0      #sum the attack impact
    
    newnet = copyNet(decoy_net)
    newnet = add_attacker(newnet)
    h = constructHARM(newnet) 
    previous_ssl = 0
    compNodes = []
    totalMTTC = 0.0
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while previous_ssl < initial_info["sslThreshold"]:
        ssl, mttc, compNodes, new_decoy_net = computeSSL(h, initial_net, decoy_net, initial_info["sslThreshold"], initial_info["sslThreshold_checkInterval"], 
                               initial_info["threshold"], initial_info["detectionPro"], 
                               initial_info["weights"][0], initial_info["weights"][1], 
                               previous_ssl, compNodes)
        
        totalMTTC += mttc
        if ssl < initial_info["sslThreshold"]:
            shuffled_net, cost = randomShuffling(new_decoy_net, pro)
            
            defense_cost = cost/mttc
#             print("Shuffled net:")
#             printNetWithVul(shuffled_net)
            
            dpath, average_expected_mttsf, average_expected_ai, average_expected_ae = cacluateMetrics(initial_net, shuffled_net, initial_info)
           
            times += 1
            total_dp += dpath
            total_mtssf += average_expected_mttsf
            total_dc += defense_cost
            total_ai += average_expected_ai
            total_ae +=average_expected_ae
            
            
            if previous_ssl == 0:
                saveOutput(file_name, 'w', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
            else:
                saveOutput(file_name, 'a+', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
                
            decoy_net = copyNet(shuffled_net)
            newnet = copyNet(decoy_net)
            newnet = add_attacker(newnet)
            h = constructHARM(newnet)                           
        
        previous_ssl = ssl
    print("SSL threshold:"+str(initial_info["sslThreshold"]))
    print("Attack intelligence  " + str(initial_info["attackerIntelligence"]["emulated"])+" "+ str(initial_info["attackerIntelligence"]["real"]))

    print([str(total_dp/times), str(total_mtssf/times), str(total_dc/times), str(total_ai/times), str(total_ae/times)])    
    return None

#---------------------------------------------------
#    sensitivity analysis
#    
#    ssl conversion
#
#
#----------------------------------------------------

def adaptiveIntervalRS_sensitive(initial_net, decoy_net, initial_info, pro, file_name, ssl_analysis_sensitive):
    total_dp = 0
    total_mtssf = 0
    total_dc = 0
    times = 0
    total_ai = 0
    total_ae = 0
    
    attack_exploitability = 0  #sum the attack exploitability
    attack_impact = 0      #sum the attack impact
    
    newnet = copyNet(decoy_net)
    newnet = add_attacker(newnet)
    h = constructHARM(newnet) 
    previous_ssl = 0
    compNodes = []
    totalMTTC = 0.0
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    #for ssl_threshold == 0.1
    dpath=0 
    average_expected_mttsf=0
    average_expected_ai=0 
    average_expected_ae = 0
    defense_cost = 0
    mttc = 0
    
    
    while previous_ssl < ssl_analysis_sensitive:
        
        ssl, mttc, compNodes, new_decoy_net = computeSSL(h, initial_net, decoy_net, ssl_analysis_sensitive, initial_info["sslThreshold_checkInterval"], 
                               initial_info["threshold"], initial_info["detectionPro"], 
                               initial_info["weights"][0], initial_info["weights"][1], 
                               previous_ssl, compNodes)
        
        totalMTTC += mttc
        
        if ssl < ssl_analysis_sensitive:
            
            shuffled_net, cost = randomShuffling(new_decoy_net, pro)
            
            defense_cost = cost/mttc
#             print("Shuffled net:")
#             printNetWithVul(shuffled_net)
            
            dpath, average_expected_mttsf, average_expected_ai, average_expected_ae = cacluateMetrics(initial_net, shuffled_net, initial_info)
            times += 1
            total_dp += dpath
            total_mtssf += average_expected_mttsf
            total_dc += defense_cost
            total_ai += average_expected_ai
            total_ae +=average_expected_ae
            
            
            if previous_ssl == 0:
                saveOutput(file_name+str(ssl_analysis_sensitive), 'w', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
            else:
                saveOutput(file_name+str(ssl_analysis_sensitive), 'a+', [str(totalMTTC), str(dpath), str(average_expected_mttsf), str(defense_cost), str(average_expected_ai), str(average_expected_ae)])
                
            decoy_net = copyNet(shuffled_net)
            newnet = copyNet(decoy_net)
            newnet = add_attacker(newnet)
            h = constructHARM(newnet)                           
        
        previous_ssl = ssl
    print("SSL threshold:"+str(ssl_analysis_sensitive))
#     print("Attack intelligence  " + str(initial_info["attackerIntelligence"]["emulated"])+" "+ str(initial_info["attackerIntelligence"]["real"]))
    if(times == 0):
        shuffled_net, cost = randomShuffling(new_decoy_net, pro)
            
        defense_cost = cost/mttc
        dpath, average_expected_mttsf, average_expected_ai, average_expected_ae = cacluateMetrics(initial_net, shuffled_net, initial_info)

        sensitive_record[0].append(dpath)
        sensitive_record[1].append(average_expected_mttsf)
        sensitive_record[2].append(defense_cost)
        sensitive_record[3].append(average_expected_ai)
        sensitive_record[4].append(average_expected_ae)
        
        print([str(dpath),str(average_expected_mttsf),str(defense_cost),str(average_expected_ai),str(average_expected_ae)])
    else:
        sensitive_record[0].append(total_dp/times)
        sensitive_record[1].append(total_mtssf/times)
        sensitive_record[2].append(total_dc/times)
        sensitive_record[3].append(total_ai/times)
        sensitive_record[4].append(total_ae/times)
        
        print([str(total_dp/times), str(total_mtssf/times), str(total_dc/times), str(total_ai/times), str(total_ae/times)])    
        return [(total_dp/times),(total_mtssf/times), (total_dc/times),(total_ai/times), (total_ae/times)]
 
 
 
if __name__ == '__main__':
    
#     num = {"laptop":2, "thermostat":2, "tv":2, "server":1} #decoy nodes
#     initial_net, decoy_net, decoy_list, initial_info = beforeShuffle(num, "init_decoy_net_metrics")
#     
#     interval = 24
#     pro = 0.5   #random shuffling index
#     times_of_interval = 30
    
#    adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, "adaptive_rs0000000")
#    fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, "fix_rs", times_of_interval)
    
    
    sensitive_record = [[],[],[],[],[]]

    for i in range(1,10):
        num = {"laptop":2, "thermostat":2, "tv":2, "server":1} #decoy nodes
        initial_net, decoy_net, decoy_list, initial_info = beforeShuffle(num, "init_decoy_net_metrics")
        
        interval = 24
        pro = 0.5   #random shuffling index
        times_of_interval = 30
        adaptiveIntervalRS_sensitive(initial_net, decoy_net, initial_info, pro, "adaptive_rs0000000", i*0.1)
      
    print(sensitive_record[0])  
    print(sensitive_record[1]) 
    print(sensitive_record[2]) 
    print(sensitive_record[3]) 
    print(sensitive_record[4]) 
      
      



