"""
This module conducts security analysis and generates SHARPE code from HARM as text file.
"""

from attackGraph import *
from attackTree import *
from harm import *
from SDIoTGen import *

#---------------------------------------------------------------------------------------------------
#Compute compromise rate for lower layer (AT); MTTC (path level) and MTTSF for upper layer (AG)
#We only consider two cases: 
#1) one vulnerability for each node 
#2) multiple vulnerabilities for one node:
#   only ADN or OR, which means the attacker need to use all vulnerabilities or any one of them
#----------------------------------------------------------------------------------------------------

def computeNodeMTTC(node):
    count = 0
    MTTC = 0
    flag = False
    if node.type == True:
        node.comp = True
        count += 1   #the compromised real node count
        if node.critical == True:
            flag = True         
        MTTC = 1.0/node.val
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        if pro > 1.0:
            pro = 1.0 
        MTTC = (1.0/node.val) * pro
    #print(node.name, node.type, node.val, MTTC, flag)
    return MTTC, count, flag

def computeMTTSF(harm, net, cflag):
    """
    harm is built harm with decoy network
    net is initial network
    cflag is metrics for whether security failure
    Compute MTTSF based on the attacker's intelligence.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    
    #Attacker randomly picks one entry point at a time
    #harm.model.printPath()
    #harm.model.nodes[0].child.treePrint()
    #print("number of attack paths:", len(harm.model.allpath))
    MTTSF = 0
    break_flag = False  
    totalCount = 0
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)
    for path in harm.model.allpath:
        for node in path:
            print(node.name)
        print("-----------------------------------------------")
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    #just defualt one target
                    MTTC, count, flag = computeNodeMTTC(node) 
                    MTTSF += MTTC
                    totalCount += count
                    #print(float(totalCount/totalNo))
                    if float(totalCount/totalNo) >= cflag or flag == True:
#                         print(node.val)
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
    return MTTSF 

def computeNodeMTTC_multitarget(node):
    count = 0
    MTTC = 0
    if node.type == True:
        node.comp = True
        count += 1   #the compromised real node count
               
        MTTC = 1.0/node.val
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        if pro > 1.0:
            pro = 1.0 
        MTTC = (1.0/node.val) * pro
    #print(node.name, node.type, node.val, MTTC, flag)
    return MTTC

def computerMTTSF_multitarget(h, net, c_flag, model):
    """
    harm is built harm with decoy network
    net is initial network
    cflag is metrics for whether security failure
    Compute MTTSF based on the attacker's intelligence.
    """
    if model =='conjunction':
        MTTSF = compute_multitargetfix2_MTTSF(h)
    elif model == 'disjunction':
        MTTSF = compute_multitargetfix1_MTTSF(h)
    else:
        MTTSF = compute_multitargetdynamic_MTTSF(h)
    
    return MTTSF
    
    

def compute_multitargetfix1_MTTSF(harm):
    """
    harm is built harm with decoy network
    """
    MTTSF = 0
    break_flag = False
    #rebuild multi target attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)

    for path in harm.model.allpath:
        str1 = ""
        for node in path:
            str1 = str1 + "->" +node.name
        print(str1)
        print("-----------------------------------------------")
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC= computeNodeMTTC_multitarget(node)                 
#                     multi-target area (fixed 4 target or )   
                    MTTSF += MTTC
                    
                    if node.target == True and node.type == True:
                        break_flag = True
                        break
                    
            #Exit outer loop
        if break_flag == True:
            break
    
    return MTTSF 

def compute_multitargetfix2_MTTSF(harm):
    """
    harm is built harm with decoy network
    """
    MTTSF = 0
    break_flag = False
    flag_score = 0
    #rebuild multi target attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)

    for path in harm.model.allpath:
        str1 = ""
        for node in path:
            str1 = str1 + "->" +node.name
        print(str1)
        print("-----------------------------------------------")
        for node in path:      
            if node is not harm.model.s:
                if node.val > 0 and node.comp == False:
                    MTTC= computeNodeMTTC_multitarget(node)            
                    MTTSF += MTTC

                    if node.target == True and node.type == True:
                        flag_score += 1   
                    if flag_score >= 2:
#                         print("conjunction attack success MTTSF:" + str(MTTSF) )
                        break_flag = True
                        break
            #Exit outer loop
        if break_flag == True:
            break
    
    return MTTSF 

def compute_multitargetdynamic_MTTSF(harm):
    """
    harm is built harm with decoy network
    """
    MTTSF = 0
    break_flag = False
    total_val = 0    
    totalCount = 0
    
    model = "dynamics"
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)
    for path in harm.model.allpath:
        str1 = ""
        for node in path:
            str1 = str1 + "->" +node.name
        print(str1)
        print("-----------------------------------------------")
        for node in path:     
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC= computeNodeMTTC_multitarget(node)
                    #multi target area (accumulation)    
                    MTTSF += MTTC
                    if node.type == True: #only evaluating the compromising degree of real nodel
                        total_val += node.score
                    #print(float(totalCount/totalNo))
                    if total_val >= 15:
                        break_flag = True
                        break
            #Exit outer loop
        if break_flag == True:
            break
    return MTTSF 

def computeSSL(harm, net, decoy_net, thre, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    Compute system security level.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))   
    totalCount = 0
    totalTime = 0
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    compNodes.append(node)
                    assignCompNodeInNet(decoy_net, node)
                    totalTime += MTTC
                    totalCount += 1
                    compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                    SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                    #Exit inner loop
                    if float(totalCount/totalNo) >= cflag or flag == True:
                        SSL = 1.0
                        break_flag = True
                        break
                    elif SSL >= thre:
                        break_flag = True
                        break
                    elif (SSL - previous_ssl) > thre_check and SSL < thre:
                        break_flag = True
                        break
        #Exit outer loop
        if break_flag == True:
            break      
    return SSL, totalTime, compNodes, decoy_net

def computeSSL_multi_conjunction(harm, net, decoy_net, thre, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    h, 
    initial_net, 
    decoy_net, 
    initial_info["sslThreshold"],  0.5
    initial_info["sslThreshold_checkInterval"],  0.01
    initial_info["threshold"],  1/3
    initial_info["detectionPro"],  0.95
    initial_info["weights"][0], 0.5
    initial_info["weights"][1], 0.5
    previous_ssl, 
    compNodes
    
    conjunction ssl: the number of compromised target nodes
    
    Compute system security level.
    """
    
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))   
    totalTime = 0
    SSL = 0
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False and node.target == True and node.type == True:
                    
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    compNodes.append(node)
                    print(len(compNodes))
                    assignCompNodeInNet(decoy_net, node)
                    totalTime += MTTC
                    SSL = len(compNodes)/3
                    #Exit inner loop
                    if SSL >= 1/3:
                        break_flag = True
                        
                        break
#                     elif (SSL - previous_ssl) > thre_check and SSL < thre:
#                         break_flag = True
#                         break
        #Exit outer loop
        if break_flag == True:
            break      
    return SSL, totalTime, compNodes, decoy_net

def computeSSL_multi_disjunction(harm, net, decoy_net, thre, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    Compute system security level.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))   
    totalCount = 0
    totalTime = 0
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False and node.type == True:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    compNodes.append(node)
                    assignCompNodeInNet(decoy_net, node)
                    totalTime += MTTC
                    totalCount += 1
                    compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                    SSL = compNeighborNo/neighborNo
                    #Exit inner loop
                    if SSL >= 1/3:
                        break_flag = True
                        break
#                     elif (SSL - previous_ssl) > thre_check and SSL < thre:
#                         break_flag = True
#                         break
        #Exit outer loop
        if break_flag == True:
            break      
    return SSL, totalTime, compNodes, decoy_net

def computeSSL_multi_dynamic(harm, net, decoy_net, thre, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    Compute system security level.
    """
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))   
    totalCount = 0
    totalTime = 0
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False and node.type == True:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    compNodes.append(node)
                    assignCompNodeInNet(decoy_net, node)
                    totalTime += MTTC
                    totalCount += node.val
                    SSL = totalCount
                    #Exit inner loop
                    if SSL >= 0.01:
                        break_flag = True
                        break
#                     elif (SSL - previous_ssl) > thre_check and SSL < thre:
#                         break_flag = True
#                         break
        #Exit outer loop
        if break_flag == True:
            break      
    return SSL, totalTime, compNodes, decoy_net
    
#---------------------------------------------------------------------------------------------------
#Compute compromise rate for lower layer (AT); MTTC for upper layer (AG); SSL
#We only consider two cases: 
#1) one vulnerability for each node 
#2) multiple vulnerabilities for one node:
#   only ADN or OR, which means the attacker need to use all vulnerabilities or any one of them
#----------------------------------------------------------------------------------------------------

def computeCompNodes(node, detect_pro):
    flag = False #SF2
    
    #print("Compromised node: ", node.name, node.type, node.val)
    if node.type == True:
        node.comp = True
        MTTC = (1.0/node.val) * node.pro - node.prev_comp
    else:
        #node.comp = True
        MTTC = (1.0/node.val) * node.pro * detect_pro
    #print("MTTC: ", MTTC)  
    return MTTC, flag 

def assignCompNodeInNet(decoy_net, attack_node):
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
            #print("Assign compromised node in original net: ", node.name, attack_node.name)
            node.comp = True
    return None
