"""
This module conducts security analysis and generates SHARPE code from HARM as text file.
"""

from attackGraph import *
from attackTree import *
from harm import *
from SDIoTGen import *
from Metrics import attack_impact, attack_exploitability

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
    multi_count = 0
    
    if node.type == True:
        node.comp = True
        count += 1
#         print(node.impact)
        if node.target == True:
#             print(node.name)
            if node.id == 8:
                flag = True 
                
            multi_count += 1
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
    return MTTC, count, flag, multi_count

def computeCompNodes(node, detect_pro):
    flag = False #SF2
    
#     print("Compromised node: ", node.name, node.type, node.val)
    if node.type == True:
        node.comp = True
        if node.critical == True:
            flag = True
        MTTC = (1.0/node.val) * node.pro - node.prev_comp
    else:
        #node.comp = True
        MTTC = (1.0/node.val) * node.pro * detect_pro
#     print("MTTC: ", MTTC)  
    return MTTC, flag 

def computeMTTSF(harm, net, cflag):
    """
    Compute MTTSF based on the attacker's intelligence.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath) #Attacker randomly picks one entry point at a time
    #harm.model.printPath()
    #harm.model.nodes[0].child.treePrint()
    #print("number of attack paths:", len(harm.model.allpath))
    MTTSF = 0
    break_flag = False
    multi_target_total = 0
    totalCount = 0
    testingcount = 0
    attack_impact = 0
    attack_exploitability = 0


    for path in harm.model.allpath:
        for node in path:
#             for conNode in node.con:
#                 print(conNode.name)
#             print("-----------------------------")
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
#                     print(node.name + "is compromising")
                    MTTC, count, flag , multi_target= computeNodeMTTC(node) 
                    MTTSF += MTTC
#                     print(node.impact)
                    attack_impact += node.impact
                    attack_exploitability += node.exploitability             
                    totalCount += count
                    multi_target_total +=multi_target
                    #print(float(totalCount/totalNo))        or (multi_target_total >=2 and flag == True)
                    if float(totalCount/totalNo) >= cflag or (multi_target_total >=2 and flag == True):
#                         print("11111111111111111   "+node.name)
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            testingcount +=1
            break
#     print("MTTSF from security evaluator mttsf calculation:    "+str(MTTSF))
    return MTTSF, attack_exploitability, attack_impact, break_flag, testingcount 

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
    
    multi_target_total = 0    
    totalCount = 0
    totalTime = 0
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
#     print("Neighbor list: ", [i.name for i in neighbor_list])
    break_flag = False
    compNodes = []
    SSL = 0
    compNeighborNo = 0
    
    
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, count, flag , multi_target= computeNodeMTTC(node)
                    if count == 1: 
                        compNodes.append(node)
                        
                    assignCompNodeInNet(decoy_net, node)
                    
                    totalTime += MTTC
                    totalCount += count
                    multi_target_total +=multi_target # sum the multi target compromised number
#                     print("SF1: ", float(totalCount/totalNo))
#                     print("SF2: ", flag)
                    
                    compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                    #len(compNodes) is similar to totalCount
                    SSL = (w1 * (len(compNodes)/totalNo)) + (w2 * (compNeighborNo/neighborNo))
                    
                    #Exit inner loop
                    if float(totalCount/totalNo) >= cflag or  (multi_target_total >=2 and flag == True):
                        SSL = 1.0
                        break_flag = True
                        break
                    elif SSL >= thre:
                        break_flag = True
                        break
                    elif (SSL - previous_ssl) > thre_check and SSL < thre:
                        break_flag = True
                        break
        print("w1 parameter: ", (len(compNodes)/totalNo),"w2 parameter: ", (compNeighborNo/neighborNo), "Break point SSL: ", SSL)
                  
        #Exit outer loop
        
        if break_flag == True:
            break
#     print("MTTC: ", totalTime)          
    return SSL, totalTime, compNodes, decoy_net


