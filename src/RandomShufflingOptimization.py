'''
Created on 2018.10.15

@author: Mengmeng Ge
'''


import copy
import math
from SDIoTGen import *
from SecurityEvaluator import *
from random import uniform

def checkConnection(iot, decoy):
    for node in iot.con:
        if node.name == decoy.name:
            return 1
    return 0

def randomShuffling(decoy_net, threshold_pro):
    """
    The comparison between the randomly generated probability and threshold:
    As long as it is larger, add if no connection or remove if connection exists.
    """
    shuffled_net = copyNet(decoy_net)
    cost = 0
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
            for node2 in shuffled_net.nodes:
                if node2.type == "emulated" or node2.type == "real":
                    random_pro = uniform(0, 1)
                    #Add or remove connection 
                    if random_pro > threshold_pro:
                        #print("Add or remove connection based probability: ", random_pro, node1.name, node2.name)
                        if checkConnection(node1, node2) == 0:
                            connectOneWay(node1, node2)
                        else:
                            disconnectOneWay(node1, node2)
                        cost += 1
            
    return shuffled_net, cost