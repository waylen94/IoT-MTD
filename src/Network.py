"""
This module contains network object and relevant functions.
"""

from Node import *
import copy

class network(object):
    """
    Create network object.
    """
    def __init__(self):
        #Initialize node list
        self.nodes = []
        #Initialize start and end points
        self.s = None
        self.e = None
        #Initialize subnets which contain each node's subnet
        self.subnets = []
        #Initialize vulnerability list which contains all node vulnerabilities
        self.vuls = []


def copyNet(net):
    """
    Copy the network to a network.
    """
    temp = copy.deepcopy(net)
    return temp

def constructSE(net):
    """
    Set the start and end in the network.
    """

    net.s = node('S-')
    net.e = node('E-')
        
    for n in net.nodes:
        if n.isStart:
            net.s.con.append(n)
        if n.isEnd:
            n.con.append(net.e)

          
def connectOneWay(node1, node2):
    """
    Connect node1 to node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #connect node1 to node2
    if (node2 not in node1.con):
        node1.con.append(node2)    
   
def connectTwoWays(node1, node2):
    """
    Connect node1 with node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #create connections
    if (node2 not in node1.con):
        node1.con.append(node2)
    if (node1 not in node2.con):
        node2.con.append(node1)

def printNet(net):
    """
    Print network.
    """   
    for node in net.nodes:
        print(node.name+":", node.type)
        print("connect:",)
        for conNode in node.con:
            print(conNode.name)
        print("-----------------------------")
    return None


def printNetWithVul(net):
    """
    Print network with vulnerabilities.
    """   
    for node in net.nodes:
        #print(node.name+":", node.type, ",", node.sec)
        print(node.name+":", node.type, node.comp, node.critical)
        print("connect:",)
        for conNode in node.con:
            if conNode.name == 'S-' or conNode.name == 'E-':
                print(conNode.name)
            else:
                print(conNode.name, conNode.type)      
                
        print("vulnerability:",)
        if node.vul is not None:
            for vul in node.vul.nodes:
                #print(vul.name+":", vul.type, ",", vul.val)
                print(vul.name+":", vul.val)
        print("------------------------------")

    return None
def disconnectOneWay(node1, node2):
    """
    Disconnect node1 with node2 in the network
    """
    names = [i.name for i in node1.con]
    if node2.name in names:
        #print(node2.name, names)
        removeNodeFromList(node2, node1.con)
    return None
def removeNodeFromList(node, con_list):
    """
    Remove node from the original connection list
    """
    for i in con_list:
        if i.name == node.name:
            con_list.remove(i)
            break
    return None

def computeNeighbors(net):
    """
    Compute 1-hop neighbors.
    """
    neighbor_list = []
    for node in net.nodes:
        for conNode in node.con:
            if conNode.target == True and conNode not in neighbor_list:
                neighbor_list.append(node)
    return neighbor_list



def checkNeighbors(compNodes, neighbor_list):
    compNo = 0
    for node in compNodes:
        for neighbor in neighbor_list:
            if node.name == "ag_"+neighbor.name:
                compNo += 1
    #print("Number of compromised neighbors: ", compNo)
    return compNo

def assignCompNodeInNet(decoy_net, attack_node):
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
#             print("Assign compromised node in original net: ", node.name, attack_node.name)
            node.comp = True
    return None