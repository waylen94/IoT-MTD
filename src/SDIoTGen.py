'''
Created on 2018.10.13

@author: Mengmeng Ge
'''

from Node import *
from Network import *
from Vulnerability import *
from harm import *
from random import Random
from time import time
from Metrics import *
from itertools import accumulate

#=================================================================================================
# Create real network 
#=================================================================================================

def add_conn(net):
    nodes_vlans = []
    for vlan in net.subnets:
        temp = []
        for node in net.nodes:
            if node.subnet == vlan:
                temp.append(node)
        nodes_vlans.append(temp)
    #print(nodes_vlans)
    
    #Add connections from other VLANs to VLAN4
    for node in nodes_vlans[3]:
        temp = nodes_vlans[0] + nodes_vlans[1] + nodes_vlans[2]
        for conNode in temp: 
            connectOneWay(conNode, node)
    
    #Add connections from VLAN2 to VLAN3
    for node in nodes_vlans[1]:
        for conNode in nodes_vlans[2]:
            connectOneWay(node, conNode)
            
    return None


def add_vul(net):
    """
    Add vulnerabilities for real devices.
    """
    for node in net.nodes:
        if 'mri' in node.name or 'ct' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8308
            #Exploitability score: 6.8
            node.score = 6.8
            createVulsWithoutType(node, 0.006, 1, "CVE-2018-8308") 
        elif 'thermostat' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2013-4860
            node.score = 6
            createVulsWithoutType(node, 0.006, 1, "CVE-2013-4860")
        elif 'meter' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2017-9944
            #Exploitability score: 10.0
            node.score = 10
            createVulsWithoutType(node, 0.042, 1, "CVE-2017-9944")     
        elif 'camera' in node.name:
            node.score = 10
            #https://nvd.nist.gov/vuln/detail/CVE-2018-10660
            createVulsWithoutType(node, 0.042, 1, "CVE-2018-10660")     
        elif 'tv' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-4094
            #Exploitability score: 8.6
            createVulsWithoutType(node, 0.012, 1, "CVE-2018-4094")
        elif 'laptop' in node.name:
            node.score = 4.9
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8345
            #Exploitability score: 4.9
            createVulsWithoutType(node, 0.004, 1, "CVE-2018-8345")     
        elif 'server' in node.name:
            node.score = 7
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8273
            createVulsWithoutType(node, 0.006, 1, "CVE-2018-8273")                  

    return None


def createRealSDIoT(node_vlan_list):
    """
    An example SD-IoT network.
    :param a list of node names separated by VLAN
    """    
    # instantiation of network 
    net = network()
    
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            iot = realNode(j)
            iot.id = id
            iot.subnet = vlan
            if iot.subnet == 'vlan4':
                iot.critical = True
                iot.target = True
            net.nodes.append(iot)
            if id == 3 or id == 7 or id == 8: #when id == 8 which is the traditonal server 
                iot.target = True
            id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    #printNetWithVul(net)
    
    return net
"""
return number of decoy nodes
"""
def add_solution_set(solution_set):
    return solution_set['laptop'], solution_set['thermostat'], solution_set['tv'], solution_set['server']
"""
return number of real nodes
"""
def getIoTNum(net):
    num = 0
    for node in net.nodes:
        if 'server' not in node.name:
            num += 1
    return num

#=================================================================================================
# Add attacker and create HARM
#=================================================================================================

def add_attacker(net):
    #Add attacker
    A = device('attacker')
    A.id = 500
    A.setStart()
    for temp in net.nodes:
        #Set the real and decoy servers as targets
        if "server" in temp.name:
            temp.setEnd()
        else:
            A.con.append(temp)
    
    net.nodes.append(A)
    constructSE(net)

    return net

def constructHARM(net):
    #Create security model
    h = harm()
    #printNet(net)
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    #h.model.printAG()
    #h.model.printPath()
    #print("number of attack paths:", len(h.model.allpath))
    
    return h

#=================================================================================================
# Add initial deployment of decoys into network
#=================================================================================================

def add_decoy_vul(node):
    """
    Add vulnerabilities for decoy devices.
    """

    if 'ct' in node.name:
        createVulsWithoutType(node, 0.006, 1, "CVE-2018-8308")
        #https://nvd.nist.gov/vuln/detail/CVE-2018-8136
        #Score: 8.6
        createVulsWithoutType(node, 0.012, 1, "CVE-2018-8136")
        node.score = 8.6
        thresholdPri(node, 1)
        terminalPri(node, 1)
    elif 'camera' in node.name:
        #https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        #Score: 10.0
        createVulsWithoutType(node, 0.042, 1, "CVE-2018-6294")  
        createVulsWithoutType(node, 0.042, 1, "CVE-2018-6295") 
        createVulsWithoutType(node, 0.042, 1, "CVE-2018-6297")
        node.score = 10 
        thresholdPri(node, 1)
        terminalPri(node, 1)
    elif 'tv' in node.name:
        createVulsWithoutType(node, 0.012, 1, "CVE-2018-4094")   
        createVulsWithoutType(node, 0.012, 1, "CVE-2018-4095")
        node.score = 8.0  
        thresholdPri(node, 1)
        terminalPri(node, 1)   
    elif 'server' in node.name:
        #https://nvd.nist.gov/vuln/detail/CVE-2016-1930
        #Score: 10.0
        node.score = 10
        createVulsWithoutType(node, 0.042, 1, "CVE-2016-1930")    
        createVulsWithoutType(node, 0.012, 1, "CVE-2016-1935") 
        createVulsWithoutType(node, 0.042, 1, "CVE-2016-1962")
        thresholdPri(node, 1)
        terminalPri(node, 1)
    elif 'laptop' in node.name:
        
        #https://nvd.nist.gov/vuln/detail/CVE-2008-3175
        #Score： 10.0
        node.score = 10
        createVulsWithoutType(node, 0.042, 1, "CVE-2008-3175")
        createVulsWithoutType(node, 0.042, 1, "CVE-2007-5003")
        #https://nvd.nist.gov/vuln/detail/CVE-2018-8345
            #Exploitability score: 4.9
        createVulsWithoutType(node, 0.004, 1, "CVE-2018-8345")
        thresholdPri(node, 1)
        terminalPri(node, 1)
    elif 'thermostat' in node.name:
        node.score = 5
        #https://nvd.nist.gov/vuln/detail/CVE-2013-4860
        createVulsWithoutType(node, 0.006, 1, "CVE-2013-4860")
        
        createVulsWithoutType(node, 0.004, 1, "CVE-2018-11315")
        createVulsWithoutType(node, 0.004, 1, "CVE-2018-3201")

        thresholdPri(node, 1)
        terminalPri(node, 1)
        
        
    return None
"""
return the decoy node and existed decoy network subnets
"""
def check_decoy_type(dimension, decoy_num, decoy_list):
    temp = list(accumulate(decoy_num))
    #print(temp, dimension)
    for i in range(0, len(temp)):
        if i == 0:
            if dimension <= temp[i]:
                return decoy_list[i], i+1
        else:
            if dimension > temp[i-1] and dimension <= temp[i]:
                return decoy_list[i], i+1
            
"""
dealing with decoy node type
"""
def add_decoy_type(node, info):
    if "server" in node.name:
        node.type = info["server_decoy_type"]
    else:
        node.type = "emulated"
    return None
"""
setting the decoy node probability for attack
"""
def add_decoy_pro(node, info):
    node.pro = info[node.type]

def add_decoy_conn(net):
    temp = []
    for node in net.nodes:
        if "decoy_server" in node.name:
            temp.append(node)
            
    for node in net.nodes:
        if "decoy" in node.name and "server" not in node.name:
            for conNode in temp:
                connectOneWay(node, conNode)
            
    return None

def add_decoy_deployment(net, info):
    
    decoy_net = copyNet(net)
    decoy_num = info["decoy_num"]
    decoy_list = info["decoy_list"]
    temp = []
    id = 100 #for network visualization because the edge connection depend on the id
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):
        name, vlan = check_decoy_type(i+1, decoy_num, decoy_list)
        #print(name, vlan)
        dnode = decoyNode(name+str(i+1)) 
        dnode.subnet = vlan #number of vlan
        if id ==100 or id ==102 or id == 106: #setting for multi target decoy 
            dnode.target = True
        dnode.id= id
        add_decoy_type(dnode, info)
        add_decoy_vul(dnode)
        add_decoy_pro(dnode, info["attackerIntelligence"])
        decoy_net.nodes.append(dnode)
        #A name list of decoys deployed
        #Used in changing connections as binary encodings need to correspond to the decoys
        temp.append(dnode.name)
        id += 1 
    
    #Add connections from decoys to decoys
    add_decoy_conn(decoy_net)
    #print("Initial deployment:")
    #printNetWithVul(decoy_net)
    
    return decoy_net, temp