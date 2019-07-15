"""
This module constructs HARMs using AG, AT in both upper and lower layers.
"""


from attackGraph import *
from attackTree import *

class harm(object):
    """
    Create harm object.
    """
    def __init__(self):
        self.model = None
#    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    def constructHarm(self, net, up, valueUp, lo, valueLow, pri):
        self.model = makeHARM(net, up, valueUp, lo, valueLow, pri)

    
def addToTreeRecursive(gate, childType, val, pri):
    for u in gate.con:
        if u.t is "node":
            if (u.n is not None) and (u.n.vul is not None):
                childType = childType.lower()
                if childType.find("attacktree") >= 0:
                    u.child = at(u.n.vul, val, pri)
                elif childType.find("attackgraph") >= 0:
                    u.child = ag(u.n.vul, val, pri)
                else:
                    print("Error")
        else:
            addToTreeRecursive(u, childType, val, pri)
            
def addToTree(aT, childType, val, pri):
    addToTreeRecursive(aT.topGate, childType, val, pri)
    
def addToGraph(aG, childType, val, pri):
    for u in aG.nodes:
        if (u.n is not None) and (u.n.vul is not None):
            childType = childType.lower()
            if childType.find("attacktree") >= 0:
                u.child = at(u.n.vul, val, pri)
            elif childType.find("attackgraph") >= 0:
                u.child = ag(u.n.vul, val, pri)
            else:
                print("Error")

def makeHARM(net, up, vu, lo, vl, pri):
    """
    Construct HARM.
        h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    :param net: network
    :param up: upper layer type
    :param vu: assign a default value to val parameter for node, no real meaning when initializing, changed and used in security analysis
    :param lo: lower layer type
    :param vl: assign a default value to val parameter for vulnerability, no real meaning when initializing, changed and used in security analysis
    :param pri: assign a privilege value in construction of lower layer vulnerability connections
    :returns: HARM: contains two layers, when using AGAT, \
                    the upper layer is attack graph listing nodes and attack paths \
                    each node has a lower layer which stored in child parameter, containing vulnerability tree
    """
    up = up.lower()    
    #Construct upper layer  
    if up.find("attacktree") >= 0:
        harm = at(net, vu) #vu: value upper, no real meaning when initializing, changed and used in security analysis?
    elif up.find("attackgraph") >= 0:
        harm = ag(net, vu)
    else:
        harm = None 
        print("HARM construction error")
    #Add lower layer to upper layer
    if harm is not None:
        if type(harm) is ag:   #if the upper layer is Attack graph
            # vl: value lower, no real meaning when initializing, changed and used in security analysis
            addToGraph(harm, lo, vl, pri)#adding attack tree to attack graph
            harm.calcPath() #Compute attack path when building the HARMs which is the default attack path
        else:
            addToTree(harm, lo, vl, pri)         
    return harm