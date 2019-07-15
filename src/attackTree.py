"""
This module constructs attack tree.
"""

from Node import *
from Network import *
from Vulnerability import *


class tNode(node):
    """
    Create attack tree node object.
    """
    def __init__(self, name):
        super(tNode, self).__init__(name)
        self.n = None
        self.t = "node"
        self.val = 0
    
    def __str__(self):
        return self.name

class tVulNode(vulNode):
    """
    Create attack tree vulnerability object.
    """
    def __init__(self, name):
        super(tVulNode, self).__init__(name)
        self.n = None   #store the original node
        self.t = "node" #type using name "andGate" "orGate"
        self.val = 0    #value as attack probability
    def __str__(self):
        return self.name
    
class andGate(node):
    def __init__(self):
        super(andGate, self).__init__("andGate")
        self.t = "andGate"

class orGate(node):
    def __init__(self):
        super(orGate, self).__init__("orGate")
        self.t = "orGate"
        
        
        
#because  the whole project coding is not object oriented programming coding practical
#so it has really confused person who reread the code
#in this part is the most confused. this is the point, node can form the network by itself.
#that means node and network is ambuguous 
#the only way to solve it, it is to reconstruct it
class at(object):
    """
    Create attack tree.
    """
    def __init__(self, network, val, *arg):
        self.topGate = None    #through the togGate go through the attack tree
        self.construct(network, val, *arg) 
        self.isAG = 0
    
    #Preprocess for the construction
    def preprocess(self, network, nodes, val, *arg):  
        for u in [network.s, network.e] + network.nodes:
            if u is not None:
                
                #For vulnerability
                if type(u) is vulNode:
                    tn = tVulNode('at_'+str(u.name))   #inital attack tree vulnerability instance
                    tn.privilege = u.privilege  
                    tn.val = u.val
                    tn.vulname = u.name
                    
                #For node
                else:
                    tn = tNode('at_'+str(u.name))
                    
                    #Assign default value to attacker node
                    if u.isStart == True:
                        tn.val = -1
                    else:
                        tn.val = val
                    
                tn.n = u
                
                #Assign default value to start and end in vulnerability network
                if u in [network.s, network.e]:
                    tn.val = 0
                    
                    
                nodes.append(tn)   
        
        #Initialize connections for attack tree node                         
        for u in nodes:
            for v in u.n.con:
                #For upper layer
                if len(arg) is 0:
                    for t in nodes:
                        if t.n is v:
                            u.con.append(t)
                #For lower layer
                else:
                    # Privilege value is used here to decide what vulnerabilities an attacker can use for attack paths 
                    if v.privilege is not None and arg[0] >= v.privilege:
                        for t in nodes:
                            if t.n is v:
                                u.con.append(t)      #construct the existed connection 
        return None
    
    #Construct the attack tree
    def construct(self, network, val, *arg):        
        nodes = []
        history = []
        self.topGate = orGate() #when construct the attack tree, initiate topGate as orGate
        self.preprocess(network, nodes, val, *arg)#primarily manipulate nodes list, 
                # which the nodes list is for construct attack tree instance and building connection 


        #For one vulnerability
        if len(nodes) < 4:
            a_gate = andGate()
            for node in nodes:
                a_gate.con.append(node)
                
            self.topGate.con.append(a_gate)
            
        #For more than one vulnerability
        else:    
            for u in nodes:
                if u.n is network.e:
                    e = u
                if u.n is network.s:
                    self.topGate.con.append(u)  
            
            
            
            # simplify initiating the and gate and or gate with created network node
            self.simplify(self.topGate, history, e)
            # targetout 
            self.targetOut(self.topGate, e)
            # foldgate
            self.foldgate(self.topGate)
            
            
            

    #Simplify the method initiating the and gate and or gate with created network node
    def simplify(self, gate, history, target):
        """
        """
        tGate = [] 
        tGate.extend(gate.con)#attack tree storing for network node connection for building the attack tree (and or)
        
        value = 1
        if len(tGate) == 0: #recursive function point in context when the gate soted the target the value will be 0
            value = 0
           
        for item in tGate:    #t attribute only cater for attack tree for discriminate normal node, and or node and 
            if (item is not target) and (item.t is "node"):
                a_gate = andGate()                                
                gate.con.append(a_gate)
                gate.con.remove(item)                                                   
                                          
                a_gate.con.append(item)                
                o_gate = orGate()                                  
                a_gate.con.append(o_gate)            
                
                for u in item.con:
                    if u not in history:
                        o_gate.con.append(u)
                       
                history.append(item)
                
                #value is the recursive core attribute
                value = self.simplify(o_gate, history, target)
                
                history.pop()
                
                if len(o_gate.con) < 1: # for the specific server target?
                    a_gate.con.remove(o_gate)
                    if len(a_gate.con) == 1 and value == 0:
                        gate.con.append(item)
                        gate.con.remove(a_gate)
                        
                value = value * item.val  
                
                  
        return value
    
    def targetOut(self, rootGate, target):
        """explanation of the function"""
        self.targetOutRecursive(rootGate, target)
        
        for gate in rootGate.con:
            gate.con.append(target)
            
        self.deleteEmptyGates(rootGate)        
      
    def deleteEmptyGates(self, gate):
        """explanation of the function"""
        removedGates = []
        for node in gate.con:
            if node.t in ['andGate', 'orGate']:
                if (len(node.con) is 1) and (node.con[0] is "removed"):
                    removedGates.append(node)
                else:
                    self.deleteEmptyGates(node)
                                
        for node in removedGates:
            gate.con.remove(node)    
            
    def targetOutRecursive(self, gate, target):
        """explanation of the function"""
        toChange = []
        for node in gate.con:
            if node is target:
                if len(gate.con) is 1:
                    del gate.con[:]
                    gate.con.append("removed")
                    break
                else:                    #confusion, if there is illegal data connection fix in there
                    toChange.append(node)                    
                    
            elif node.t in ['andGate', 'orGate']:
                self.targetOutRecursive(node, target)
                
                
        for node in toChange:
            gate.con.remove(node)
            nothing = tNode('at-.')
            nothing.val = 1            
            gate.con.append(nothing)
            
    #Fold gate with one child (node.con == 1)                
    def foldgate(self, gate):
        """explanation of the function"""
        removedGates = []
        for node in gate.con:
            if node.t in ['andGate', 'orGate']:
                self.foldgate(node)
                
                if len(node.con) == 1:
                    gate.con.extend(node.con)
                    removedGates.append(node)                
        for node in removedGates:
            gate.con.remove(node)
                 
    
    
    
    
    
       
    def tPrintRecursive(self, gate):
        print(gate.name, '->',)
        for u in gate.con:
            print(u.name,)
        for u in gate.con:
            if u.t in ['andGate', 'orGate']:
                self.tPrintRecursive(u)
    
    #Print tree
    def treePrint(self):
        self.tPrintRecursive(self.topGate)

    #----------------------------------------------------------------------------------------------    
    #AT is lower layer

    
    
    #Calculate the mean-time-to-compromise value for each node in the attack tree
    def calcMTTCRecursive(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val += self.calcMTTCRecursive(u) 
                #print ('and:', val)
        elif s.t is "orGate":
            val = 0
            for u in s.con:
                tval = self.calcMTTCRecursive(u)
                if tval >= val:
                    val = tval 
        elif s.t is "node":
            val = s.val
        else:
            val = 0
        return val
    
    #Get the mean-time-to-compromise value of each node in the attack tree
    def calcMTTC(self):
        return self.calcMTTCRecursive(self.topGate)

