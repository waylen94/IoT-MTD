"""
This module constructs attack graph.
"""
from Node import *
from Network import *
from Vulnerability import *
from math import *
  
class gnode(node):
    """
    Create attack graph node object.
    """
    def __init__(self, name):
        super(gnode, self).__init__(name)
        #Store the network node
        self.n = None
        #Store the Simulation value used in security analysis val could be attack probability
        self.val = 0
        #vulnerabilities network
        self.vuls = []
        #node have type except start and end node
        self.type = None
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = None
        #Used to check whether the node is included in the attack path or not
        self.inPath = 0
        #Initialize start and end points
#         self.s = None
#         self.e = None
    def __str__(self):
        return self.name
                
class gVulNode(vulNode):
    """
    Create attack graph vulnerability object.
    """
    def __init__(self, name):
        super(gVulNode, self).__init__(name)

class ag(network):
    """
    Create attack graph.
    """   
    #Construct the attack graph
    def __init__(self, network, val, *arg):
        super(ag, self).__init__()        
        self.path = [] 
        self.allpath = []               #Store all possible paths from start to end
        self.isAG = 1                   #1 means it is attack graph
        self.subnets = network.subnets  #All subnets in the network
        self.vuls = network.vuls        #All vuls in the network
                
        #Instantiate nodes in attack graph using network info
        for u in [network.s, network.e] + network.nodes:
            
            if u is not None:   
                
                #For vulnerability       
                if type(u) is vulNode:
                    gn = gVulNode('ag_' + str(u.name))
                    gn.privilege = u.privilege
                    gn.val = u.val
                #For node
                else:
                    gn = gnode('ag_' + str(u.name))
                        
                    #Assign default value to attacker node
                    if u.isStart == True:
                        gn.val = -1
                    else:
                        gn.val = val               
                    if u is not network.s and u is not network.e:
                        gn.id = u.id
                        gn.target = u.target
                        gn.type = u.type
                        gn.pro = u.pro
                        gn.critical = u.critical
                        gn.comp = u.comp
                        gn.prev_comp = u.prev_comp                     
                        #for sub in u.subnet:
                            #gn.subnet.append(sub)                                                                                     
                gn.n = u #attack graph node
                
                #Assign default value to start and end in network
                if u in [network.s, network.e]:
                    gn.val = -1
                if u is network.e:
                    gn.target = True                        
                self.nodes.append(gn)
                #print(gn.name)
                
        #Initialize connections for attack graph node   
        for u in self.nodes:       
            #print(u)
            for v in u.n.con:
                #For upper layer
                if len(arg) is 0:
                    for t in self.nodes:
                        if t.n.name == v.name:
                            #print("connections:", t.name)
                            u.con.append(t)
                #For lower layer
                else:
                    if arg[0] >= v.privilege:
                        for t in self.nodes:
                            if t.n is v:
                                u.con.append(t) 
        
        #Initialize start and end in attack graph   
        for u in self.nodes:
            if u.n is network.s:
                self.s = u  
            if u.n is network.e:
                self.e = u
        
        #Remove start and end from nodes in attack graph      
        if self.s is not None:
            self.nodes.remove(self.s)
            
        if self.e is not None:
            self.nodes.remove(self.e)           
    
    
    #Traverse graph one end target                  
    """
    u : start point ( attacker node) which has connection with multiple nodes
    e : end point ( server node ) 
    """
    def travelAgRecursive(self, u, e, path):
        val = 0 
        for v in u.con:

            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                #v.inpath: node has been calculated or not
                #     AND And and  
                #v.child: nodes has vulnerabilities or not, only node with vulnerabilities can build AT
                #v.name: or nodes is attacker
                #v is e: or node is server (end point)
                #
                self.path.append(v)
                v.inPath = 1
                #print(self.path)
                #Recursively traverse the path until to the end point
                if v is not e:              
                    val += self.travelAgRecursive(v, e, self.path)                            
                else:
                    #this function mainly focus on the all path attribute to calculate the attack path
                    self.allpath.append(path[:])

                self.path.pop() 
                v.inPath = 0

        return val

    #Traverse graph to get attack paths
    def travelAg(self): 
        self.allpath = []
        #Start to traverse from start point
        self.path = [self.s]
        #print(self.s.name)
        val = self.travelAgRecursive(self.s, self.e, self.path) #The value records recursion times  

        return val   
    
    
        #Traverse graph multi targets                
    """
    u : start point ( attacker node) which has connection with multiple nodes
    model: differate the 
    1.fixed conjunction target
    2.fixed disjunction target model 
    3.dynamic target model 
    """
    multi_num = 2 #in conjunction scenario all 2 nodes compromised representing attack success
    multi_cunt_real = 0 #calculate whether attacker achieve attack success
    multi_cunt_decoy = 0
    
    def travelAgRecursive_multitarget_conjunction(self, u, path):
        val = 0  
        for v in u.con:
            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                
                self.path.append(v)
                v.inPath = 1
                str1 = ""
                for node in path:
                    str1 = str1 + node.name + "->" 
                print(str1)
                print("----------------------------------------")
                if v.target != True:             
                    val += self.travelAgRecursive_multitarget_conjunction(v,self.path)                          
                else:
                    if v.type == True:
#                     print(v.name)
                        self.multi_cunt_real +=1
                    else:
                        self.multi_cunt_decoy +=1    
#                     print(self.multi_cunt)       
                    if self.multi_cunt_real < self.multi_num and self.multi_cunt_decoy < self.multi_num:#if there are not enough targets then recurse again
                        val += self.travelAgRecursive_multitarget_conjunction(v,self.path)
                    else:
                        self.allpath.append(path[:])    
                        
                self.path.pop() 
                v.inPath = 0
                
            #rebuild the initialized recoded index
            self.multi_cunt_real = 0
            self.multi_cunt_decoy = 0    
        return val
    
    def travelAgRecursive_multitarget_disjunction(self, u, path):
        val = 0 
        for v in u.con:

            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                #v.inpath: node has been calculated or not
                #     AND And and  
                #v.child: nodes has vulnerabilities or not, only node with vulnerabilities can build AT
                #v.name: or nodes is attacker
                #v is e: or node is server (end point)
                #
                self.path.append(v)
                v.inPath = 1
                #print(self.path)
                #Recursively traverse the path until to the end point
                if v.target != True:              
                    val += self.travelAgRecursive_multitarget_disjunction(v, self.path)                            
                else:
                    #this function mainly focus on the all path attribute to calculate the attack path
                    self.allpath.append(path[:])
                self.path.pop() 
                v.inPath = 0

        return val
    total_real_val = 0 # real node  accumulated metrics value
    total_decoy_val = 0
    def travelAgRecursive_multitarget_dynamic(self, u, path):
        val = 0  
        
        for v in u.con:

            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                #v.inpath: node has been calculated or not
                #     AND And and  
                #v.child: nodes has vulnerabilities or not, only node with vulnerabilities can build AT
                #v.name: or nodes is attacker
                #v is e: or node is server (end point)
                #
                self.path.append(v)
                v.inPath = 1
                #print(self.path)
                if v.target != True:               
                    val += self.travelAgRecursive_multitarget_dynamic(v, self.path)                          
                else:
                    if v.type == True:
                        self.total_real_val += v.val
                    else:
                        self.total_decoy_val += v.val
                    if self.total_real_val > 1.7 or self.total_decoy_val > 1.7: #for this moment only for testing multi target mode, the total_val > 0.04 is meaningless, it should be added more accurate attribute ex.critical_level replace.
                        self.allpath.append(path[:])
                    else:
                        val += self.travelAgRecursive_multitarget_dynamic(v, self.path) 
                self.path.pop() 
                v.inPath = 0
                self.total_real_val = 0
                self.total_decoy_val = 0
        return val
    
        #Traverse graph to get attack paths(working for multi target scenarios)
    def travelAg_multitarget(self, model): 
        self.allpath = []
        #Start to traverse from start point
        self.path = [self.s]
        #print(self.s.name)
        if model =='conjunction':
            val = self.travelAgRecursive_multitarget_conjunction(self.s, self.path)
        elif model == 'disjunction':
            val = self.travelAgRecursive_multitarget_disjunction(self.s, self.path)
        else:
            val = self.travelAgRecursive_multitarget_dynamic(self.s, self.path)
            
            
            
        #The value records recursion times  

        return val 
    
    
    #Print graph
    def printAG(self):
        i = 0
        
        for node in self.nodes:
            print(i ,': ', node.name, ', ', len(node.con), ": ",)
            for cons in node.con:
                #the target connects to end point, do not print end point
                if cons != self.e:
                    print(cons.name,)
            print
            i += 1       
        return None
    
    #Print attack paths
    def printPath(self):

        for path in self.allpath:
            print("--------------------------------------------------")
            #print(path)
            for node in path:
                print(node.name)
            print("--------------------------------------------------")
        return None
    
    
    #Calculate attack paths
    def calcPath(self):
        return self.travelAg()
    
    
    
    #---------------------------------------------------------------------------------------------
    #In case that the node is in the upper layer and has child (not none), assign child value to node value 
    def getMTTCValue(self):
        for u in self.nodes:
            if u.child is not None: 
                #get the lower level info which corresponded with vunerability logic gate
                u.val = u.child.calcMTTC()
                #print(u.name, u.val)

    def calcMTTC(self):
        self.getMTTCValue()
        
    def tree_AGAT_print(self):
        for u in self.nodes:
            if u.child is not None: 
                u.child.treePrint()


