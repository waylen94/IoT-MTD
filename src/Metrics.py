"""
-------------------------------------------------------------------------
Part: This part contains functions for calculating path-based metrics
-------------------------------------------------------------------------
"""  
#===================================================================================
#Compute the number of real attack paths and decoy attack paths
#===================================================================================

def decoyPath(h):
    """
    @return: number of decoy attack paths
    @return: number of real attack paths
    """
    dsum = 0
    rsum = 0
    for path in h.model.allpath:
        if 'decoy_server' in path[len(path)-2].name:
            dsum += 1
        elif 'server' in path[len(path)-2].name:
            rsum += 1
    #print(dsum, float(dsum)/float(dsum+rsum))
    return dsum, rsum

#===================================================================================
#deception proportion
#===================================================================================
def decoyproportion(h):
    proportion = 0 
    dsum = 0
    rsum = 0
    for path in h.model.allpath:
        if 'decoy_server' in path[len(path)-2].name:
            dsum += 1
        elif 'server' in path[len(path)-2].name:
            rsum += 1
    #print(dsum, float(dsum)/float(dsum+rsum))
    
    proportion = float(dsum)/dsum+rsum
    return proportion
#===================================================================================
#attack exploitability
#===================================================================================
def attack_exploitability(h):
    attack_exploitability_sum = 0 
    
    return attack_exploitability_sum
#===================================================================================
#attack impact
#===================================================================================
def attack_impact(h):
    attack_impact_sum = 0 
    
    return attack_impact_sum