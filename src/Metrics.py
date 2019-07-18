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
        if 'decoy' in path[len(path)-1].name:
            dsum += 1
        elif 'server' in path[len(path)-2].name:
            rsum += 1
    #print(dsum, float(dsum)/float(dsum+rsum))
    return dsum


