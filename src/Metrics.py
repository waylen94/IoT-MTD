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


#====================================================================================
#Normalize metric values
#====================================================================================
def nomalizeMetrics(metric_list, normalized_range):
    normalized_value_list = []
    min_value = normalized_range[0]
    max_value = normalized_range[1]
    for i in metric_list:
        temp = float(i - min_value)/float(max_value - min_value)
        normalized_value_list.append(temp)
    return normalized_value_list


#====================================================================================
#Compute the cost of solutions
#====================================================================================
def solutionCost(candidate_solution, info):
    """
    Calculate the total cost of deployed solutions: connections
    """
    total_cost = info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"])
    solution_cost = 0.0
    for i in range(0, total_cost):
        if candidate_solution[i] != info["previous_solution"][i]: 
            solution_cost += 1.0
    
    return float(total_cost - solution_cost)