'''
This module provides the multi-objective problem for optimal security defences.
@author: meng
'''

import warnings
import copy
from inspyred import ec
from inspyred.ec import emo
from inspyred.ec import selectors
import itertools
import math
from SDIoTGen import *
from SecurityEvaluator import *

class problem(object):
    def __init__(self, dimensions, objectives=1):
        """
        dimensions: the number of inputs to the problem
        objectives: the number of outputs of the problem (default 1)
        bounder: the bounding function for the problem (default None)
        maximize: whether the problem is one of maximization (default True)
        """
        self.dimensions = dimensions
        self.objectives = objectives
        self.bounder = None
        self.maximize = True
        self.dimensions_bits_list = None
        self.dimension_bits = 0
        self.net = None
        self.decoy_net = None #Store net with initial decoy deployment and then shuffled net afterwards
        self.info = None
        self.real_bounder = None
        self.decoy_list = None
        self.sim_num = None
        
    def generator(self, random, args):
        """The generator function for the problem."""
        raise NotImplementedError
        
    def evaluator(self, candidates, args):
        """The evaluator function for the problem."""
        raise NotImplementedError
        
    def __call__(self, *args, **kwargs):
        # allows that function to accept an arbitrary number of arguments and keyword arguments
        candidate = [a for a in args]
        fit = self.evaluator([candidate], kwargs)
        return fit[0]


class problemBinaryDeploymentShuffle(problem):
    def __init___(self, dimensions=4):
        problem.__init__(self, dimensions, 2)
        self.bounder = ec.DiscreteBounder([0, 1])
        self.maximze = True

    def assign_dimensions_bits_list(self, dimensions_bits_list):
        """
        A list of length of dimension bits.
        Each input/dimension may have different length of bits.
        """
        self.dimensions_bits_list = dimensions_bits_list
    
    def generate_net(self, node_vlan_list):
        self.net = createRealSDIoT(node_vlan_list)
        
    def calc_bit_length(self):
        """
        Calculate the total number of bits encoded for the solution.
        """
        for i in range(0, len(self.dimensions_bits_list)):
            self.dimension_bits += self.dimensions_bits_list[i]
    
    def add_real_bounder(self, bounder_list):
        """
        Assign the bounder in real numbers for the solution.
        """
        self.real_bounder = bounder_list
    
    def check_bounder_real(self, c_real):
        for i in range(0, len(c_real)):
            if c_real[i] > self.real_bounder[i]:
                return 0
        return 1
    
    def check_server_decoy(self, c_real):
        #Make sure at least one server decoy is deployed 
        temp = []
        for i in range(0, self.info["dserver_dimension"]):
            num = self.info["diot_dimension"] * (self.info["riot_num"] + 1) + i * (self.info["riot_num"] + 1)
            #print(num, c_real[num])
            temp.append(c_real[num])
        if temp == [0] * len(temp):
            return 0
        return 1
    
    def check_conn(self, c_real):
        for i in range(0, self.dimensions):
            num = i * (self.info["riot_num"] + 1)
            if c_real[num] == 0:
                if c_real[num+1:num+self.info["riot_num"]+1] != [0] * self.info["riot_num"]:
                    #print(c_real[num+1:num+self.info["riot_num"]+1])
                    return 0
        return 1
    
    def binary_to_real(self, candidate_binary):
        real_val = int(''.join([str(i) for i in candidate_binary]), 2)
        return real_val
    
    def real_value_list(self, candidate):
        """
        Convert the binary values to real values for the solution.
        Each input/dimension may have different bits.
        """
        candidate_real = []
        p = 0
        for i in range(0, self.dimensions):
            num = i * (self.info["riot_num"] + 1)
            for j in range(0, self.info["riot_num"] + 1):
                c = candidate[p:p+self.dimensions_bits_list[num+j]]
                candidate_real.append(self.binary_to_real(c))
                p += self.dimensions_bits_list[num+j]
                #print(c, p)
        
        #print(candidate_real)
        return candidate_real        
    
    def generator(self, random, args):
        candidate = [random.choice([0, 1]) for _ in range(0, self.dimension_bits)]
        return candidate
        
    def evaluator(self, candidates, args):
        fitness = []
        for c_binary in candidates:
            print("binary solution:", c_binary)
            c_real = self.real_value_list(c_binary)
            #print("real value solution:", c_real)
            if self.check_bounder_real(c_real) == 1 and self.check_server_decoy(c_real) == 1 and self.check_conn(c_real) == 1:
                #Encoded solution is within bounder
                #At least one server decoy is deployed
                #If no decoy deployed, no connection added
                newnet = add_solution(self.net, c_real, self.info)
                add_attacker(newnet)
                h = constructHARM(newnet)
                f1 = decoyPath(h)
                f2 = computeMTTSF(h, self.net, self.info["threshold"])
                f3 = solutionCost(c_real, self.info)
                print(f1, f2, f3)
                fitness.append(emo.Pareto([f1, f2, f3])) # a Pareto multi-objective solution
            else:
                fitness.append(None)

        return fitness
    
class problemBinary(problem):
    def __init___(self, dimensions=4):
        problem.__init__(self, dimensions, 2)
        self.bounder = ec.DiscreteBounder([0, 1])
        self.maximze = True

    def assign_dimensions_bits_list(self, dimensions_bits_list):
        """
        A list of length of dimension bits.
        Each input/dimension may have different length of bits.
        """
        self.dimensions_bits_list = dimensions_bits_list
    
    def generate_net(self, node_vlan_list):
        self.net = createRealSDIoT(node_vlan_list)

    def add_initial_decoy_deployment(self):
        self.decoy_net, self.decoy_list = add_decoy_deployment(self.net, self.info)
        
    def calc_bit_length(self):
        """
        Calculate the total number of bits encoded for the solution.
        """
        for i in range(0, len(self.dimensions_bits_list)):
            self.dimension_bits += self.dimensions_bits_list[i]
    
    def add_real_bounder(self, bounder_list):
        """
        Assign the bounder in real numbers for the solution.
        """
        self.real_bounder = bounder_list
    
    def generator(self, random, args):
        candidate = [random.choice([0, 1]) for _ in range(0, self.dimension_bits)]
        return candidate
        
    def evaluator(self, candidates, args):
        fitness = []
        for c_binary in candidates:
            #print("binary solution:", c_binary)
            #shuffle net work
            net = add_solution(self.decoy_net, c_binary, self.info, self.decoy_list)
            newnet = add_attacker(net)
#             print("Add attacker:")
#             printNet(newnet)
            harm = constructHARM(newnet)

            f1 = decoyPath(harm) 
            f3 = solutionCost(c_binary, self.info)
            f2 = 0.0
            for i in range(0, self.sim_num):
                f2 += computeMTTSF(harm, self.net, self.info["threshold"])
                
            print(f1, f2, f3)
            fitness.append(emo.Pareto([f1, float(f2/self.sim_num), f3])) # a Pareto multi-objective solution

        return fitness