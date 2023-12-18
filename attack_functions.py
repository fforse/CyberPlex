import sys

import logging
import json
import random

# From mal-toolbox
import maltoolbox
import maltoolbox.cl_parser
from maltoolbox.language import classes_factory
from maltoolbox.language import specification
from maltoolbox.model import model
from maltoolbox.attackgraph import attackgraph
from maltoolbox.attackgraph import query
from maltoolbox.attackgraph.analyzers import apriori
from maltoolbox.ingestors import neo4j

# From mgg-project
import cost_from_ttc
import attack_simulation

# Extra packages
from py2neo import Graph
import networkx as nx
import matplotlib.pyplot as plt


""" Add attacker"""
def add_attacker(addAttacker, honorModel, langSpec):
    if addAttacker:
        honorModel.attackers.clear()
        attacker = model.Attacker()
        attacker.name = "Attacker"
        entry_point_asset = honorModel.get_asset_by_id(-5788304309433211)
        list_of_tuples = [(entry_point_asset, ["fullAccess"])] # can add more compromised attack steps to this asset, example "attemptFullAccessFromSupplyChainCompromise"
        attacker.entry_points = list_of_tuples
        honorModel.add_attacker(attacker)

        """ Generate attackgraps from model """
        attkgraph = attackgraph.AttackGraph()
        attkgraph.generate_graph(langSpec, honorModel)
        """ Add another asset the attacker has compromised"""
        #Second_asset = honorModel.get_asset_by_id(-5788304309433211)
        #honorModel.attackers[0].entry_points.append((Second_asset, ["fullAccess"]))
        #third_asset = honorModel.get_asset_by_id(2482232589996571)
        #honorModel.attackers[0].entry_points.append((third_asset, ["attemptDelete"]))
        attkgraph.attach_attackers(honorModel)
        return attkgraph
    
def setting_up_attackSimulation(attkgraph, test_dijkstra, test_random_path):

    """ Setting up an attack simulation"""
    attacker = attkgraph.attackers[0]
    attacker_entry_point = attacker.node.id
    attackSimulation = attack_simulation.AttackSimulation(attkgraph, attacker)
    attackSimulation.start_node = attacker_entry_point
    attackSimulation.set_target_node("Application:-5788304309433211:read") # Example: "Application:-8870229874954749:modify"
    attackSimulation.set_attacker_cost_budget(1000000)

    """ If Dijkstra"""
    if test_dijkstra:
        costOfAttacks = attackSimulation.dijkstra()
        print(costOfAttacks)
        print(attackSimulation.visited)

    """ If random path"""
    if test_random_path:
        costOfAttacks = attackSimulation.random_path()
        print(costOfAttacks)
        print(attackSimulation.visited)
    
    
    return attackSimulation

  ############################ Upload to Neo4j ############################################

def create_neo4j_graph(attackSimulation):
    """ Upload hacking chain to neo4j"""
    neo4j_graph_connection = Graph(uri="neo4j://localhost:7687", user="Fredrik", password="fred4551", name="attackgraphs")
    attackSimulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)


    """ Create neo4j model instance """

    #neo4j.ingest_model(honorModel, "neo4j://localhost:7687", "Fredrik",
    #"fred4551", "ingestmodel", delete=True)


################################## Visualisation of attackgraph with networkX###############################################
class Node:
    """ 
    Define a node to use with networkX
    """
    def __init__(self, node_id, node_type, node_name):
        self.id = node_id
        self.type = node_type
        self.name = node_name

def visualize_with_networkX(attackSimulation):
    """ 
     Visualize the attackgraph with networkX package
    """
    nodes = {}
    edgeLabels = {}
    labels = {}
    
    # Create networkX graph object
    networkXGraph = nx.DiGraph()
    # Create node-objects from visited nodes from attack
    for node_id in attackSimulation.visited:
        node = attackSimulation.attackgraph_dictionary[node_id]
        networkXnode = Node(node.id, node.type, node.name)
        # Put node in graph
        networkXGraph.add_node(networkXnode)
        nodes[node.id] = networkXnode
        # Customize what is written inside the node
        labels[networkXnode] = node_id

    costDict = attackSimulation.get_costs("costs.json")
    
    # Add Edges
    for id in attackSimulation.attackgraph_dictionary.keys():
        if id in nodes.keys():
            for link in attackSimulation.path[id]:
                if link.id in nodes.keys():
                    from_node = nodes[id]
                    to_node = nodes[link.id]
                    networkXGraph.add_edge(from_node, to_node)
                    if link.id in costDict.keys():
                        # Customize label for the edges
                        edgeLabels[to_node] = costDict[link.id]

    # Plot the network with matplotlib
    pos = nx.spring_layout(networkXGraph)

    # Draw network
    nx.draw(networkXGraph, pos, with_labels=True, labels = labels, font_weight='bold', font_size = 6, node_size=800, node_color='#add8e6', font_color='black')
    
    # Add cost labels to the edge/arrows
    for (from_node, to_node) in networkXGraph.edges():
        if from_node in edgeLabels.keys():
            cost = edgeLabels[from_node]
            label_pos = pos[from_node] + (pos[to_node] - pos[from_node]) * 0.5  # Label set at the midpoint
            plt.text(label_pos[0], label_pos[1], f'Cost: {cost}', color='red', fontsize=8, ha='center', va='center')
    
    # Plot the graph
    plt.show()

