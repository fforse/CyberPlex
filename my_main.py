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

# From my python files
import modfication_of_model
import add_plexigrid
import attack_functions
import model_functions

# From mgg-project
import cost_from_ttc
import attack_simulation

# Extra packages
from py2neo import Graph
import networkx as nx
import matplotlib.pyplot as plt



""" Modify model"""
modifyModel = False

""" Change depedning on test case"""
removeSmartMeterCompany = True

""" Choose the modifed file or the Honor-model"""
use_modified_model = True

if use_modified_model:
    json_file = "tempModel.json"
else:
    json_file = "honor_test.json"

"""Add attacker"""
addAttacker = True

""" Turn off defennces"""
no_defences = True

""" Run Attack"""
run_attack = True

""" Add assets"""
add_assets = False

""" Add plexigrid associations"""
add_association = False

""" Load the language specification, coreLang mar file """
langSpec = specification.load_language_specification_from_json("coreLang.json")

""" Get coreLang in json format"""
#specification.save_language_specification_to_json(langSpec, "coreLang.json")

""" Generate python classes from specification """
pythClasses = classes_factory.LanguageClassesFactory(langSpec)
pythClasses.create_classes()
#print(dir(pythClasses.ns.Network)) # print attribute from the generated classes

"""Create a model object """
honorModel = model.Model("honormodel", langSpec, pythClasses)

""" Load model from json format. If first time running the program, use "honor_test.json" else use "tempModel.json" """
honorModel.load_from_file(json_file)

""" Modify model"""
modfication_of_model.modify_model(modifyModel, removeSmartMeterCompany, honorModel)

""" Add Plexigrid assets and associations"""
add_plexigrid.add_plexigrid_assets(pythClasses, honorModel)

###################TEST######################################
""" Test which asset ids that are conneected to an asset"""
"""
testasset = honorModel.get_asset_by_id(8482151560692704)
for assoc in testasset.associations:
    if testasset in getattr(assoc,
            list(vars(assoc)['_properties'])[0]):
            connectedAssocName = list(vars(assoc)['_properties'])[1]
    else:
        connectedAssocName = list(vars(assoc)['_properties'])[0]
    connectedAsset = getattr(assoc, connectedAssocName)
    print(connectedAsset[0].id)
"""
################################################################

""" Add attacker"""
attkgraph = attack_functions.add_attacker(addAttacker, honorModel, langSpec)

""" Save in a temp json file """
honorModel.save_to_file("tempModel.json")


""" Turn of defenses for testing"""
def turn_off_defences(attackgraph):
    for node in attackgraph.nodes:
        if node.type == 'defense':
            node.is_necessary = False

if no_defences:
    turn_off_defences(attkgraph)
""" Extract defenses"""
extractDefenses = False
if extractDefenses:
    model_functions.extract_defenses(honorModel, "defenses.json")

if run_attack:
    attkgraph.save_to_file("attackgraph_file.json")
    model_functions.cost_function(attkgraph)

    # Set which test
    test_dijkstra = True
    test_random_path = False
    attackSimulation = attack_functions.setting_up_attackSimulation(attkgraph, test_dijkstra, test_random_path)

upload_to_neo4j = False
if upload_to_neo4j:
    attack_functions.create_neo4j_graph(attackSimulation)
    
visualize = True
if visualize:
    attack_functions.visualize_with_networkX(attackSimulation)


