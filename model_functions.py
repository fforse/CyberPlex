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

################################## Create Json files #########################################################
""" Make every ttc label to a cost"""
def cost_function(attackgraph):
    costDict = {}
    output_file = "costs.json"
    # To give all attack steps a cost
    for node in attackgraph.nodes:
        # If the ttc is defined
        if node.ttc != None:
            ttc = node.ttc
            cost = cost_from_ttc.cost_from_ttc(ttc)
            roundedCost = int(round(cost, 0))
            #print(roundedCost)
            costDict[node.id] = roundedCost
        # If the ttc is null
        else:
            node.ttc = 0
            costDict[node.id] = node.ttc
    with open(output_file, 'w') as file:
        json.dump(costDict, file)
        #print(node.to_dict()['id'])

""" Extract all defenses for an asset"""

def extract_defenses(honorModel, output_file):
    """
    Extract the defense attributes for all asssets in a model

    Input: A model instance and output_file
    Output: A dict in the form "assetCategory:assetId:Defense":"probabilityDistribution" and saves the dictionary to specified output_file in json format
    """
    defenseDict = {}
    for asset in honorModel.assets:
        type_of_asset = type(asset).__name__
        # Applies for almost all asset categories
        if hasattr(asset, "notPresent"): 
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "notPresent"
            defenseDict[defenses] = float(asset.notPresent)
        # For Application, RoutingFirewall, Data and Hardware
        if hasattr(asset, "supplyChainAuditing"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "supplyChainAuditing"
            defenseDict[defenses] = float(asset.supplyChainAuditing)
        # For Network
        if hasattr(asset, "adversaryInTheMiddleDefense"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "adversaryInTheMiddleDefense"
            defenseDict[defenses] = float(asset.adversaryInTheMiddleDefense)
        if hasattr(asset, "eavesdropDefense"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "eavesdropDefense"
            defenseDict[defenses] = float(asset.eavesdropDefense)
        if hasattr(asset, "networkAccessControl"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "networkAccessControl"
            defenseDict[defenses] = float(asset.networkAccessControl)
        # For SoftwareVulnerability and HardwareVulnerability
        if hasattr(asset, "availabilityImpactLimitations") :
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "availabilityImpactLimitations"
            defenseDict[defenses] = float(asset.availabilityImpactLimitations)
        if hasattr(asset, "confidentialityImpactLimitations") :
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "confidentialityImpactLimitations"
            defenseDict[defenses] = float(asset.confidentialityImpactLimitations)
        if hasattr(asset, "highComplexityExploitRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "highComplexityExploitRequired"
            defenseDict[defenses] = float(asset.highComplexityExploitRequired)
        if hasattr(asset, "highPrivilegesRequired") :
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "highPrivilegesRequired"
            defenseDict[defenses] = float(asset.highPrivilegesRequired)
        if hasattr(asset, "integrityImpactLimitations"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "integrityImpactLimitations"
            defenseDict[defenses] = float(asset.integrityImpactLimitations)
        if hasattr(asset, "localAccessRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "localAccessRequired"
            defenseDict[defenses] = float(asset.localAccessRequired)    
        if hasattr(asset, "lowPrivilegesRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "lowPrivilegesRequired"
            defenseDict[defenses] = float(asset.lowPrivilegesRequired)
        if hasattr(asset, "networkAccessRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "networkAccessRequired"
            defenseDict[defenses] = float(asset.networkAccessRequired)
        if hasattr(asset, "physicalAccessRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "physicalAccessRequired"
            defenseDict[defenses] = float(asset.physicalAccessRequired)
        if hasattr(asset, "userInteractionRequired"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "userInteractionRequired"
            defenseDict[defenses] = float(asset.userInteractionRequired)
        # For Hardware
        if hasattr(asset, "hardwareModificationsProtection"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "hardwareModificationsProtection"
            defenseDict[defenses] = float(asset.hardwareModificationsProtection)
        # For ConnectionRule
        if hasattr(asset, "payloadInspection"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "payloadInspection"
            defenseDict[defenses] = float(asset.payloadInspection)
        if hasattr(asset, "restricted"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "restricted"
            defenseDict[defenses] = float(asset.restricted)
        # For User
        if hasattr(asset, "noPasswordReuse"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "noPasswordReuse"
            defenseDict[defenses] = float(asset.noPasswordReuse)
        if hasattr(asset, "noRemovableMediaUsage"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "noRemovableMediaUsage"
            defenseDict[defenses] = float(asset.noRemovableMediaUsage)
        if hasattr(asset, "securityAwareness"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "securityAwareness"
            defenseDict[defenses] = float(asset.securityAwareness)
        # For Credentials
        if hasattr(asset, "notDisclosed"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "notDisclosed"
            defenseDict[defenses] = float(asset.notDisclosed)
        if hasattr(asset, "notGuessable"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "notGuessable"
            defenseDict[defenses] = float(asset.notGuessable)
        if hasattr(asset, "notPhishable"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "notPhishable"
            defenseDict[defenses] = float(asset.notPhishable)
        if hasattr(asset, "unique"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "unique"
            defenseDict[defenses] = float(asset.unique)
        # For HardwareVulnerability
        if hasattr(asset, "effortRequiredToExploit"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "effortRequiredToExploit"
            defenseDict[defenses] = float(asset.effortRequiredToExploit)
        if hasattr(asset, "unique"):
            defenses = type_of_asset + ":" + str(asset.id) + ":" + "unique"
            defenseDict[defenses] = float(asset.unique)
    with open(output_file, 'w') as file:
        json.dump(defenseDict, file)
    return defenseDict