import sys

import logging
import json

import maltoolbox
import maltoolbox.cl_parser
from maltoolbox.language import classes_factory
from maltoolbox.language import specification
from maltoolbox.model import model
from maltoolbox.attackgraph import attackgraph
from maltoolbox.attackgraph.analyzers import apriori
from maltoolbox.ingestors import neo4j



""" Modify model"""
modify_model = False

""" Change depedning on test case"""
remove_smart_meter_company = True

""" Choose the modifed file or the Honor-model"""
use_modified_model = True

if use_modified_model == True:
    json_file = "tempModel.json"
else:
    json_file = "honor_test.json"

"""Add attacker"""
add_attacker = False

""" Load the language specification, coreLang mar file """
langSpec = specification.load_language_specification_from_mar("mal_corelang_test.mar")

""" Get coreLang in json format"""
#specification.save_language_specification_to_json(langSpec, "coreLang.json")

""" Generate python classes from specification """
pythClasses = classes_factory.LanguageClassesFactory(langSpec)
pythClasses.create_classes()

"""Create a model object """
honorModel = model.Model("honormodel", langSpec, pythClasses)

""" Load model from json format. If first time running the program, use "honor_test.json" else use "tempModel.json" """
honorModel.load_from_file(json_file)

""" Get number of associations for an asset"""
def get_number_of_associations(asset):
    numberOfAssocs=0
    for assoc in asset.associations:
        numberOfAssocs = numberOfAssocs + 1 
    return numberOfAssocs


""" Remove associated assets"""
    
def remove_associations(asset):
    for assoc in asset.associations:
        if asset in getattr(assoc,
            list(vars(assoc)['_properties'])[0]):
            connectedAssocName = list(vars(assoc)['_properties'])[1]
        else:
            connectedAssocName = list(vars(assoc)['_properties'])[0]
        connectedAsset = getattr(assoc, connectedAssocName)
        associatedAsset = honorModel.get_asset_by_id(connectedAsset[0].id)
        if associatedAsset != None: 
            if associatedAsset.name == "Internet":
                print("Found the internet")
                honorModel.delete_all_associations_by_asset_id(asset.id)
            else:
                nassocs = get_number_of_associations(associatedAsset)
                # If the associated node is an edge, remove it.
                if nassocs == 1:
                    honorModel.delete_asset(associatedAsset)
                    honorModel.delete_all_associations_by_asset_id(asset.id)
                # If the associated node have multiple connections, let it be.
                else:
                    honorModel.delete_all_associations_by_asset_id(asset.id)
                

""" Remove all assets and their associations having a specfied word in their name"""

def remove_asset_by_word(word):
    for asset in honorModel.assets:
        if word in asset.name:
            remove_associations(asset)
            honorModel.delete_asset(asset)
        else:
            pass 
""" Removes asset and their associations by asset Id"""
def remove_asset_by_id(assetId):
    for asset in honorModel.assets:
        if assetId == asset.id:
            remove_associations(asset)
            honorModel.delete_asset(asset)
        else:
            pass




if modify_model == True:
    """ Remove assets that only exist in the parts of the diagram that is not needed for this project"""
    remove_asset_by_word("Flex")
    remove_asset_by_word("BRP")
    remove_asset_by_word("Forecasting Engine")
    remove_asset_by_word("FMO")
    remove_asset_by_word("Realtime Portfolio Optimization")
    remove_asset_by_word("Portfolio schedule")
    remove_asset_by_word("Price Determination Module")
    remove_asset_by_word("Core Zone LAN")


    """ Delete assets by ID manually """
    # Removed oper plan lan
    remove_asset_by_id(100898871897509330)
    # Remove Office apps
    remove_asset_by_id(-4261889968587799)
    remove_asset_by_id(8422929894975537)
    remove_asset_by_id(4609041281564954080)

    # Remove office stations
    remove_asset_by_id(-6772814032133054)
    remove_asset_by_id(5430278858885866)
    remove_asset_by_id(-3726203282743803897)

    # Remove Smart phones
    remove_asset_by_id(5342943235266378)
    remove_asset_by_id(-1651829060724692)
    remove_asset_by_id(-7990077015743772938)

    # Remove remaning nodes that is no longer connected to any network
    """ Routing firewall"""
    remove_asset_by_id(5861894220968398) 
    remove_asset_by_id(9487955995225705) 
    remove_asset_by_id(998645070887503)
    remove_asset_by_id(-3679067691953713)
    remove_asset_by_id(1953908654782484)
    remove_asset_by_id(8647976104775730872)
    remove_asset_by_id(630599287284321073)
    remove_asset_by_id(-1219191878300317907)
    remove_asset_by_id(-6852300144031777)
    remove_asset_by_id(793427202612141)

    """ Other single assets"""

    remove_asset_by_id(5466457068975510) # vendor repo
    remove_asset_by_id(2853168851534234089) # Office LAN
    remove_asset_by_id(9289055741320983) # Software product
    """ Data"""

    remove_asset_by_id(50952803218571521)
    remove_asset_by_id(-3540500933244485)


    """Identity"""
    remove_asset_by_id(724411689770437278)
    remove_asset_by_id(5953117939489696)
    """ enc keys"""
    remove_asset_by_id(6208161549452362)
    """Web server"""
    remove_asset_by_id(4467712106477498) 

    """HMI"""

    remove_asset_by_id(-7951899973500451269) 
    remove_asset_by_id(7450651581530868) 
    remove_asset_by_id(-1614407497478242)

    """ Hardware"""
    remove_asset_by_id(7263467691339827543)
    remove_asset_by_id(-3208148400870044)
    remove_asset_by_id(-9263438396079499)


    """ IDPS"""

    remove_asset_by_id(5297210351268283906)
    remove_asset_by_id(3751404497637033322)
    remove_asset_by_id(-1809447059000080)  
    remove_asset_by_id(-3026791298869886)
    remove_asset_by_id(226926412673467811)
    remove_asset_by_id(2988778213196154)
    remove_asset_by_id(3719593162493644)
    remove_asset_by_id(9602180365781539)
    #remove_asset_by_id()
    #remove_asset_by_id()


    """ Connection rules"""
    remove_asset_by_id(5284237359521220281)
    remove_asset_by_id(34831888698443)
    remove_asset_by_id(9391517259115448)
    remove_asset_by_id(-5710554851359565)
    remove_asset_by_id(8148353667981430)
    remove_asset_by_id(6828937191462768)
    remove_asset_by_id(741400175886211)
    remove_asset_by_id(-9526882671881760)
    remove_asset_by_id(-9927256164015983)
    remove_asset_by_id(6160499563261742524)
    #remove_asset_by_id()
    #remove_asset_by_id()
    
    
    """ Delete all attackers"""
    honorModel.attackers.clear()

""" Remove smart meter company"""
if remove_smart_meter_company == True:
    remove_asset_by_word("Data Acquisitions Server")
    remove_asset_by_word("Head End LAN")
    remove_asset_by_id(6422000877406470711) # Home lan
    remove_asset_by_id(-4921966004899526197)
    remove_asset_by_id(-4843381891044259938)
    remove_asset_by_id(-6307008247164809928)
    remove_asset_by_id(-9033956709002227818)
    remove_asset_by_id(-2777251403626038)
    remove_asset_by_id(2197678936095523)
    remove_asset_by_id(6285948730045251)
    remove_asset_by_id(6523388025420282)
    remove_asset_by_id(3462987087913438036)
    remove_asset_by_id(4202976130662506) # data
    remove_asset_by_id(6307075106216496016) # SM Application
    remove_asset_by_id(4008919923640124487) # Heating
    remove_asset_by_id(5185958517877591920) # EV
    remove_asset_by_id(3680162965350382) # HEMS
    remove_asset_by_id(-6537745890440361712)
    remove_asset_by_id(2220090544218393038) # user
    remove_asset_by_id(-4373164576582296) # identity
    remove_asset_by_id(4968758791644596546) # web server
    remove_asset_by_id(-7283750711606031546) # connection
    remove_asset_by_id(-2889968223457820481) # routing
    remove_asset_by_id(4919524858234960) # connection
    remove_asset_by_id(-8373281683568219) # credentials
    remove_asset_by_id(5953117495399963) # PL-C/LoRaWAN
    remove_asset_by_id(7622638448884612) # Meter data conc
    remove_asset_by_id(-6257796774946495) # kwh meter
    remove_asset_by_id(2197678936095523) # routing
    remove_asset_by_id(-2777251403626038) # connection





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


""" Add attacker"""
if add_attacker:
    attacker = model.Attacker()
    attacker.id = "-4557996462960095"
    attacker.name = "Attacker"
    entry_point_asset = honorModel.get_asset_by_id(1007211369537407)
    list_of_tuples = [(entry_point_asset, ['fullAccess'])]
    attacker.entry_points = list_of_tuples

    honorModel.add_attacker(attacker)

""" Generate attackgraps from model """
attkgraph = attackgraph.AttackGraph()
attkgraph.generate_graph(langSpec, honorModel)
attkgraph.attach_attackers(honorModel)
attkgraph.save_to_file("attackgraph_file.json")


""" Make every ttc label to a cost"""
for node in attkgraph.nodes:
    if node.ttc != None:
        ttc = node.ttc
        
        print(ttc)
    #print(theNode)

""" Save in a temp json file """
honorModel.save_to_file("tempModel.json")

""" Create neo4j model instance """

#neo4j.ingest_model(honorModel, "neo4j://localhost:7687", "Fredrik",
#"fred4551", "ingestmodel", delete=True)

""" Create neo4j attackgraph instance """

#neo4j.ingest_attack_graph(attkgraph, "neo4j://localhost:7687", "Fredrik",
#"fred4551", "attackgraphs", delete=True)


