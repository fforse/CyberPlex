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

""" Get number of associations for an asset"""
def get_number_of_associations(asset):
    numberOfAssocs=0
    for assoc in asset.associations:
        numberOfAssocs = numberOfAssocs + 1 
    return numberOfAssocs

""" Remove associated assets"""
    
def remove_associations(asset, honorModel):
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

def remove_asset_by_word(word, honorModel):
    for asset in honorModel.assets:
        if word in asset.name:
            remove_associations(asset, honorModel)
            honorModel.delete_asset(asset)
        else:
            pass 

""" Removes asset and their associations by asset Id"""
def remove_asset_by_id(assetId, honorModel):
    for asset in honorModel.assets:
        if assetId == asset.id:
            remove_associations(asset, honorModel)
            honorModel.delete_asset(asset)
        else:
            pass



def modify_model(modifyModel, removeSmartMeterCompany, honorModel):
    if modifyModel:
        """ Remove assets that only exist in the parts of the diagram that is not needed for this project"""
        remove_asset_by_word("Flex", honorModel)
        remove_asset_by_word("BRP", honorModel)
        remove_asset_by_word("Forecasting Engine", honorModel)
        remove_asset_by_word("FMO", honorModel)
        remove_asset_by_word("Realtime Portfolio Optimization", honorModel)
        remove_asset_by_word("Portfolio schedule", honorModel)
        remove_asset_by_word("Price Determination Module", honorModel)
        remove_asset_by_word("Core Zone LAN", honorModel)


        """ Delete assets by ID manually """
        # Removed oper plan lan
        remove_asset_by_id(100898871897509330)
        # Remove Office apps
        remove_asset_by_id(-4261889968587799, honorModel)
        remove_asset_by_id(8422929894975537, honorModel)
        remove_asset_by_id(4609041281564954080, honorModel)

        # Remove office stations
        remove_asset_by_id(-6772814032133054, honorModel)
        remove_asset_by_id(5430278858885866, honorModel)
        remove_asset_by_id(-3726203282743803897, honorModel)

        # Remove Smart phones
        remove_asset_by_id(5342943235266378, honorModel)
        remove_asset_by_id(-1651829060724692, honorModel)
        remove_asset_by_id(-7990077015743772938, honorModel)

        # Remove remaning nodes that is no longer connected to any network
        """ Routing firewall"""
        remove_asset_by_id(5861894220968398, honorModel) 
        remove_asset_by_id(9487955995225705, honorModel) 
        remove_asset_by_id(998645070887503, honorModel)
        remove_asset_by_id(-3679067691953713, honorModel)
        remove_asset_by_id(1953908654782484, honorModel)
        remove_asset_by_id(8647976104775730872, honorModel)
        remove_asset_by_id(630599287284321073, honorModel)
        remove_asset_by_id(-1219191878300317907, honorModel)
        remove_asset_by_id(-6852300144031777, honorModel)
        remove_asset_by_id(793427202612141, honorModel)

        """ Other single assets"""

        remove_asset_by_id(5466457068975510, honorModel) # vendor repo
        remove_asset_by_id(2853168851534234089, honorModel) # Office LAN
        remove_asset_by_id(9289055741320983, honorModel) # Software product
        """ Data"""

        remove_asset_by_id(50952803218571521, honorModel)
        remove_asset_by_id(-3540500933244485, honorModel)


        """Identity"""
        remove_asset_by_id(724411689770437278, honorModel)
        remove_asset_by_id(5953117939489696, honorModel)
        """ enc keys"""
        remove_asset_by_id(6208161549452362, honorModel)
        """Web server"""
        remove_asset_by_id(4467712106477498, honorModel) 

        """HMI"""

        remove_asset_by_id(-7951899973500451269, honorModel) 
        remove_asset_by_id(7450651581530868, honorModel) 
        remove_asset_by_id(-1614407497478242, honorModel)

        """ Hardware"""
        remove_asset_by_id(7263467691339827543, honorModel)
        remove_asset_by_id(-3208148400870044, honorModel)
        remove_asset_by_id(-9263438396079499, honorModel)


        """ IDPS"""

        remove_asset_by_id(5297210351268283906, honorModel)
        remove_asset_by_id(3751404497637033322, honorModel)
        remove_asset_by_id(-1809447059000080, honorModel)  
        remove_asset_by_id(-3026791298869886, honorModel)
        remove_asset_by_id(226926412673467811, honorModel)
        remove_asset_by_id(2988778213196154, honorModel)
        remove_asset_by_id(3719593162493644, honorModel)
        remove_asset_by_id(9602180365781539, honorModel)
        #remove_asset_by_id(, honorModel)
        #remove_asset_by_id(, honorModel)


        """ Connection rules"""
        remove_asset_by_id(5284237359521220281, honorModel)
        remove_asset_by_id(34831888698443, honorModel)
        remove_asset_by_id(9391517259115448, honorModel)
        remove_asset_by_id(-5710554851359565, honorModel)
        remove_asset_by_id(8148353667981430, honorModel)
        remove_asset_by_id(6828937191462768, honorModel)
        remove_asset_by_id(741400175886211, honorModel)
        remove_asset_by_id(-9526882671881760, honorModel)
        remove_asset_by_id(-9927256164015983, honorModel)
        remove_asset_by_id(6160499563261742524, honorModel)
        #remove_asset_by_id(, honorModel)
        #remove_asset_by_id(, honorModel)
        
        
        """ Delete all attackers"""
        honorModel.attackers.clear()

    """ Remove smart meter company"""
    if removeSmartMeterCompany:
        remove_asset_by_word("Data Acquisitions Server", honorModel)
        remove_asset_by_word("Head End LAN", honorModel)
        remove_asset_by_id(6422000877406470711, honorModel) # Home lan
        remove_asset_by_id(-4921966004899526197, honorModel)
        remove_asset_by_id(-4843381891044259938, honorModel)
        remove_asset_by_id(-6307008247164809928, honorModel)
        remove_asset_by_id(-9033956709002227818, honorModel)
        remove_asset_by_id(-2777251403626038, honorModel)
        remove_asset_by_id(2197678936095523, honorModel)
        remove_asset_by_id(6285948730045251, honorModel)
        remove_asset_by_id(6523388025420282, honorModel)
        remove_asset_by_id(3462987087913438036, honorModel)
        remove_asset_by_id(4202976130662506, honorModel) # data
        remove_asset_by_id(6307075106216496016, honorModel) # SM Application
        remove_asset_by_id(4008919923640124487, honorModel) # Heating
        remove_asset_by_id(5185958517877591920, honorModel) # EV
        remove_asset_by_id(3680162965350382, honorModel) # HEMS
        remove_asset_by_id(-6537745890440361712, honorModel)
        remove_asset_by_id(2220090544218393038, honorModel) # user
        remove_asset_by_id(-4373164576582296, honorModel) # identity
        remove_asset_by_id(4968758791644596546, honorModel) # web server
        remove_asset_by_id(-7283750711606031546, honorModel) # connection
        remove_asset_by_id(-2889968223457820481, honorModel) # routing
        remove_asset_by_id(4919524858234960, honorModel) # connection
        remove_asset_by_id(-8373281683568219, honorModel) # credentials
        remove_asset_by_id(5953117495399963, honorModel) # PL-C/LoRaWAN
        remove_asset_by_id(7622638448884612, honorModel) # Meter data conc
        remove_asset_by_id(-6257796774946495, honorModel) # kwh meter
        remove_asset_by_id(2197678936095523, honorModel) # routing
        remove_asset_by_id(-2777251403626038, honorModel) # connection

