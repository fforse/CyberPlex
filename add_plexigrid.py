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
import modfication_of_model

""" Add Plexigrid assets"""
add_association = False
add_assets = False
addToHonorModel = False
def add_plexigrid_assets(pythClasses, honorModel):
    if add_assets:
        # FTP server
        plexigridFtp = pythClasses.ns.Application()
        plexigridFtp.metaconcept = "Application"
        plexigridFtp.name = "Plexigrid FTP server"
        plexigridFtp.supplyChainAuditing = 1
        # Software vulnerability
        vulnerabilityAsset = pythClasses.ns.SoftwareVulnerability()
        vulnerabilityAsset.metaconcept = "SoftwareVulnerability"
        vulnerabilityAsset.name = "SoftwareVulnerability Plexi"
        # Network
        plexiNetwork = pythClasses.ns.Network()
        plexiNetwork.metaconcept = "Network"
        plexiNetwork.name = "Plexigrid Core Network"
        # Connection Node
        plexiConn = pythClasses.ns.ConnectionRule()
        plexiConn.metaconcept = "ConnectionRule"
        plexiConn.name = "ConnectionRule"
        # Routing
        plexiRouting = pythClasses.ns.RoutingFirewall()
        plexiRouting.metaconcept = "RoutingFirewall"
        plexiRouting.name = "RoutingFirewall"
        plexiRouting.supplyChainAuditing = 1
        # Vulnerability related to Router
        vulnerabilityAssetRouting = pythClasses.ns.SoftwareVulnerability()
        vulnerabilityAssetRouting.metaconcept = "SoftwareVulnerability"
        vulnerabilityAssetRouting.name = "SoftwareVulnerability"
        # Add to model
        honorModel.add_asset(plexiNetwork)
        honorModel.add_asset(plexigridFtp)
        honorModel.add_asset(vulnerabilityAsset)
        honorModel.add_asset(plexiConn)
        honorModel.add_asset(plexiRouting)
        honorModel.add_asset(vulnerabilityAssetRouting)
    if add_association:
        # Add software vulnerability to plexigrid FTP 
        associationBetweenAssets = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
        associationBetweenAssets.application = [plexigridFtp]
        associationBetweenAssets.vulnerabilities = [vulnerabilityAsset]
        # Add connection and firewall
        # FirewallConnectionRule (routingFirewalls, connectionRules)
        assocFirewallandConn = pythClasses.ns.FirewallConnectionRule()
        assocFirewallandConn.routingFirewalls = [plexiRouting]
        assocFirewallandConn.connectionRules = [plexiConn]
        # Add vulnerabillity to router
        assocVulnandFirewall = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
        assocVulnandFirewall.application = [plexiRouting]
        assocVulnandFirewall.vulnerabilities = [vulnerabilityAssetRouting]
        # Add connection to network
        # NetworkConnections (networks, netConnection)
        assocConnandNetwork = pythClasses.ns.NetworkConnection()
        assocConnandNetwork.networks = [plexiNetwork]
        assocConnandNetwork.netConnections = [plexiConn]
        # Connect FTP with network
        assocAppliandNetwork = pythClasses.ns.NetworkExposure()
        assocAppliandNetwork.networks = [plexiNetwork]
        assocAppliandNetwork.applications = [plexigridFtp]

        honorModel.add_association(associationBetweenAssets)
        honorModel.add_association(assocFirewallandConn)
        honorModel.add_association(assocVulnandFirewall)
        honorModel.add_association(assocConnandNetwork)
        honorModel.add_association(assocAppliandNetwork)
        """
        # Connect to HONOR-model
        """
    if addToHonorModel:
        associationToHonorModel = pythClasses.ns.NetworkConnection()
        internet = honorModel.get_asset_by_id(8103222226739678984)
        plexigridConn = honorModel.get_asset_by_id(8868704904159774858)
        associationToHonorModel.networks = [internet]
        associationToHonorModel.netConnections = [plexigridConn]
        honorModel.add_association(associationToHonorModel)