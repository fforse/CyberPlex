# From mal-toolboxFalsC
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
add_association = True
add_assets = True
addToHonorModel = True
# Email->Email
test_case1 = True
# Email->Onedrive
test_case2 = False
#SFTP-> Email
test_case3 = False
#SFTP->Onedrive
test_case4 = False
def add_plexigrid_assets(pythClasses, honorModel):
    if add_assets:
################################################## Test 1 ########################################################################       
        if test_case1:
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Plexigrid development Network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Plexigrid project/sales Network"
            # connection node between development and Project/sales networks
            plexiInternalConn = pythClasses.ns.ConnectionRule()
            plexiInternalConn.metaconcept = "ConnectionRule"
            plexiInternalConn.name = "ConnectionRule"
            # connection between Plexi project/sales and internet
            plexiSalesConn = pythClasses.ns.ConnectionRule()
            plexiSalesConn.metaconcept = "ConnectionRule"
            plexiSalesConn.name = "ConnectionRule internet"
            # connection between Plexi dev and internet
            plexiDevConn = pythClasses.ns.ConnectionRule()
            plexiDevConn.metaconcept = "ConnectionRule"
            plexiDevConn.name = "ConnectionRule internet"
            # connection between sales network and sales mail server
            plexiMailSalesConn = pythClasses.ns.ConnectionRule()
            plexiMailSalesConn.metaconcept = "ConnectionRule"
            plexiMailSalesConn.name = "ConnectionRule"
            # connection between Dev network and Dev mail server
            plexiMailDevConn = pythClasses.ns.ConnectionRule()
            plexiMailDevConn.metaconcept = "ConnectionRule"
            plexiMailDevConn.name = "ConnectionRule"
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall between Sales and dev
            plexiSalesDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiSalesDevFirewall.metaconcept = "RoutingFirewall"
            plexiSalesDevFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall sales/dev
            vulnerabilityFirewallSalesDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallSalesDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallSalesDev.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Office station"
            plexigridSalesOffice.supplyChainAuditing = 1
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Mail-Server for Plexigrid project/sales
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "Plexigrid mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "Project Manager"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            # Software vulnreability for Project/sales mail server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            # Mail-server for Plexigrid Dev network
            plexigridDevMail = pythClasses.ns.Application()
            plexigridDevMail.metaconcept = "Application"
            plexigridDevMail.name = "Plexigrid mail server"
            plexigridDevMail.supplyChainAuditing = 1
            # Software vulnreability for Dev mail server
            vulnerabilityDevMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDevMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDevMail.name = "SoftwareVulnerability Mail server"
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"
            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            honorModel.add_asset(plexiInternalConn)
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridSalesMail)
            honorModel.add_asset(plexigridDevMail)
            honorModel.add_asset(plexigridDataDSO)
            honorModel.add_asset(vulnerabilityDevMail)
            honorModel.add_asset(vulnerabilitySalesMail)
            honorModel.add_asset(plexiMailSalesConn)
            honorModel.add_asset(plexiMailDevConn)
            honorModel.add_asset(plexigridPMIdentity)
            honorModel.add_asset(plexigridPMUser)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexigridSalesOfficeConn)
            honorModel.add_asset(plexigridSalesOffice)
            honorModel.add_asset(plexigridDevOffice)
            honorModel.add_asset(plexiSalesDevFirewall)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            honorModel.add_asset(vulnerabilityFirewallSalesDev)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(plexiDevConn)
################################################## Test 2 ########################################################################       

        if test_case2:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            # OneDrive for Plexigrid project/sales
            """
            Might need additional vulnerabilities, we will see 
            """
            cloudOneDrive = pythClasses.ns.Application()
            cloudOneDrive.metaconcept = "Application"
            cloudOneDrive.name = "OneDrive"
            cloudOneDrive.supplyChainAuditing = 1
            # connection between cloud network and OneDrive
            plexiCloudOneDriveConn = pythClasses.ns.ConnectionRule()
            plexiCloudOneDriveConn.metaconcept = "ConnectionRule"
            plexiCloudOneDriveConn.name = "ConnectionRule"
            # Software vulnreability for OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability OneDrive"
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Plexigrid development Network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Plexigrid project/sales Network"
            # connection node between development and Project/sales networks
            plexiInternalConn = pythClasses.ns.ConnectionRule()
            plexiInternalConn.metaconcept = "ConnectionRule"
            plexiInternalConn.name = "ConnectionRule"
            # connection between Plexi project/sales and internet
            plexiSalesConn = pythClasses.ns.ConnectionRule()
            plexiSalesConn.metaconcept = "ConnectionRule"
            plexiSalesConn.name = "ConnectionRule internet"
            # connection between Plexi dev and internet
            plexiDevConn = pythClasses.ns.ConnectionRule()
            plexiDevConn.metaconcept = "ConnectionRule"
            plexiDevConn.name = "ConnectionRule internet"
            # connection between sales network and sales mail server
            plexiMailSalesConn = pythClasses.ns.ConnectionRule()
            plexiMailSalesConn.metaconcept = "ConnectionRule"
            plexiMailSalesConn.name = "ConnectionRule"
            # connection between Dev network and Dev mail server
            plexiMailDevConn = pythClasses.ns.ConnectionRule()
            plexiMailDevConn.metaconcept = "ConnectionRule"
            plexiMailDevConn.name = "ConnectionRule"
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall between Sales and dev
            plexiSalesDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiSalesDevFirewall.metaconcept = "RoutingFirewall"
            plexiSalesDevFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall sales/dev
            vulnerabilityFirewallSalesDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallSalesDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallSalesDev.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Office station"
            plexigridSalesOffice.supplyChainAuditing = 1
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Mail-Server for Plexigrid project/sales
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "Plexigrid mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "Project Manager"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            # Software vulnreability for Project/sales mail server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"
            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            honorModel.add_asset(plexiInternalConn)
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridSalesMail)
            honorModel.add_asset(plexigridDataDSO)
            honorModel.add_asset(vulnerabilitySalesMail)
            honorModel.add_asset(plexiMailSalesConn)
            honorModel.add_asset(plexigridPMIdentity)
            honorModel.add_asset(plexigridPMUser)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexigridSalesOfficeConn)
            honorModel.add_asset(plexigridSalesOffice)
            honorModel.add_asset(plexigridDevOffice)
            honorModel.add_asset(plexiSalesDevFirewall)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            honorModel.add_asset(vulnerabilityFirewallSalesDev)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(cloudNetwork)
            honorModel.add_asset(cloudOneDrive)
            honorModel.add_asset(CloudInternetConn)
            honorModel.add_asset(plexiCloudOneDriveConn)
            honorModel.add_asset(vulnerabilityOneDrive)
            honorModel.add_asset(plexiDevConn)

            

################################################## Test 3 ########################################################################       

        if test_case3:
            # Credentials for encryption
            DSOCreds = pythClasses.ns.Credentials()
            DSOCreds.metaconcept = "Credentials"
            DSOCreds.name = "Encryption keys"
            # Credentials data
            DSOEncryptedCreds = pythClasses.ns.Data()
            DSOEncryptedCreds.metaconcept = "Data"
            DSOEncryptedCreds.name = "Encrypted keys data"
            # Replicated information (to symbolize the same data)
            replicatedMeterData = pythClasses.ns.Information()
            replicatedMeterData.metaconcept = "Information"
            replicatedMeterData.name = "Metering Information"
            # SFTP server
            plexigridSftp = pythClasses.ns.Application()
            plexigridSftp.metaconcept = "Application"
            plexigridSftp.name = "Plexigrid SFTP server"
            plexigridSftp.supplyChainAuditing = 1
            # Software vulnerability related to SFTP
            vulnerabilitySftp = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySftp.metaconcept = "SoftwareVulnerability"
            vulnerabilitySftp.name = "SoftwareVulnerability SFTP"
            # Connection between SFTP
            plexiSFTPConn = pythClasses.ns.ConnectionRule()
            plexiSFTPConn.metaconcept = "ConnectionRule"
            plexiSFTPConn.name = "ConnectionRule"
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Plexigrid development Network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Plexigrid project/sales Network"
            # connection node between development and Project/sales networks
            plexiInternalConn = pythClasses.ns.ConnectionRule()
            plexiInternalConn.metaconcept = "ConnectionRule"
            plexiInternalConn.name = "ConnectionRule"
            # connection between Plexi project/sales and internet
            plexiSalesConn = pythClasses.ns.ConnectionRule()
            plexiSalesConn.metaconcept = "ConnectionRule"
            plexiSalesConn.name = "ConnectionRule internet"
            # connection between Plexi dev and internet
            plexiDevConn = pythClasses.ns.ConnectionRule()
            plexiDevConn.metaconcept = "ConnectionRule"
            plexiDevConn.name = "ConnectionRule internet"
            # connection between sales network and sales mail server
            plexiMailSalesConn = pythClasses.ns.ConnectionRule()
            plexiMailSalesConn.metaconcept = "ConnectionRule"
            plexiMailSalesConn.name = "ConnectionRule"
            # connection between Dev network and Dev mail server
            plexiMailDevConn = pythClasses.ns.ConnectionRule()
            plexiMailDevConn.metaconcept = "ConnectionRule"
            plexiMailDevConn.name = "ConnectionRule"
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall between Sales and dev
            plexiSalesDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiSalesDevFirewall.metaconcept = "RoutingFirewall"
            plexiSalesDevFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall sales/dev
            vulnerabilityFirewallSalesDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallSalesDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallSalesDev.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Office station"
            plexigridSalesOffice.supplyChainAuditing = 1
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Mail-Server for Plexigrid project/sales
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "Plexigrid mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "Project Manager"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            # Software vulnreability for Project/sales mail server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            # Mail-server for Plexigrid Dev network
            plexigridDevMail = pythClasses.ns.Application()
            plexigridDevMail.metaconcept = "Application"
            plexigridDevMail.name = "Plexigrid mail server"
            plexigridDevMail.supplyChainAuditing = 1
            # Software vulnreability for Dev mail server
            vulnerabilityDevMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDevMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDevMail.name = "SoftwareVulnerability Mail server"
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"
            # Metering Data going from PM->Dev
            plexigridDataPM = pythClasses.ns.Data()
            plexigridDataPM.metaconcept = "Data"
            plexigridDataPM.name = "Metering Data"
            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            honorModel.add_asset(plexiInternalConn)
            honorModel.add_asset(plexiMailSalesConn)
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridDevMail)
            honorModel.add_asset(plexigridSalesMail)
            honorModel.add_asset(plexigridDataDSO)
            honorModel.add_asset(vulnerabilityDevMail)
            honorModel.add_asset(vulnerabilitySalesMail)
            honorModel.add_asset(plexiMailDevConn)
            honorModel.add_asset(plexigridPMIdentity)
            honorModel.add_asset(plexigridPMUser)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexigridSalesOfficeConn)
            honorModel.add_asset(plexigridSalesOffice)
            honorModel.add_asset(plexigridDevOffice)
            honorModel.add_asset(plexiSalesDevFirewall)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            honorModel.add_asset(vulnerabilityFirewallSalesDev)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(plexiDevConn)
            honorModel.add_asset(plexigridSftp)
            honorModel.add_asset(vulnerabilitySftp)
            honorModel.add_asset(plexiSFTPConn)
            honorModel.add_asset(DSOCreds)
            honorModel.add_asset(DSOEncryptedCreds)
            honorModel.add_asset(replicatedMeterData)
            honorModel.add_asset(plexigridDataPM)


################################################## Test 4 ########################################################################       

        if test_case4:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            # OneDrive for Plexigrid project/sales
            """
            Might need additional vulnerabilities, we will see 
            """
            cloudOneDrive = pythClasses.ns.Application()
            cloudOneDrive.metaconcept = "Application"
            cloudOneDrive.name = "OneDrive"
            cloudOneDrive.supplyChainAuditing = 1
            # connection between cloud network and OneDrive
            plexiCloudOneDriveConn = pythClasses.ns.ConnectionRule()
            plexiCloudOneDriveConn.metaconcept = "ConnectionRule"
            plexiCloudOneDriveConn.name = "ConnectionRule"
            # Software vulnreability for OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability OneDrive"
             # Credentials for encryption
            DSOCreds = pythClasses.ns.Credentials()
            DSOCreds.metaconcept = "Credentials"
            DSOCreds.name = "Encryption keys"
            # Credentials data
            DSOEncryptedCreds = pythClasses.ns.Data()
            DSOEncryptedCreds.metaconcept = "Data"
            DSOEncryptedCreds.name = "Encrypted keys data"
            # Replicated information (to symbolize the same data)
            replicatedMeterData = pythClasses.ns.Information()
            replicatedMeterData.metaconcept = "Information"
            replicatedMeterData.name = "Metering Information"
            # SFTP server
            plexigridSftp = pythClasses.ns.Application()
            plexigridSftp.metaconcept = "Application"
            plexigridSftp.name = "Plexigrid SFTP server"
            plexigridSftp.supplyChainAuditing = 1
            # Software vulnerability related to SFTP
            vulnerabilitySftp = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySftp.metaconcept = "SoftwareVulnerability"
            vulnerabilitySftp.name = "SoftwareVulnerability SFTP"
            # Connection between SFTP
            plexiSFTPConn = pythClasses.ns.ConnectionRule()
            plexiSFTPConn.metaconcept = "ConnectionRule"
            plexiSFTPConn.name = "ConnectionRule"
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Plexigrid development Network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Plexigrid project/sales Network"
            # connection node between development and Project/sales networks
            plexiInternalConn = pythClasses.ns.ConnectionRule()
            plexiInternalConn.metaconcept = "ConnectionRule"
            plexiInternalConn.name = "ConnectionRule"
            # connection between Plexi project/sales and internet
            plexiSalesConn = pythClasses.ns.ConnectionRule()
            plexiSalesConn.metaconcept = "ConnectionRule"
            plexiSalesConn.name = "ConnectionRule internet"
            # connection between Plexi dev and internet
            plexiDevConn = pythClasses.ns.ConnectionRule()
            plexiDevConn.metaconcept = "ConnectionRule"
            plexiDevConn.name = "ConnectionRule internet"
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall between Sales and dev
            plexiSalesDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiSalesDevFirewall.metaconcept = "RoutingFirewall"
            plexiSalesDevFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall sales/dev
            vulnerabilityFirewallSalesDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallSalesDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallSalesDev.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Office station"
            plexigridSalesOffice.supplyChainAuditing = 1
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "Project Manager"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"
            # Metering Data going from PM->Dev
            plexigridDataPM = pythClasses.ns.Data()
            plexigridDataPM.metaconcept = "Data"
            plexigridDataPM.name = "Metering Data"
            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            honorModel.add_asset(plexiInternalConn)
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridDataDSO)
            honorModel.add_asset(plexigridPMIdentity)
            honorModel.add_asset(plexigridPMUser)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexigridSalesOfficeConn)
            honorModel.add_asset(plexigridSalesOffice)
            honorModel.add_asset(plexigridDevOffice)
            honorModel.add_asset(plexiSalesDevFirewall)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            honorModel.add_asset(vulnerabilityFirewallSalesDev)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(plexiDevConn)
            honorModel.add_asset(plexigridSftp)
            honorModel.add_asset(vulnerabilitySftp)
            honorModel.add_asset(plexiSFTPConn)
            honorModel.add_asset(DSOCreds)
            honorModel.add_asset(DSOEncryptedCreds)
            honorModel.add_asset(replicatedMeterData)
            honorModel.add_asset(plexigridDataPM)
            honorModel.add_asset(cloudNetwork)
            honorModel.add_asset(CloudInternetConn)
            honorModel.add_asset(cloudOneDrive)
            honorModel.add_asset(plexiCloudOneDriveConn)
            honorModel.add_asset(vulnerabilityOneDrive)    
    
    
    if add_association:
################################################## Test 1 ########################################################################       

        if test_case1:
           # Add networkconnections project/sales 
            assocConnSalesnetwork = pythClasses.ns.NetworkConnection()
            assocConnSalesnetwork.networks = [plexiSalesNetwork]
            assocConnSalesnetwork.netConnections = [plexiInternalConn]
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections Development
            assocConnDevnetwork = pythClasses.ns.NetworkConnection()
            assocConnDevnetwork.networks = [plexiDevNetwork]
            assocConnDevnetwork.netConnections = [plexiInternalConn]
            # Add Sales mail server to network
            assocConnSalesMail = pythClasses.ns.NetworkConnection()
            assocConnSalesMail.networks = [plexiSalesNetwork]
            assocConnSalesMail.netConnections = [plexiMailSalesConn]
            assocConnMailSales = pythClasses.ns.ApplicationConnection()
            assocConnMailSales.applications = [plexigridSalesMail]
            assocConnMailSales.appConnections = [plexiMailSalesConn]
            # Add softwarevuln. to sales mail server
            assocVulnSales = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSales.application = [plexigridSalesMail]
            assocVulnSales.vulnerabilities = [vulnerabilitySalesMail]
            # Add devs mail server to network
            assocConnDevMail = pythClasses.ns.NetworkConnection()
            assocConnDevMail.networks = [plexiDevNetwork]
            assocConnDevMail.netConnections = [plexiMailDevConn]
            assocConnMailDev = pythClasses.ns.ApplicationConnection()
            assocConnMailDev.applications = [plexigridDevMail]
            assocConnMailDev.appConnections = [plexiMailDevConn]
            # Add softwarevuln. to devs mail server
            assocVulnDevs = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnDevs.application = [plexigridDevMail]
            assocVulnDevs.vulnerabilities = [vulnerabilityDevMail]
            # Add dev office to dev network
            assocConnDevOffice = pythClasses.ns.NetworkConnection()
            assocConnDevOffice.networks = [plexiDevNetwork]
            assocConnDevOffice.netConnections = [plexigridDevOfficeConn]
            assocConnOfficeDev = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDev.applications = [plexigridDevOffice]
            assocConnOfficeDev.appConnections = [plexigridDevOfficeConn]
            assocDevHardware = pythClasses.ns.SysExecution()
            assocDevHardware.hostHardware = [plexigridDevHardware]
            assocDevHardware.sysExecutedApps=[plexigridDevOffice]
            # Vulnerability to devs office zone
            assocVulnHardwareDev = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDev.vulnerabilities = [plexigridDevHardwarevuln]
            assocVulnHardwareDev.hardware = [plexigridDevHardware]
            # Add sales office to sales network
            assocConnSalesOffice = pythClasses.ns.NetworkConnection()
            assocConnSalesOffice.networks = [plexiSalesNetwork]
            assocConnSalesOffice.netConnections = [plexigridSalesOfficeConn]
            assocConnOfficeSales = pythClasses.ns.ApplicationConnection()
            assocConnOfficeSales.applications = [plexigridSalesOffice]
            assocConnOfficeSales.appConnections = [plexigridSalesOfficeConn]
            assocSalesHardware = pythClasses.ns.SysExecution()
            assocSalesHardware.hostHardware = [plexigridSalesHardware]
            assocSalesHardware.sysExecutedApps=[plexigridSalesOffice]
            # Vulnerability to sales office zone
            assocVulnHardwareSales = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareSales.vulnerabilities = [plexigridSalesHardwarevuln]
            assocVulnHardwareSales.hardware = [plexigridSalesHardware]
            # Add identity to sales mail server
            assocIdentityMail = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityMail.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityMail.execPrivApps = [plexigridSalesMail]
            # Add identity to Sales office so they have the same privs
            assocIdentityOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityOffice.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityOffice.execPrivApps = [plexigridSalesOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexiSalesConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewalls dev sales
            assocSalesDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocSalesDevFirewall.connectionRules = [plexiInternalConn]
            assocSalesDevFirewall.routingFirewalls = [plexiSalesDevFirewall]
            # Vulnerability firewall
            assocSalesDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesDevFirewallVuln.application = [plexiSalesDevFirewall]
            assocSalesDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallSalesDev]
            # Send data from Sales mail to Dev mail
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesMail]
            assocSendSales.sentData = [plexigridDataDSO]
            # receive data to Dev mail from sales mail
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevMail]
            assocRecDevs.receivedData = [plexigridDataDSO]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataDSO]
            # Receive data from DSO to Sales
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSalesMail]
            assocDSOSales.receivedData = [plexigridDataDSO]
            # Add every association to the model
            honorModel.add_association(assocConnSalesnetwork)
            honorModel.add_association(assocConnSalesnetworkInternet)
            honorModel.add_association(assocConnDevnetwork)
            honorModel.add_association(assocVulnSales)
            honorModel.add_association(assocVulnDevs)
            honorModel.add_association(assocSendSales)
            honorModel.add_association(assocRecDevs)
            honorModel.add_association(assocDataSales)
            honorModel.add_association(assocDataDev)
            honorModel.add_association(assocDSOSales)
            honorModel.add_association(assocConnMailDev)
            honorModel.add_association(assocConnDevMail)
            honorModel.add_association(assocConnSalesMail)
            honorModel.add_association(assocConnMailSales)
            honorModel.add_association(assocIdentityMail)
            honorModel.add_association(assocIdentityUser)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocConnSalesOffice)
            honorModel.add_association(assocConnOfficeSales)
            honorModel.add_association(assocIdentityOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetSalesFirewall)
            honorModel.add_association(assocSalesDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            honorModel.add_association(assocSalesDevFirewallVuln)
        

################################################## Test 2 ########################################################################       

        if test_case2:
            # Add onedrive to cloud network
            assocConnOneDriveCloud = pythClasses.ns.NetworkConnection()
            assocConnOneDriveCloud.networks = [cloudNetwork]
            assocConnOneDriveCloud.netConnections = [plexiCloudOneDriveConn]
            assocConnCloudOneDrive = pythClasses.ns.ApplicationConnection()
            assocConnCloudOneDrive.applications = [cloudOneDrive]
            assocConnCloudOneDrive.appConnections = [plexiCloudOneDriveConn]
            # Vulnerability to OneDrive
            assocVulnOneDrive = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnOneDrive.application = [cloudOneDrive]
            assocVulnOneDrive.vulnerabilities = [vulnerabilityOneDrive]
            # Add Cloud to internet
            assocCloudInternet = pythClasses.ns.NetworkConnection()
            assocCloudInternet.networks = [cloudNetwork]
            assocCloudInternet.netConnections = [CloudInternetConn]
            # Add networkconnections project/sales 
            assocConnSalesnetwork = pythClasses.ns.NetworkConnection()
            assocConnSalesnetwork.networks = [plexiSalesNetwork]
            assocConnSalesnetwork.netConnections = [plexiInternalConn]
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections Development
            assocConnDevnetwork = pythClasses.ns.NetworkConnection()
            assocConnDevnetwork.networks = [plexiDevNetwork]
            assocConnDevnetwork.netConnections = [plexiInternalConn]
            # Add Sales mail server to network
            assocConnSalesMail = pythClasses.ns.NetworkConnection()
            assocConnSalesMail.networks = [plexiSalesNetwork]
            assocConnSalesMail.netConnections = [plexiMailSalesConn]
            assocConnMailSales = pythClasses.ns.ApplicationConnection()
            assocConnMailSales.applications = [plexigridSalesMail]
            assocConnMailSales.appConnections = [plexiMailSalesConn]
            # Add softwarevuln. to sales mail server
            assocVulnSales = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSales.application = [plexigridSalesMail]
            assocVulnSales.vulnerabilities = [vulnerabilitySalesMail]
            # Add dev office to dev network
            assocConnDevOffice = pythClasses.ns.NetworkConnection()
            assocConnDevOffice.networks = [plexiDevNetwork]
            assocConnDevOffice.netConnections = [plexigridDevOfficeConn]
            assocConnOfficeDev = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDev.applications = [plexigridDevOffice]
            assocConnOfficeDev.appConnections = [plexigridDevOfficeConn]
            assocDevHardware = pythClasses.ns.SysExecution()
            assocDevHardware.hostHardware = [plexigridDevHardware]
            assocDevHardware.sysExecutedApps=[plexigridDevOffice]
            # Vulnerability to devs office zone
            assocVulnHardwareDev = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDev.vulnerabilities = [plexigridDevHardwarevuln]
            assocVulnHardwareDev.hardware = [plexigridDevHardware]
            # Add sales office to sales network
            assocConnSalesOffice = pythClasses.ns.NetworkConnection()
            assocConnSalesOffice.networks = [plexiSalesNetwork]
            assocConnSalesOffice.netConnections = [plexigridSalesOfficeConn]
            assocConnOfficeSales = pythClasses.ns.ApplicationConnection()
            assocConnOfficeSales.applications = [plexigridSalesOffice]
            assocConnOfficeSales.appConnections = [plexigridSalesOfficeConn]
            assocSalesHardware = pythClasses.ns.SysExecution()
            assocSalesHardware.hostHardware = [plexigridSalesHardware]
            assocSalesHardware.sysExecutedApps=[plexigridSalesOffice]
            # Vulnerability to sales office zone
            assocVulnHardwareSales = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareSales.vulnerabilities = [plexigridSalesHardwarevuln]
            assocVulnHardwareSales.hardware = [plexigridSalesHardware]
            # Add identity to sales mail server
            assocIdentityMail = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityMail.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityMail.execPrivApps = [plexigridSalesMail]
            # Add identity to Sales office so they have the same privs
            assocIdentityOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityOffice.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityOffice.execPrivApps = [plexigridSalesOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexiSalesConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewalls dev sales
            assocSalesDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocSalesDevFirewall.connectionRules = [plexiInternalConn]
            assocSalesDevFirewall.routingFirewalls = [plexiSalesDevFirewall]
            # Vulnerability firewall
            assocSalesDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesDevFirewallVuln.application = [plexiSalesDevFirewall]
            assocSalesDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallSalesDev]
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataDSO]
            # receive data to oneDrive from sales office
            assocRecOnedrive = pythClasses.ns.ReceiveData()
            assocRecOnedrive.receiverApp = [cloudOneDrive]
            assocRecOnedrive.receivedData = [plexigridDataDSO]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDSO]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataDSO]
            # The data is accessable from the whole cloud network
            assocDataCloud = pythClasses.ns.DataInTransit()
            assocDataCloud.transitNetwork = [cloudNetwork]
            assocDataCloud.transitData = [plexigridDataDSO]
            # Receive data from DSO to Sales
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSalesMail]
            assocDSOSales.receivedData = [plexigridDataDSO]
           
            # Add every association to the model
            honorModel.add_association(assocConnSalesnetwork)
            honorModel.add_association(assocConnSalesnetworkInternet)
            honorModel.add_association(assocConnDevnetwork)
            honorModel.add_association(assocVulnSales)
            honorModel.add_association(assocSendSales)
            honorModel.add_association(assocRecDevs)
            honorModel.add_association(assocDataSales)
            honorModel.add_association(assocDataDev)
            honorModel.add_association(assocDSOSales)
            honorModel.add_association(assocConnSalesMail)
            honorModel.add_association(assocConnMailSales)
            honorModel.add_association(assocIdentityMail)
            honorModel.add_association(assocIdentityUser)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocConnSalesOffice)
            honorModel.add_association(assocConnOfficeSales)
            honorModel.add_association(assocIdentityOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetSalesFirewall)
            honorModel.add_association(assocSalesDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            honorModel.add_association(assocSalesDevFirewallVuln)
            honorModel.add_association(assocConnCloudOneDrive)
            honorModel.add_association(assocConnOneDriveCloud)
            honorModel.add_association(assocVulnOneDrive)
            honorModel.add_association(assocCloudInternet)
            honorModel.add_association(assocDataCloud)
            honorModel.add_association(assocRecOnedrive)
            
################################################## Test 3 ########################################################################
        if test_case3:
           # Add SFTP to Sales network
            assocConnSftpSalesNetwork = pythClasses.ns.NetworkConnection()
            assocConnSftpSalesNetwork.networks = [plexiSalesNetwork]
            assocConnSftpSalesNetwork.netConnections = [plexiSFTPConn]
            assocConnSftpSales = pythClasses.ns.ApplicationConnection()
            assocConnSftpSales.applications = [plexigridSftp]
            assocConnSftpSales.appConnections = [plexiSFTPConn]
            # Add softwareVuln. to SFTP
            assocVulnSFTP = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSFTP.application = [plexigridSftp]
            assocVulnSFTP.vulnerabilities = [vulnerabilitySftp]
            # Add credentials to meteringData
            assocEncData = pythClasses.ns.EncryptionCredentials()
            assocEncData.encryptCreds = [DSOCreds]
            assocEncData.encryptedData = [plexigridDataDSO]
            # Add credentials data to credentials
            assocCredData = pythClasses.ns.InfoContainment()
            assocCredData.containerData = [DSOEncryptedCreds]
            assocCredData.information = [DSOCreds]
            # Add credData to SFTP
            assocCredSFTP = pythClasses.ns.AppContainment()
            assocCredSFTP.containedData = [DSOEncryptedCreds]
            assocCredSFTP.containingApp = [plexigridSftp]
            # Add replicated information to unencrypted data(PM)
            assocEncryptedData = pythClasses.ns.Replica()
            assocEncryptedData.replicatedInformation = [replicatedMeterData]
            assocEncryptedData.dataReplicas = [plexigridDataPM]
            # Add replicated information to unencrypted data(PM)
            assocUnencryptedData = pythClasses.ns.Replica()
            assocUnencryptedData.replicatedInformation = [replicatedMeterData]
            assocUnencryptedData.dataReplicas = [plexigridDataDSO]
            # Add networkconnections project/sales 
            assocConnSalesnetwork = pythClasses.ns.NetworkConnection()
            assocConnSalesnetwork.networks = [plexiSalesNetwork]
            assocConnSalesnetwork.netConnections = [plexiInternalConn]
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections Development
            assocConnDevnetwork = pythClasses.ns.NetworkConnection()
            assocConnDevnetwork.networks = [plexiDevNetwork]
            assocConnDevnetwork.netConnections = [plexiInternalConn]
            # Add Sales mail server to network
            assocConnSalesMail = pythClasses.ns.NetworkConnection()
            assocConnSalesMail.networks = [plexiSalesNetwork]
            assocConnSalesMail.netConnections = [plexiMailSalesConn]
            assocConnMailSales = pythClasses.ns.ApplicationConnection()
            assocConnMailSales.applications = [plexigridSalesMail]
            assocConnMailSales.appConnections = [plexiMailSalesConn]
            # Add softwarevuln. to sales mail server
            assocVulnSales = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSales.application = [plexigridSalesMail]
            assocVulnSales.vulnerabilities = [vulnerabilitySalesMail]
            # Add devs mail server to network
            assocConnDevMail = pythClasses.ns.NetworkConnection()
            assocConnDevMail.networks = [plexiDevNetwork]
            assocConnDevMail.netConnections = [plexiMailDevConn]
            assocConnMailDev = pythClasses.ns.ApplicationConnection()
            assocConnMailDev.applications = [plexigridDevMail]
            assocConnMailDev.appConnections = [plexiMailDevConn]
            # Add softwarevuln. to devs mail server
            assocVulnDevs = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnDevs.application = [plexigridDevMail]
            assocVulnDevs.vulnerabilities = [vulnerabilityDevMail]
            # Add dev office to dev network
            assocConnDevOffice = pythClasses.ns.NetworkConnection()
            assocConnDevOffice.networks = [plexiDevNetwork]
            assocConnDevOffice.netConnections = [plexigridDevOfficeConn]
            assocConnOfficeDev = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDev.applications = [plexigridDevOffice]
            assocConnOfficeDev.appConnections = [plexigridDevOfficeConn]
            assocDevHardware = pythClasses.ns.SysExecution()
            assocDevHardware.hostHardware = [plexigridDevHardware]
            assocDevHardware.sysExecutedApps=[plexigridDevOffice]
            # Vulnerability to devs office zone
            assocVulnHardwareDev = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDev.vulnerabilities = [plexigridDevHardwarevuln]
            assocVulnHardwareDev.hardware = [plexigridDevHardware]
            # Add sales office to sales network
            assocConnSalesOffice = pythClasses.ns.NetworkConnection()
            assocConnSalesOffice.networks = [plexiSalesNetwork]
            assocConnSalesOffice.netConnections = [plexigridSalesOfficeConn]
            assocConnOfficeSales = pythClasses.ns.ApplicationConnection()
            assocConnOfficeSales.applications = [plexigridSalesOffice]
            assocConnOfficeSales.appConnections = [plexigridSalesOfficeConn]
            assocSalesHardware = pythClasses.ns.SysExecution()
            assocSalesHardware.hostHardware = [plexigridSalesHardware]
            assocSalesHardware.sysExecutedApps=[plexigridSalesOffice]
            # Vulnerability to sales office zone
            assocVulnHardwareSales = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareSales.vulnerabilities = [plexigridSalesHardwarevuln]
            assocVulnHardwareSales.hardware = [plexigridSalesHardware]
            # Add identity to sales mail server
            assocIdentityMail = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityMail.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityMail.execPrivApps = [plexigridSalesMail]
            # Add identity to Sales office so they have the same privs
            assocIdentityOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityOffice.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityOffice.execPrivApps = [plexigridSalesOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexiSalesConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewalls dev sales
            assocSalesDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocSalesDevFirewall.connectionRules = [plexiInternalConn]
            assocSalesDevFirewall.routingFirewalls = [plexiSalesDevFirewall]
            # Vulnerability firewall
            assocSalesDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesDevFirewallVuln.application = [plexiSalesDevFirewall]
            assocSalesDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallSalesDev]
            # Send data from Sales to Dev mail
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesMail]
            assocSendSales.sentData = [plexigridDataPM]
            # receive data to Dev mail from sales mail
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevMail]
            assocRecDevs.receivedData = [plexigridDataPM]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataPM]
            # Receive data from DSO to SFTP
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSftp]
            assocDSOSales.receivedData = [plexigridDataDSO]
            # Add every association to the model
            honorModel.add_association(assocConnSalesnetwork)
            honorModel.add_association(assocConnSalesnetworkInternet)
            honorModel.add_association(assocConnDevnetwork)
            honorModel.add_association(assocVulnSales)
            honorModel.add_association(assocVulnDevs)
            honorModel.add_association(assocSendSales)
            honorModel.add_association(assocRecDevs)
            honorModel.add_association(assocDataSales)
            honorModel.add_association(assocDataDev)
            honorModel.add_association(assocDSOSales)
            honorModel.add_association(assocConnMailDev)
            honorModel.add_association(assocConnDevMail)
            honorModel.add_association(assocConnSalesMail)
            honorModel.add_association(assocConnMailSales)
            honorModel.add_association(assocIdentityMail)
            honorModel.add_association(assocIdentityUser)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocConnSalesOffice)
            honorModel.add_association(assocConnOfficeSales)
            honorModel.add_association(assocIdentityOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetSalesFirewall)
            honorModel.add_association(assocSalesDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            honorModel.add_association(assocSalesDevFirewallVuln)
            honorModel.add_association(assocConnSftpSalesNetwork)
            honorModel.add_association(assocConnSftpSales)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredSFTP)
            honorModel.add_association(assocVulnSFTP)
            honorModel.add_association(assocEncryptedData)
            honorModel.add_association(assocUnencryptedData)
 ################################################## Test 4 ########################################################################       
        if test_case4:
             # Add onedrive to cloud network
            assocConnOneDriveCloud = pythClasses.ns.NetworkConnection()
            assocConnOneDriveCloud.networks = [cloudNetwork]
            assocConnOneDriveCloud.netConnections = [plexiCloudOneDriveConn]
            assocConnCloudOneDrive = pythClasses.ns.ApplicationConnection()
            assocConnCloudOneDrive.applications = [cloudOneDrive]
            assocConnCloudOneDrive.appConnections = [plexiCloudOneDriveConn]
            # Vulnerability to OneDrive
            assocVulnOneDrive = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnOneDrive.application = [cloudOneDrive]
            assocVulnOneDrive.vulnerabilities = [vulnerabilityOneDrive]
            # Add Cloud to internet
            assocCloudInternet = pythClasses.ns.NetworkConnection()
            assocCloudInternet.networks = [cloudNetwork]
            assocCloudInternet.netConnections = [CloudInternetConn]
            # Add SFTP to Sales network
            assocConnSftpSalesNetwork = pythClasses.ns.NetworkConnection()
            assocConnSftpSalesNetwork.networks = [plexiSalesNetwork]
            assocConnSftpSalesNetwork.netConnections = [plexiSFTPConn]
            assocConnSftpSales = pythClasses.ns.ApplicationConnection()
            assocConnSftpSales.applications = [plexigridSftp]
            assocConnSftpSales.appConnections = [plexiSFTPConn]
            # Add softwareVuln. to SFTP
            assocVulnSFTP = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSFTP.application = [plexigridSftp]
            assocVulnSFTP.vulnerabilities = [vulnerabilitySftp]
            # Add credentials to meteringData
            assocEncData = pythClasses.ns.EncryptionCredentials()
            assocEncData.encryptCreds = [DSOCreds]
            assocEncData.encryptedData = [plexigridDataDSO]
            # Add credentials data to credentials
            assocCredData = pythClasses.ns.InfoContainment()
            assocCredData.containerData = [DSOEncryptedCreds]
            assocCredData.information = [DSOCreds]
            # Add credData to SFTP
            assocCredSFTP = pythClasses.ns.AppContainment()
            assocCredSFTP.containedData = [DSOEncryptedCreds]
            assocCredSFTP.containingApp = [plexigridSftp]
            # Add replicated information to unencrypted data(PM)
            assocEncryptedData = pythClasses.ns.Replica()
            assocEncryptedData.replicatedInformation = [replicatedMeterData]
            assocEncryptedData.dataReplicas = [plexigridDataPM]
            # Add replicated information to encrypted data(PM)
            assocUnencryptedData = pythClasses.ns.Replica()
            assocUnencryptedData.replicatedInformation = [replicatedMeterData]
            assocUnencryptedData.dataReplicas = [plexigridDataDSO]
            # Add networkconnections project/sales 
            assocConnSalesnetwork = pythClasses.ns.NetworkConnection()
            assocConnSalesnetwork.networks = [plexiSalesNetwork]
            assocConnSalesnetwork.netConnections = [plexiInternalConn]
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections Development
            assocConnDevnetwork = pythClasses.ns.NetworkConnection()
            assocConnDevnetwork.networks = [plexiDevNetwork]
            assocConnDevnetwork.netConnections = [plexiInternalConn]
            # Add dev office to dev network
            assocConnDevOffice = pythClasses.ns.NetworkConnection()
            assocConnDevOffice.networks = [plexiDevNetwork]
            assocConnDevOffice.netConnections = [plexigridDevOfficeConn]
            assocConnOfficeDev = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDev.applications = [plexigridDevOffice]
            assocConnOfficeDev.appConnections = [plexigridDevOfficeConn]
            assocDevHardware = pythClasses.ns.SysExecution()
            assocDevHardware.hostHardware = [plexigridDevHardware]
            assocDevHardware.sysExecutedApps=[plexigridDevOffice]
            # Vulnerability to devs office zone
            assocVulnHardwareDev = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDev.vulnerabilities = [plexigridDevHardwarevuln]
            assocVulnHardwareDev.hardware = [plexigridDevHardware]
            # Add sales office to sales network
            assocConnSalesOffice = pythClasses.ns.NetworkConnection()
            assocConnSalesOffice.networks = [plexiSalesNetwork]
            assocConnSalesOffice.netConnections = [plexigridSalesOfficeConn]
            assocConnOfficeSales = pythClasses.ns.ApplicationConnection()
            assocConnOfficeSales.applications = [plexigridSalesOffice]
            assocConnOfficeSales.appConnections = [plexigridSalesOfficeConn]
            assocSalesHardware = pythClasses.ns.SysExecution()
            assocSalesHardware.hostHardware = [plexigridSalesHardware]
            assocSalesHardware.sysExecutedApps=[plexigridSalesOffice]
            # Vulnerability to sales office zone
            assocVulnHardwareSales = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareSales.vulnerabilities = [plexigridSalesHardwarevuln]
            assocVulnHardwareSales.hardware = [plexigridSalesHardware]
            # Add identity to Sftp
            assocIdentitySftp = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentitySftp.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentitySftp.execPrivApps = [plexigridSftp]
            # Add identity to Sales office so they have the same privs
            assocIdentityOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityOffice.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityOffice.execPrivApps = [plexigridSalesOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexiSalesConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewalls dev sales
            assocSalesDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocSalesDevFirewall.connectionRules = [plexiInternalConn]
            assocSalesDevFirewall.routingFirewalls = [plexiSalesDevFirewall]
            # Vulnerability firewall
            assocSalesDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesDevFirewallVuln.application = [plexiSalesDevFirewall]
            assocSalesDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallSalesDev]
            # Send data from Sales to Dev mail
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataPM]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataPM]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataPM]
            # The data is accessable from the whole Dev network
            assocDataCloud = pythClasses.ns.DataInTransit()
            assocDataCloud.transitNetwork = [cloudNetwork]
            assocDataCloud.transitData = [plexigridDataPM]
            # Receive data from DSO to SFTP
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSftp]
            assocDSOSales.receivedData = [plexigridDataDSO]
            # The onedrive will contain the data
            assocCloudContainData = pythClasses.ns.AppContainment()
            assocCloudContainData.containedData = [plexigridDataPM]
            assocCloudContainData.containingApp = [cloudOneDrive]
            # Add every association to the model
            honorModel.add_association(assocConnSalesnetwork)
            honorModel.add_association(assocConnSalesnetworkInternet)
            honorModel.add_association(assocConnDevnetwork)
            honorModel.add_association(assocSendSales)
            honorModel.add_association(assocRecDevs)
            honorModel.add_association(assocDataSales)
            honorModel.add_association(assocDataDev)
            honorModel.add_association(assocDSOSales)
            honorModel.add_association(assocIdentityUser)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocConnSalesOffice)
            honorModel.add_association(assocConnOfficeSales)
            honorModel.add_association(assocIdentityOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetSalesFirewall)
            honorModel.add_association(assocSalesDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            honorModel.add_association(assocSalesDevFirewallVuln)
            honorModel.add_association(assocConnSftpSalesNetwork)
            honorModel.add_association(assocConnSftpSales)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredSFTP)
            honorModel.add_association(assocIdentitySftp)
            honorModel.add_association(assocVulnSFTP)
            honorModel.add_association(assocEncryptedData)
            honorModel.add_association(assocUnencryptedData)
            honorModel.add_association(assocDataCloud)
            honorModel.add_association(assocConnOneDriveCloud)
            honorModel.add_association(assocConnCloudOneDrive)
            honorModel.add_association(assocVulnOneDrive)
            honorModel.add_association(assocCloudInternet)
            honorModel.add_association(assocCloudContainData)
        
            """
            # Connect to HONOR-model
            """  
    if addToHonorModel:
################################################## Test 1 ########################################################################
        if test_case1:
            # connect sales network to the internet
            assocSalesDSO = pythClasses.ns.NetworkConnection()
            internet = honorModel.get_asset_by_id(8103222226739678984)
            assocSalesDSO.networks = [internet]
            assocSalesDSO.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevDSO = pythClasses.ns.NetworkConnection()
            assocDevDSO.networks = [internet]
            assocDevDSO.netConnections = [plexiDevConn]
            # Data will be in transit through the internet(Email)
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data will be sent from DSO mail server to sales Mail server
            DSOMail = honorModel.get_asset_by_id(1007211369537407)
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOMail]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Add every association to the model
            honorModel.add_association(assocSalesDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocDevDSO)
            honorModel.save_to_file("./TestCases/case1.json")
################################################## Test 2 ########################################################################      
        if test_case2:
            # connect sales network to the internet
            assocSalesDSO = pythClasses.ns.NetworkConnection()
            internet = honorModel.get_asset_by_id(8103222226739678984)
            assocSalesDSO.networks = [internet]
            assocSalesDSO.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevDSO = pythClasses.ns.NetworkConnection()
            assocDevDSO.networks = [internet]
            assocDevDSO.netConnections = [plexiDevConn]
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]
            # Data will be in transit through the internet(Email)
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data will be sent from DSO mail server to sales Mail server
            DSOMail = honorModel.get_asset_by_id(1007211369537407)
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOMail]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Add every association to the model
            honorModel.add_association(assocSalesDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocInternetCloud)
            honorModel.add_association(assocDevDSO)
            honorModel.save_to_file("./TestCases/case2.json")
################################################## Test 3 ########################################################################
        if test_case3:
            # connect sales network to the internet
            assocSalesDSO = pythClasses.ns.NetworkConnection()
            internet = honorModel.get_asset_by_id(8103222226739678984)
            assocSalesDSO.networks = [internet]
            assocSalesDSO.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevDSO = pythClasses.ns.NetworkConnection()
            assocDevDSO.networks = [internet]
            assocDevDSO.netConnections = [plexiDevConn]
            # Data will be in transit through the internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data will be sent from DSO office station to sales SFTP server
            DSO_office = honorModel.get_asset_by_id(7480460796777191)
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSO_office]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be in transit through the internet
            assocDataInternet2= pythClasses.ns.DataInTransit()
            assocDataInternet2.transitNetwork = [internet]
            assocDataInternet2.transitData = [plexigridDataPM]
            # Add credData to SFTP
            assocCredSDSO = pythClasses.ns.AppContainment()
            assocCredSDSO.containedData = [DSOEncryptedCreds]
            assocCredSDSO.containingApp = [DSO_office]
            # Add every association to the model
            honorModel.add_association(assocSalesDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocDataInternet2)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocCredSDSO)
            honorModel.add_association(assocDevDSO)
            honorModel.save_to_file("./TestCases/case3.json")
################################################## Test 4 ########################################################################
        if test_case4:
            # connect sales network to the internet
            assocSalesDSO = pythClasses.ns.NetworkConnection()
            internet = honorModel.get_asset_by_id(8103222226739678984)
            assocSalesDSO.networks = [internet]
            assocSalesDSO.netConnections = [plexiSalesConn]
             # connect dev network to the internet
            assocDevDSO = pythClasses.ns.NetworkConnection()
            assocDevDSO.networks = [internet]
            assocDevDSO.netConnections = [plexiDevConn]
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]
            # Data will be in transit through the internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data will be sent from DSO office station to sales SFTP server
            DSO_office = honorModel.get_asset_by_id(7480460796777191)
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSO_office]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be in transit through the internet
            assocDataInternet2= pythClasses.ns.DataInTransit()
            assocDataInternet2.transitNetwork = [internet]
            assocDataInternet2.transitData = [plexigridDataPM]
            # Add credData to SFTP
            assocCredSDSO = pythClasses.ns.AppContainment()
            assocCredSDSO.containedData = [DSOEncryptedCreds]
            assocCredSDSO.containingApp = [DSO_office]
        
            # Add every association to the model
            honorModel.add_association(assocSalesDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocDataInternet2)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocCredSDSO)
            honorModel.add_association(assocInternetCloud)
            honorModel.add_association(assocDevDSO)
            honorModel.save_to_file("./TestCases/case4.json")