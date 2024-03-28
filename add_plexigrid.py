
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
add_association = True
add_assets = True
# Use the whole DSO
addToHonorModel = False
# Use the relevant parts of the DSO
addDSO = True

# Email->Email
test_case1 = False
# Email->Onedrive
test_case2 = True
#SFTP-> Email
test_case3 = False
#SFTP->Onedrive
test_case4 = False
# DSO SFTP-> database (skip PM)
test_case5 = False
# DSO OneDrive -> database (skip PM)
test_case6 = False

def add_plexigrid_assets(pythClasses, honorModel):
    if add_assets:
################################################## Test 1 ########################################################################       
        if test_case1:
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network"
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
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Sales Office station"
            plexigridSalesOffice.supplyChainAuditing = 1

            # Add pm sophos security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "Sophos"
            plexigridSalesIDPS.supplyChainAuditing = 1
            # Add pm sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            # Replicated information (to symbolize the same data)
            replicatedMeterDatatoDatabase = pythClasses.ns.Information()
            replicatedMeterDatatoDatabase.metaconcept = "Information"
            replicatedMeterDatatoDatabase.name = "Metering Information"
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
    


            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            # Identity symbolyzing a regular User
            plexigridRegularIdentity = pythClasses.ns.Identity()
            plexigridRegularIdentity.metaconcept = "Identity"
            plexigridRegularIdentity.name = "Regular User"
            # User symbolyzing the real human (PM)
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User" 


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
            plexigridDevOffice.name = "Devs Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Mail-Server for Plexigrid project/sales
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
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
            plexigridDevMail.name = "mail server"
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
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(plexiDevConn)

            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(plexigridRegularIdentity)
            honorModel.add_asset(vulnerabilityOfficeSales)
            honorModel.add_asset(vulnerabilityOfficeDev)                        
            
            honorModel.add_asset(plexigridSalesIDPS)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(plexidatabasecloudconn)
            honorModel.add_asset(SSHCreds)
            honorModel.add_asset(SSHEncryptedCreds)
            honorModel.add_asset(replicatedMeterDatatoDatabase)
            honorModel.add_asset(plexigridDataSSH)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

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
            CloudInternetConn.restricted = 0.8 # ports on the computer that are blocked
            CloudInternetConn.payloadInspection = 0.9 # Microsoft has IDPS or firewall that try to filter malicous payloads
            # OneDrive for Plexigrid project/sales
            cloudOneDrive = pythClasses.ns.Application()
            cloudOneDrive.metaconcept = "Application"
            cloudOneDrive.name = "OneDrive"
            # connection between cloud network and OneDrive
            plexiCloudOneDriveConn = pythClasses.ns.ConnectionRule()
            plexiCloudOneDriveConn.metaconcept = "ConnectionRule"
            plexiCloudOneDriveConn.name = "ConnectionRule"
            # Software vulnreability for OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability OneDrive"
            vulnerabilityOneDrive.highComplexityExploitRequired = 0.95 # needs really advanced exploits
            vulnerabilityOneDrive.confidentialityImpactLimitations = 0.95 # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilityOneDrive.availabilityImpactLimitations = 0.95 # microsoft have great resources, related to deny
            vulnerabilityOneDrive.integrityImpactLimitations = 0.95 # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilityOneDrive.highPrivilegesRequired = 1 # need admin access to change anything (microsoft staff)
            vulnerabilityOneDrive.highPrivilegesRequired = 1 # need admin access to change anything (microsoft staff)
            vulnerabilityOneDrive.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network"
            # connection between Plexi project/sales and internet
            plexiSalesConn = pythClasses.ns.ConnectionRule()
            plexiSalesConn.metaconcept = "ConnectionRule"
            plexiSalesConn.name = "ConnectionRule internet"
            # connection between Plexi dev and internet
            plexiDevConn = pythClasses.ns.ConnectionRule()
            plexiDevConn.metaconcept = "ConnectionRule"
            plexiDevConn.name = "ConnectionRule internet"
            # connection between cloud network and sales(microsoft) mail server
            plexiMailSalesConn = pythClasses.ns.ConnectionRule()
            plexiMailSalesConn.metaconcept = "ConnectionRule"
            plexiMailSalesConn.name = "ConnectionRule"
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            plexigridDevOfficeConn.restricted = 0.6 # ports on the computer that are blocked
            plexigridDevOfficeConn.payloadInspection = 0.7 # Sophos try to filter malicous payloads
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"

            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeSales.highComplexityExploitRequired = 0.8 # difficult but not more than microsoft
            vulnerabilityOfficeSales.userInteractionRequired = 1 # The user has to click something malicious
            vulnerabilityOfficeSales.highPrivilegesRequired = 1 # Need to have admin role
            vulnerabilityOfficeSales.localAccessRequired = 1 # Need network access to exploit
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeDev.highComplexityExploitRequired = 0.8 # difficult but not more than microsoft
            vulnerabilityOfficeDev.userInteractionRequired = 1 # The user has to click something malicious
            vulnerabilityOfficeDev.highPrivilegesRequired = 1 # Need to have admin role
            vulnerabilityOfficeDev.localAccessRequired = 1 # Need network access to exploit
            # User symbolyzing the real human 
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User"
            plexigridRegularUser.securityAwareness = 0.5
            # Add pm sophos security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "Sophos"
            plexigridSalesIDPS.supplyChainAuditing = 1
            plexigridSalesIDPS.effectiveness = 0.6
            # Add dev sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
            plexigridDevIDPS.effectiveness = 0.6
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.confidentialityImpactLimitations = 0.95 # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.availabilityImpactLimitations = 0.95 # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.integrityImpactLimitations = 0.95 # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.effortRequiredToExploit = 1
            
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            SSHCreds.notGuessable = 1 # Almost impossible to guess 
            SSHCreds.unique = 1 # completely unique
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            # Replicated information (to symbolize the same data)
            replicatedMeterDatatoDatabase = pythClasses.ns.Information()
            replicatedMeterDatatoDatabase.metaconcept = "Information"
            replicatedMeterDatatoDatabase.name = "Metering Information"
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
            # Add credentials to the dev identity connected to onedrive
            OneDriveDevCreds = pythClasses.ns.Credentials()
            OneDriveDevCreds.metaconcept = "Credentials"
            OneDriveDevCreds.name = "Password/Username" 
            OneDriveDevCreds.notGuessable = 0.6 # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveDevCreds.unique = 0.8 # assume that the password is not used for multiple services
            # Add MFA to this identity
            OneDriveMFADevCreds = pythClasses.ns.Credentials()
            OneDriveMFADevCreds.metaconcept = "Credentials"
            OneDriveMFADevCreds.name = "MFA"
            OneDriveMFADevCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            OneDriveMFADevCreds.unique = 1
            # Add credentials to the sales identity connected to onedrive
            OneDriveSalesCreds = pythClasses.ns.Credentials()
            OneDriveSalesCreds.metaconcept = "Credentials"
            OneDriveSalesCreds.name = "Password/Username" 
            OneDriveSalesCreds.notGuessable = 0.6 # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveSalesCreds.unique = 0.8 # assume that the password is not used for multiple services
            # Add MFA to this identity
            OneDriveMFASalesCreds = pythClasses.ns.Credentials()
            OneDriveMFASalesCreds.metaconcept = "Credentials"
            OneDriveMFASalesCreds.name = "MFA"
            OneDriveMFASalesCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            OneDriveMFASalesCreds.unique = 1 # unique
            # Add identity that the dev user use for OneDrive
            plexigridDevOneDriveIdentity = pythClasses.ns.Identity()
            plexigridDevOneDriveIdentity.metaconcept = "Identity"
            plexigridDevOneDriveIdentity.name = "Dev Identity"
            # Add metering data from PM-> Onedrive
            plexigridDataPMOneDrive = pythClasses.ns.Data()
            plexigridDataPMOneDrive.metaconcept = "Data"
            plexigridDataPMOneDrive.name = "Metering Data"
            # Add encryption keys to meter
            PMOneDriveCreds = pythClasses.ns.Credentials()
            PMOneDriveCreds.metaconcept = "Credentials"
            PMOneDriveCreds.name = "Encryption keys"
            PMOneDriveCreds.notGuessable = 1 # Almost impossible to guess 
            PMOneDriveCreds.unique = 1 # completely unique
            # Add encryption keys data between OneDrive and PM
            PMOneDriveEncryptedCreds = pythClasses.ns.Data()
            PMOneDriveEncryptedCreds.metaconcept = "Data"
            PMOneDriveEncryptedCreds.name = "Encrypted keys data"
            # Add metering data from OneDrive -> Dev 
            plexigridDataDevOneDrive = pythClasses.ns.Data()
            plexigridDataDevOneDrive.metaconcept = "Data"
            plexigridDataDevOneDrive.name = "Metering Data"
            # Add encryption keys data between OneDrive and Dev
            DevOneDriveCreds = pythClasses.ns.Credentials()
            DevOneDriveCreds.metaconcept = "Credentials"
            DevOneDriveCreds.name = "Encryption keys"
            DevOneDriveCreds.notGuessable = 1 # Almost impossible to guess 
            DevOneDriveCreds.unique = 1 # completely unique
            # Credentials data
            DevOneDriveEncryptedCreds = pythClasses.ns.Data()
            DevOneDriveEncryptedCreds.metaconcept = "Data"
            DevOneDriveEncryptedCreds.name = "Encrypted keys data"
            
            
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "PM's Office station"
            plexigridSalesOffice.supplyChainAuditing = 1
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = 1 # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = 1 # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Devs Office station"
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            plexigridSalesOfficeConn.restricted = 0.6 # ports on the computer that are blocked
            plexigridSalesOfficeConn.payloadInspection = 0.7 # Sophos try to filter malicous payloads
            # Mail-Server for Plexigrid project/sales (microsoft server)
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            plexigridPMUser.securityAwareness = 0.5 # not very aware
            # Software vulnreability for Project/sales mail microsoft server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            vulnerabilitySalesMail.highComplexityExploitRequired = 0.95 # needs really advanced exploits
            vulnerabilitySalesMail.confidentialityImpactLimitations = 0.95 # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilitySalesMail.availabilityImpactLimitations = 0.95 # microsoft have great resources, related to deny
            vulnerabilitySalesMail.integrityImpactLimitations = 0.95 # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilitySalesMail.highPrivilegesRequired = 1 # need admin access to change anything (microsoft staff)
            vulnerabilitySalesMail.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"
            # Unencrypted metering Data
            # unencryptedData = pythClasses.ns.Data()
            # unencryptedData.metaconcept = "Data"
            # unencryptedData.name = "Unencrypted Metering Data"

            # Credentials to private dev office station
            plexidevCredentials = pythClasses.ns.Credentials()
            plexidevCredentials.metaconcept = "Credentials"
            plexidevCredentials.name = "Password/Username" 
            plexidevCredentials.notGuessable = 0.6 # How hard it is to guess the password (not a part of the most common password dictionary)
            plexidevCredentials.unique = 0.8 # assume that the password is not used for multiple services
            # Identity dev to office station
            plexiDevIdentityOffice = pythClasses.ns.Identity()
            plexiDevIdentityOffice.metaconcept = "Identity"
            plexiDevIdentityOffice.name = "Dev identity"
            # Identity PM to office station
            plexiPMIdentityOffice = pythClasses.ns.Identity()
            plexiPMIdentityOffice.metaconcept = "Identity"
            plexiPMIdentityOffice.name = "PM identity"
            # Credentials to private PM office station
            plexiPMCredentials = pythClasses.ns.Credentials()
            plexiPMCredentials.metaconcept = "Credentials"
            plexiPMCredentials.name = "Password/Username" 
            plexiPMCredentials.notGuessable = 0.6 # How hard it is to guess the password (not a part of the most common password dictionary)
            plexiPMCredentials.unique = 0.8 # assume that the password is not used for multiple services
            

            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            
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
            
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            
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

            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(vulnerabilityOfficeSales)
            honorModel.add_asset(vulnerabilityOfficeDev)

            honorModel.add_asset(plexigridSalesIDPS)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(plexidatabasecloudconn)
            honorModel.add_asset(SSHCreds)
            honorModel.add_asset(SSHEncryptedCreds)
            honorModel.add_asset(replicatedMeterDatatoDatabase)
            honorModel.add_asset(plexigridDataSSH)
            honorModel.add_asset(OneDriveDevCreds)
            honorModel.add_asset(OneDriveMFADevCreds)
            honorModel.add_asset(OneDriveSalesCreds)
            honorModel.add_asset(OneDriveMFASalesCreds)

            honorModel.add_asset(plexigridDevOneDriveIdentity)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

            honorModel.add_asset(plexigridDataPMOneDrive)
            honorModel.add_asset(PMOneDriveCreds)
            honorModel.add_asset(PMOneDriveEncryptedCreds)
            honorModel.add_asset(plexigridDataDevOneDrive)
            honorModel.add_asset(DevOneDriveCreds)
            honorModel.add_asset(DevOneDriveEncryptedCreds)
            # honorModel.add_asset(unencryptedData)

            honorModel.add_asset(plexidevCredentials)
            honorModel.add_asset(plexiDevIdentityOffice)
            honorModel.add_asset(plexiPMIdentityOffice)
            honorModel.add_asset(plexiPMCredentials)


            

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
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network"
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
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"

            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            # Identity symbolyzing a regular User
            plexigridRegularIdentity = pythClasses.ns.Identity()
            plexigridRegularIdentity.metaconcept = "Identity"
            plexigridRegularIdentity.name = "Regular User"
            # User symbolyzing the real human (PM)
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User" 


            # Add pm sophos security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "Sophos"
            plexigridSalesIDPS.supplyChainAuditing = 1
            plexigridSalesIDPS.effectiveness = 0.8
            # Add pm sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
            plexigridDevIDPS.effectiveness = 0.8

            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
            # Add credentials to the sales identity connected to sftp
            SFTPSalesCreds = pythClasses.ns.Credentials()
            SFTPSalesCreds.metaconcept = "Credentials"
            SFTPSalesCreds.name = "Password/Username or Key authentication" 
            # Add MFA to this identity
            SFTPMFASalesCreds = pythClasses.ns.Credentials()
            SFTPMFASalesCreds.metaconcept = "Credentials"
            SFTPMFASalesCreds.name = "MFA"
            # Add identity that the PM use for SFTP
            plexigridPMSFTPIdentity = pythClasses.ns.Identity()
            plexigridPMSFTPIdentity.metaconcept = "Identity"
            plexigridPMSFTPIdentity.name = "PM Identity"
            
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Sales Office station"
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
            plexigridDevOffice.name = "Devs Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Mail-Server for Plexigrid project/sales
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            plexigridSalesMail.supplyChainAuditing = 1
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM" 
            plexigridPMUser.securityAwareness = 1
            # Software vulnreability for Project/sales mail server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            # Mail-server for Plexigrid Dev network
            plexigridDevMail = pythClasses.ns.Application()
            plexigridDevMail.metaconcept = "Application"
            plexigridDevMail.name = "mail server"
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
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            
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
            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(plexigridRegularIdentity)
            honorModel.add_asset(vulnerabilityOfficeSales)
            honorModel.add_asset(vulnerabilityOfficeDev)

            honorModel.add_asset(plexigridSalesIDPS)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(plexidatabasecloudconn)
            honorModel.add_asset(SSHCreds)
            honorModel.add_asset(SSHEncryptedCreds)
            honorModel.add_asset(plexigridDataSSH)
            honorModel.add_asset(SFTPSalesCreds)
            honorModel.add_asset(SFTPMFASalesCreds)
            honorModel.add_asset(plexigridPMSFTPIdentity)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

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
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network"
            
            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            # Identity symbolyzing a regular User
            plexigridRegularIdentity = pythClasses.ns.Identity()
            plexigridRegularIdentity.metaconcept = "Identity"
            plexigridRegularIdentity.name = "Regular User"
            # User symbolyzing the real human (PM)
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User" 

            # Add pm sophos security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "Sophos"
            plexigridSalesIDPS.supplyChainAuditing = 1
            # Add pm sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
            # Add credentials to the dev identity connected to onedrive
            OneDriveDevCreds = pythClasses.ns.Credentials()
            OneDriveDevCreds.metaconcept = "Credentials"
            OneDriveDevCreds.name = "Password/Username" 
            # Add MFA to this identity
            OneDriveMFADevCreds = pythClasses.ns.Credentials()
            OneDriveMFADevCreds.metaconcept = "Credentials"
            OneDriveMFADevCreds.name = "MFA"
            # Add credentials to the sales identity connected to onedrive
            OneDriveSalesCreds = pythClasses.ns.Credentials()
            OneDriveSalesCreds.metaconcept = "Credentials"
            OneDriveSalesCreds.name = "Password/Username" 
            # Add MFA to this identity
            OneDriveMFASalesCreds = pythClasses.ns.Credentials()
            OneDriveMFASalesCreds.metaconcept = "Credentials"
            OneDriveMFASalesCreds.name = "MFA"
            # Add identity that the PM use for OneDrive
            plexigridPMOneDriveIdentity = pythClasses.ns.Identity()
            plexigridPMOneDriveIdentity.metaconcept = "Identity"
            plexigridPMOneDriveIdentity.name = "PM Identity"
            # Add identity that the dev user use for OneDrive
            plexigridDevOneDriveIdentity = pythClasses.ns.Identity()
            plexigridDevOneDriveIdentity.metaconcept = "Identity"
            plexigridDevOneDriveIdentity.name = "Dev Identity"
            # Add credentials to the sales identity connected to sftp
            SFTPSalesCreds = pythClasses.ns.Credentials()
            SFTPSalesCreds.metaconcept = "Credentials"
            SFTPSalesCreds.name = "Password/Username or Key authentication" 
            # Add MFA to this identity
            SFTPMFASalesCreds = pythClasses.ns.Credentials()
            SFTPMFASalesCreds.metaconcept = "Credentials"
            SFTPMFASalesCreds.name = "MFA"
            # Add identity that the PM use for SFTP
            plexigridPMSFTPIdentity = pythClasses.ns.Identity()
            plexigridPMSFTPIdentity.metaconcept = "Identity"
            plexigridPMSFTPIdentity.name = "PM Identity"
            # Add metering data from PM-> Onedrive
            plexigridDataPMOneDrive = pythClasses.ns.Data()
            plexigridDataPMOneDrive.metaconcept = "Data"
            plexigridDataPMOneDrive.name = "Metering Data"
            # Add encryption keys to meter
            PMOneDriveCreds = pythClasses.ns.Credentials()
            PMOneDriveCreds.metaconcept = "Credentials"
            PMOneDriveCreds.name = "Encryption keys"
            # Add encryption keys data between OneDrive and PM
            PMOneDriveEncryptedCreds = pythClasses.ns.Data()
            PMOneDriveEncryptedCreds.metaconcept = "Data"
            PMOneDriveEncryptedCreds.name = "Encrypted keys data"
            # Add metering data from OneDrive -> Dev 
            plexigridDataDevOneDrive = pythClasses.ns.Data()
            plexigridDataDevOneDrive.metaconcept = "Data"
            plexigridDataDevOneDrive.name = "Metering Data"
            # Add encryption keys data between OneDrive and Dev
            DevOneDriveCreds = pythClasses.ns.Credentials()
            DevOneDriveCreds.metaconcept = "Credentials"
            DevOneDriveCreds.name = "Encryption keys"
            # Credentials data
            DevOneDriveEncryptedCreds = pythClasses.ns.Data()
            DevOneDriveEncryptedCreds.metaconcept = "Data"
            DevOneDriveEncryptedCreds.name = "Encrypted keys data"
            
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
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "Sales Office station"
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
            plexigridDevOffice.name = "Devs Office station"
            plexigridDevOffice.supplyChainAuditing = 1
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
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
            
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridDataDSO)
            honorModel.add_asset(plexigridPMIdentity)
            honorModel.add_asset(plexigridPMUser)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexigridSalesOfficeConn)
            honorModel.add_asset(plexigridSalesOffice)
            honorModel.add_asset(plexigridDevOffice)
            
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(plexiInternetSalesFirewall)
            
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

            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(plexigridRegularIdentity)
            honorModel.add_asset(vulnerabilityOfficeSales)
            honorModel.add_asset(vulnerabilityOfficeDev)

            honorModel.add_asset(plexigridSalesIDPS)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(plexidatabasecloudconn)
            honorModel.add_asset(SSHCreds)
            honorModel.add_asset(SSHEncryptedCreds)
            honorModel.add_asset(plexigridDataSSH)
            honorModel.add_asset(OneDriveDevCreds)
            honorModel.add_asset(OneDriveMFADevCreds)
            honorModel.add_asset(OneDriveSalesCreds)
            honorModel.add_asset(OneDriveMFASalesCreds)

            honorModel.add_asset(SFTPSalesCreds)
            honorModel.add_asset(SFTPMFASalesCreds)
            honorModel.add_asset(plexigridPMSFTPIdentity)

            honorModel.add_asset(plexigridPMOneDriveIdentity)
            honorModel.add_asset(plexigridDevOneDriveIdentity)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

            
            honorModel.add_asset(plexigridDataPMOneDrive)
            honorModel.add_asset(PMOneDriveCreds)
            honorModel.add_asset(PMOneDriveEncryptedCreds)
            honorModel.add_asset(plexigridDataDevOneDrive)
            honorModel.add_asset(DevOneDriveCreds)
            honorModel.add_asset(DevOneDriveEncryptedCreds)
        
################################################## Test 5 ######################################################################## 
        if test_case5:
            pass
################################################## Test 6 ########################################################################       
        if test_case6:
            pass


    if add_association:
################################################## Test 1 ########################################################################       

        if test_case1:
           
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
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

            # SoftwareVuln to sales
            assocSalesSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesSoftwareVuln.application = [plexigridSalesOffice]
            assocSalesSoftwareVuln.vulnerabilities = [vulnerabilityOfficeSales]
            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            # Add identity to Sales office so they have the same privs
            assocIdentityDevOffice = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityDevOffice.lowPrivAppIAMs = [plexigridRegularIdentity]
            assocIdentityDevOffice.lowPrivApps = [plexigridDevOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityDevUser.users = [plexigridRegularUser]
            assocIdentityDevUser.userIds = [plexigridRegularIdentity]


            # Vulnerability to sales office zone
            assocVulnHardwareSales = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareSales.vulnerabilities = [plexigridSalesHardwarevuln]
            assocVulnHardwareSales.hardware = [plexigridSalesHardware]
            # Add identity to sales mail server
            assocIdentityMail = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityMail.executionPrivIAMs = [plexigridPMIdentity]
            assocIdentityMail.execPrivApps = [plexigridSalesMail]
            
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

            # Add idps to office stations
            assocIDPSSalesOffice = pythClasses.ns.AppProtection()
            assocIDPSSalesOffice.protectorIDPSs = [plexigridSalesIDPS]
            assocIDPSSalesOffice.protectedApps = [plexigridSalesOffice]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]
            # Add credData to database
            assocCreddevoffice = pythClasses.ns.AppContainment()
            assocCreddevoffice.containedData = [SSHEncryptedCreds]
            assocCreddevoffice.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncSSHData = pythClasses.ns.EncryptionCredentials()
            assocEncSSHData.encryptCreds = [SSHCreds]
            assocEncSSHData.encryptedData = [plexigridDataSSH]
            # Add credentials data to credentials
            assocCredSSHData = pythClasses.ns.InfoContainment()
            assocCredSSHData.containerData = [SSHEncryptedCreds]
            assocCredSSHData.information = [SSHCreds]
            # Add credData to database
            assocCredDatabase = pythClasses.ns.AppContainment()
            assocCredDatabase.containedData = [SSHEncryptedCreds]
            assocCredDatabase.containingApp = [plexigriddatabase]
            # Add replicated information to unencrypted metering data
            assocreplicatedData = pythClasses.ns.Replica()
            assocreplicatedData.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedData.dataReplicas = [plexigridDataDSO]
            # Add replicated information to encrypted data
            assocDatabaseData = pythClasses.ns.Replica()
            assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocDatabaseData.dataReplicas = [plexigridDataSSH]
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            
            # Connect database to conn to cloud
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            assocConndatabaseCloud = pythClasses.ns.NetworkConnection()
            assocConndatabaseCloud.networks = [cloudNetwork]
            assocConndatabaseCloud.netConnections = [plexidatabasecloudconn]
            assocDatabaseHardware = pythClasses.ns.SysExecution()
            assocDatabaseHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocDatabaseHardware.sysExecutedApps=[plexigriddatabase]
            assocVulnHardwareDatabase = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDatabase.vulnerabilities = [plexigridAppDataBaseHardwarevuln]
            assocVulnHardwareDatabase.hardware = [plexigridAppDatabaseHardware]
            # Connect web application to conn
            assocConnApplication = pythClasses.ns.ApplicationConnection()
            assocConnApplication.applications = [plexigridApplication]
            assocConnApplication.appConnections = [plexiApplicationcloudconn]
            assocConnApplicationCloud = pythClasses.ns.NetworkConnection()
            assocConnApplicationCloud.networks = [cloudNetwork]
            assocConnApplicationCloud.netConnections = [plexiApplicationcloudconn]
            assocApplicationHardware = pythClasses.ns.SysExecution()
            assocApplicationHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocApplicationHardware.sysExecutedApps=[plexigridApplication]

            


           
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
            
            honorModel.add_association(assocConnSalesnetworkInternet)
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
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetSalesFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)
            honorModel.add_association(assocIdentityDevOffice)
            honorModel.add_association(assocIdentityDevUser)
            
            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocreplicatedData)
            honorModel.add_association(assocDatabaseData)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)


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
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add Sales mail server to microsoftCloud network
            assocConnSalesMail = pythClasses.ns.NetworkConnection()
            assocConnSalesMail.networks = [cloudNetwork]
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
            assocIdentityMail = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityMail.lowPrivAppIAMs = [plexigridPMIdentity]
            assocIdentityMail.lowPrivApps = [plexigridSalesMail]
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

            # SoftwareVuln to sales
            assocSalesSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesSoftwareVuln.application = [plexigridSalesOffice]
            assocSalesSoftwareVuln.vulnerabilities = [vulnerabilityOfficeSales]
            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            


            # Add idps to office stations
            assocIDPSSalesOffice = pythClasses.ns.AppProtection()
            assocIDPSSalesOffice.protectorIDPSs = [plexigridSalesIDPS]
            assocIDPSSalesOffice.protectedApps = [plexigridSalesOffice]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]
            # Add credData to database
            assocCreddevoffice = pythClasses.ns.AppContainment()
            assocCreddevoffice.containedData = [SSHEncryptedCreds]
            assocCreddevoffice.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncSSHData = pythClasses.ns.EncryptionCredentials()
            assocEncSSHData.encryptCreds = [SSHCreds]
            assocEncSSHData.encryptedData = [plexigridDataSSH]
            # Add credentials data to credentials
            assocCredSSHData = pythClasses.ns.InfoContainment()
            assocCredSSHData.containerData = [SSHEncryptedCreds]
            assocCredSSHData.information = [SSHCreds]
            # Add credData to database
            assocCredDatabase = pythClasses.ns.AppContainment()
            assocCredDatabase.containedData = [SSHEncryptedCreds]
            assocCredDatabase.containingApp = [plexigriddatabase]
            # Add replicated information to unencrypted metering data
            assocreplicatedData = pythClasses.ns.Replica()
            assocreplicatedData.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedData.dataReplicas = [plexigridDataDSO]
            # Add replicated information to encrypted data
            assocDatabaseData = pythClasses.ns.Replica()
            assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocDatabaseData.dataReplicas = [plexigridDataSSH]
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Connect app to conn
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            # Connect database to conn to cloud
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            assocConndatabaseCloud = pythClasses.ns.NetworkConnection()
            assocConndatabaseCloud.networks = [cloudNetwork]
            assocConndatabaseCloud.netConnections = [plexidatabasecloudconn]
            assocDatabaseHardware = pythClasses.ns.SysExecution()
            assocDatabaseHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocDatabaseHardware.sysExecutedApps=[plexigriddatabase]
            assocVulnHardwareDatabase = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDatabase.vulnerabilities = [plexigridAppDataBaseHardwarevuln]
            assocVulnHardwareDatabase.hardware = [plexigridAppDatabaseHardware]
            # Connect web application to conn
            assocConnApplication = pythClasses.ns.ApplicationConnection()
            assocConnApplication.applications = [plexigridApplication]
            assocConnApplication.appConnections = [plexiApplicationcloudconn]
            assocConnApplicationCloud = pythClasses.ns.NetworkConnection()
            assocConnApplicationCloud.networks = [cloudNetwork]
            assocConnApplicationCloud.netConnections = [plexiApplicationcloudconn]
            assocApplicationHardware = pythClasses.ns.SysExecution()
            assocApplicationHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocApplicationHardware.sysExecutedApps=[plexigridApplication]
            # Connect Dev user to OneDrive
            assocDevtoOneDrive = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDevtoOneDrive.lowPrivAppIAMs = [plexigridDevOneDriveIdentity]
            assocDevtoOneDrive.lowPrivApps = [cloudOneDrive]
            # Connect Pm to OneDrive
            assocSalestoOneDrive = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoOneDrive.lowPrivAppIAMs = [plexigridPMIdentity]
            assocSalestoOneDrive.lowPrivApps = [cloudOneDrive]
            # Connect credentials to dev user
            assocCredDevIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDevIdentity.identities = [plexigridDevOneDriveIdentity]
            assocCredDevIdentity.credentials = [OneDriveDevCreds]
            # Connect MFA
            assocCredMFADevIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADevIdentity.requiredFactors = [OneDriveMFADevCreds]
            assocCredMFADevIdentity.credentials = [OneDriveDevCreds]
            # Connect credentials to sales user
            assocCredSalesIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesIdentity.identities = [plexigridPMIdentity]
            assocCredSalesIdentity.credentials = [OneDriveSalesCreds]
            # Connect MFA
            assocCredMFASalesIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesIdentity.requiredFactors = [OneDriveMFASalesCreds]
            assocCredMFASalesIdentity.credentials = [OneDriveSalesCreds]
            # Connect dev user to new identity
            assocOneDriveIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocOneDriveIdentityDevUser.users = [plexigridRegularUser]
            assocOneDriveIdentityDevUser.userIds = [plexigridDevOneDriveIdentity]

            # Add credData to PM
            assocCredPM = pythClasses.ns.AppContainment()
            assocCredPM.containedData = [PMOneDriveEncryptedCreds]
            assocCredPM.containingApp = [plexigridSalesOffice]
            # Add credentials to meteringData
            assocEncOneDrivePM = pythClasses.ns.EncryptionCredentials()
            assocEncOneDrivePM.encryptCreds = [PMOneDriveCreds]
            assocEncOneDrivePM.encryptedData = [plexigridDataPMOneDrive]
            # Add credentials data to credentials
            assocCredOneDrivePM = pythClasses.ns.InfoContainment()
            assocCredOneDrivePM.containerData = [PMOneDriveEncryptedCreds]
            assocCredOneDrivePM.information = [PMOneDriveCreds]
            # Add credData to OneDrive
            assocCredOneDrive1 = pythClasses.ns.AppContainment()
            assocCredOneDrive1.containedData = [PMOneDriveEncryptedCreds]
            assocCredOneDrive1.containingApp = [cloudOneDrive]
            # Add replicated information to unencrypted metering data
            assocreplicatedDataPMOneDrive = pythClasses.ns.Replica()
            assocreplicatedDataPMOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedDataPMOneDrive.dataReplicas = [plexigridDataPMOneDrive]
            # Add credData to Dev
            assocCredDev = pythClasses.ns.AppContainment()
            assocCredDev.containedData = [DevOneDriveEncryptedCreds]
            assocCredDev.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncOneDriveDev = pythClasses.ns.EncryptionCredentials()
            assocEncOneDriveDev.encryptCreds = [DevOneDriveCreds]
            assocEncOneDriveDev.encryptedData = [plexigridDataDevOneDrive]
            # Add credentials data to credentials
            assocCredOneDriveDev = pythClasses.ns.InfoContainment()
            assocCredOneDriveDev.containerData = [DevOneDriveEncryptedCreds]
            assocCredOneDriveDev.information = [DevOneDriveCreds]
            # Add credData to OneDrive
            assocCredOneDrive2 = pythClasses.ns.AppContainment()
            assocCredOneDrive2.containedData = [DevOneDriveEncryptedCreds]
            assocCredOneDrive2.containingApp = [cloudOneDrive]
            # Add replicated information to unencrypted metering data
            assocreplicatedDataDevOneDrive = pythClasses.ns.Replica()
            assocreplicatedDataDevOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedDataDevOneDrive.dataReplicas = [plexigridDataDevOneDrive]

           
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataPMOneDrive]
            # receive data to oneDrive from sales office
            assocRecOnedrive = pythClasses.ns.ReceiveData()
            assocRecOnedrive.receiverApp = [cloudOneDrive]
            assocRecOnedrive.receivedData = [plexigridDataPMOneDrive]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole cloud network
            assocDataCloud = pythClasses.ns.DataInTransit()
            assocDataCloud.transitNetwork = [cloudNetwork]
            assocDataCloud.transitData = [plexigridDataPMOneDrive]
            # Receive data from DSO to Sales
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSalesMail]
            assocDSOSales.receivedData = [plexigridDataDSO]
            # The data is accessable from the whole cloud network
            assocDataCloudDev = pythClasses.ns.DataInTransit()
            assocDataCloudDev.transitNetwork = [cloudNetwork]
            assocDataCloudDev.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole Dev network
            assocDataDevTransit = pythClasses.ns.DataInTransit()
            assocDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocDataDevTransit.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole PM's network
            assocDataPMTransit = pythClasses.ns.DataInTransit()
            assocDataPMTransit.transitNetwork = [plexiSalesNetwork]
            assocDataPMTransit.transitData = [plexigridDataPMOneDrive]

            # Connect the unencrypted data to use for local storage
            assocLocallyUnencryptedData = pythClasses.ns.Replica()
            assocLocallyUnencryptedData.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocLocallyUnencryptedData.dataReplicas = [plexigridDataDSO]
            # Add locally downloaded data
            assocLocallyDev = pythClasses.ns.DataHosting()
            assocLocallyDev.hostedData = [plexigridDataDSO]
            assocLocallyDev.hardware = [plexigridDevHardware]
            # Add locally downloaded data
            assocLocallyPM = pythClasses.ns.DataHosting()
            assocLocallyPM.hostedData = [plexigridDataDSO]
            assocLocallyPM.hardware = [plexigridSalesHardware]

            # Connect office identity to dev user
            assocIdentityOfficeDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityOfficeDevUser.users = [plexigridRegularUser]
            assocIdentityOfficeDevUser.userIds = [plexiDevIdentityOffice]
            # Connect office identity to pm user
            assocIdentityOfficePMUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityOfficePMUser.users = [plexigridPMUser]
            assocIdentityOfficePMUser.userIds = [plexiPMIdentityOffice]
            # Connect office credentials to PM office identity
            assocCredPMOfficeIdentity = pythClasses.ns.IdentityCredentials()
            assocCredPMOfficeIdentity.identities = [plexiPMIdentityOffice]
            assocCredPMOfficeIdentity.credentials = [plexiPMCredentials]
            # Connect identity with admin right to PM office
            assocPMOfficeIdentity = pythClasses.ns.ExecutionPrivilegeAccess()
            assocPMOfficeIdentity.executionPrivIAMs = [plexiPMIdentityOffice]
            assocPMOfficeIdentity.execPrivApps = [plexigridSalesOffice]
            # Connect office credentials to dev office identity
            assocCredDevOfficeIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDevOfficeIdentity.identities = [plexiDevIdentityOffice]
            assocCredDevOfficeIdentity.credentials = [plexidevCredentials]
            # Connect identity with admin right to Dev office
            assocDevOfficeIdentity = pythClasses.ns.ExecutionPrivilegeAccess()
            assocDevOfficeIdentity.executionPrivIAMs = [plexiDevIdentityOffice]
            assocDevOfficeIdentity.execPrivApps = [plexigridDevOffice]

            # Add every association to the model
            
            honorModel.add_association(assocConnSalesnetworkInternet)
            
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
            
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            
            honorModel.add_association(assocConnCloudOneDrive)
            honorModel.add_association(assocConnOneDriveCloud)
            honorModel.add_association(assocVulnOneDrive)
            honorModel.add_association(assocCloudInternet)
            honorModel.add_association(assocDataCloud)
            honorModel.add_association(assocRecOnedrive)

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)


            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocreplicatedData)
            honorModel.add_association(assocDatabaseData)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocDevtoOneDrive)
            honorModel.add_association(assocSalestoOneDrive)
            honorModel.add_association(assocCredDevIdentity)
            honorModel.add_association(assocCredSalesIdentity)
            honorModel.add_association(assocCredMFADevIdentity)
            honorModel.add_association(assocCredMFASalesIdentity)
            honorModel.add_association(assocOneDriveIdentityDevUser)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)
            
            honorModel.add_association(assocCredPM)
            honorModel.add_association(assocEncOneDrivePM)
            honorModel.add_association(assocCredOneDrivePM)
            honorModel.add_association(assocCredOneDrive1)
            honorModel.add_association(assocreplicatedDataPMOneDrive)
            honorModel.add_association(assocCredDev)
            honorModel.add_association(assocEncOneDriveDev)
            honorModel.add_association(assocCredOneDriveDev)
            honorModel.add_association(assocCredOneDrive2)
            honorModel.add_association(assocreplicatedDataDevOneDrive)
            honorModel.add_association(assocDataCloudDev)
            honorModel.add_association(assocDataDevTransit)
            honorModel.add_association(assocDataPMTransit)

            honorModel.add_association(assocLocallyDev)
            honorModel.add_association(assocLocallyPM)
            honorModel.add_association(assocLocallyUnencryptedData)
            honorModel.add_association(assocCredPMOfficeIdentity)
            honorModel.add_association(assocPMOfficeIdentity)
            honorModel.add_association(assocCredDevOfficeIdentity)
            honorModel.add_association(assocDevOfficeIdentity)
            honorModel.add_association(assocIdentityOfficeDevUser)
            honorModel.add_association(assocIdentityOfficePMUser)

            

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

            # SoftwareVuln to sales
            assocSalesSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesSoftwareVuln.application = [plexigridSalesOffice]
            assocSalesSoftwareVuln.vulnerabilities = [vulnerabilityOfficeSales]
            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            # Add identity to dev office so they have the same privs
            assocIdentityDevOffice = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityDevOffice.lowPrivAppIAMs = [plexigridRegularIdentity]
            assocIdentityDevOffice.lowPrivApps = [plexigridDevOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityDevUser.users = [plexigridRegularUser]
            assocIdentityDevUser.userIds = [plexigridRegularIdentity]
            
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            
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

            # Add idps to office stations
            assocIDPSSalesOffice = pythClasses.ns.AppProtection()
            assocIDPSSalesOffice.protectorIDPSs = [plexigridSalesIDPS]
            assocIDPSSalesOffice.protectedApps = [plexigridSalesOffice]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]
            # Add credData to database
            assocCreddevoffice = pythClasses.ns.AppContainment()
            assocCreddevoffice.containedData = [SSHEncryptedCreds]
            assocCreddevoffice.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncSSHData = pythClasses.ns.EncryptionCredentials()
            assocEncSSHData.encryptCreds = [SSHCreds]
            assocEncSSHData.encryptedData = [plexigridDataSSH]
            # Add credentials data to credentials
            assocCredSSHData = pythClasses.ns.InfoContainment()
            assocCredSSHData.containerData = [SSHEncryptedCreds]
            assocCredSSHData.information = [SSHCreds]
            # Add credData to database
            assocCredDatabase = pythClasses.ns.AppContainment()
            assocCredDatabase.containedData = [SSHEncryptedCreds]
            assocCredDatabase.containingApp = [plexigriddatabase]
            # Add replicated information to encrypted data
            assocDatabaseData = pythClasses.ns.Replica()
            assocDatabaseData.replicatedInformation = [replicatedMeterData]
            assocDatabaseData.dataReplicas = [plexigridDataSSH]
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Connect app to conn
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            # Connect database to conn to cloud
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            assocConndatabaseCloud = pythClasses.ns.NetworkConnection()
            assocConndatabaseCloud.networks = [cloudNetwork]
            assocConndatabaseCloud.netConnections = [plexidatabasecloudconn]
            assocDatabaseHardware = pythClasses.ns.SysExecution()
            assocDatabaseHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocDatabaseHardware.sysExecutedApps=[plexigriddatabase]
            assocVulnHardwareDatabase = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDatabase.vulnerabilities = [plexigridAppDataBaseHardwarevuln]
            assocVulnHardwareDatabase.hardware = [plexigridAppDatabaseHardware]
            # Connect web application to conn
            assocConnApplication = pythClasses.ns.ApplicationConnection()
            assocConnApplication.applications = [plexigridApplication]
            assocConnApplication.appConnections = [plexiApplicationcloudconn]
            assocConnApplicationCloud = pythClasses.ns.NetworkConnection()
            assocConnApplicationCloud.networks = [cloudNetwork]
            assocConnApplicationCloud.netConnections = [plexiApplicationcloudconn]
            assocApplicationHardware = pythClasses.ns.SysExecution()
            assocApplicationHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocApplicationHardware.sysExecutedApps=[plexigridApplication]
            # Connect Pm to SFTP
            assocSalestoSFTP = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoSFTP.lowPrivAppIAMs = [plexigridPMSFTPIdentity]
            assocSalestoSFTP.lowPrivApps = [plexigridSftp]
            # Connect credentials to sales user
            assocCredSalesIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesIdentity.identities = [plexigridPMSFTPIdentity]
            assocCredSalesIdentity.credentials = [SFTPSalesCreds]
            # Connect MFA
            assocCredMFASalesIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesIdentity.requiredFactors = [SFTPMFASalesCreds]
            assocCredMFASalesIdentity.credentials = [SFTPSalesCreds]
            # Connect pm user to new identity
            assocSFTPIdentityPMUser = pythClasses.ns.UserAssignedIdentities()
            assocSFTPIdentityPMUser.users = [plexigridPMUser]
            assocSFTPIdentityPMUser.userIds = [plexigridPMSFTPIdentity]
            # Add every association to the model
            
            honorModel.add_association(assocConnSalesnetworkInternet)
            
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
            
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            
            honorModel.add_association(assocConnSftpSalesNetwork)
            honorModel.add_association(assocConnSftpSales)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredSFTP)
            honorModel.add_association(assocVulnSFTP)
            honorModel.add_association(assocEncryptedData)
            honorModel.add_association(assocUnencryptedData)

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)
            honorModel.add_association(assocIdentityDevOffice)
            honorModel.add_association(assocIdentityDevUser)

            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocDatabaseData)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocSalestoSFTP)
            honorModel.add_association(assocCredSalesIdentity)
            honorModel.add_association(assocCredMFASalesIdentity)
            honorModel.add_association(assocSFTPIdentityPMUser)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)


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
            
            # Add networkconnections project/sales (conn to internet)
            assocConnSalesnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnSalesnetworkInternet.networks = [plexiSalesNetwork]
            assocConnSalesnetworkInternet.netConnections = [plexiSalesConn]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            
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

            # SoftwareVuln to sales
            assocSalesSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSalesSoftwareVuln.application = [plexigridSalesOffice]
            assocSalesSoftwareVuln.vulnerabilities = [vulnerabilityOfficeSales]
            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            # Add identity to Sales office so they have the same privs
            assocIdentityDevOffice = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityDevOffice.lowPrivAppIAMs = [plexigridRegularIdentity]
            assocIdentityDevOffice.lowPrivApps = [plexigridDevOffice]
            # Add user to identity to enable social engineering attacks
            assocIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityDevUser.users = [plexigridRegularUser]
            assocIdentityDevUser.userIds = [plexigridRegularIdentity]
            
           
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataPMOneDrive]
            # receive data to oneDrive from sales office
            assocRecOnedrive = pythClasses.ns.ReceiveData()
            assocRecOnedrive.receiverApp = [cloudOneDrive]
            assocRecOnedrive.receivedData = [plexigridDataPMOneDrive]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole sales network
            assocDataSales = pythClasses.ns.DataInTransit()
            assocDataSales.transitNetwork = [plexiSalesNetwork]
            assocDataSales.transitData = [plexigridDataDSO]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole cloud network
            assocDataCloud = pythClasses.ns.DataInTransit()
            assocDataCloud.transitNetwork = [cloudNetwork]
            assocDataCloud.transitData = [plexigridDataPMOneDrive]
            # The data is accessable from the whole cloud network
            assocDataCloudDev = pythClasses.ns.DataInTransit()
            assocDataCloudDev.transitNetwork = [cloudNetwork]
            assocDataCloudDev.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole Dev network
            assocDataDevTransit = pythClasses.ns.DataInTransit()
            assocDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocDataDevTransit.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole PM's network
            assocDataPMTransit = pythClasses.ns.DataInTransit()
            assocDataPMTransit.transitNetwork = [plexiSalesNetwork]
            assocDataPMTransit.transitData = [plexigridDataPMOneDrive]
            # Receive data from DSO to SFTP
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSftp]
            assocDSOSales.receivedData = [plexigridDataDSO]
            

             # Add idps to office stations
            assocIDPSSalesOffice = pythClasses.ns.AppProtection()
            assocIDPSSalesOffice.protectorIDPSs = [plexigridSalesIDPS]
            assocIDPSSalesOffice.protectedApps = [plexigridSalesOffice]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]
            # Add credData to database
            assocCreddevoffice = pythClasses.ns.AppContainment()
            assocCreddevoffice.containedData = [SSHEncryptedCreds]
            assocCreddevoffice.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncSSHData = pythClasses.ns.EncryptionCredentials()
            assocEncSSHData.encryptCreds = [SSHCreds]
            assocEncSSHData.encryptedData = [plexigridDataSSH]
            # Add credentials data to credentials
            assocCredSSHData = pythClasses.ns.InfoContainment()
            assocCredSSHData.containerData = [SSHEncryptedCreds]
            assocCredSSHData.information = [SSHCreds]
            # Add credData to database
            assocCredDatabase = pythClasses.ns.AppContainment()
            assocCredDatabase.containedData = [SSHEncryptedCreds]
            assocCredDatabase.containingApp = [plexigriddatabase]
            # Add replicated information to encrypted data
            assocDatabaseData = pythClasses.ns.Replica()
            assocDatabaseData.replicatedInformation = [replicatedMeterData]
            assocDatabaseData.dataReplicas = [plexigridDataSSH]
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Connect app to conn
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            # Connect database to conn to cloud
            assocConndatabase = pythClasses.ns.ApplicationConnection()
            assocConndatabase.applications = [plexigriddatabase]
            assocConndatabase.appConnections = [plexidatabasecloudconn]
            assocConndatabaseCloud = pythClasses.ns.NetworkConnection()
            assocConndatabaseCloud.networks = [cloudNetwork]
            assocConndatabaseCloud.netConnections = [plexidatabasecloudconn]
            assocDatabaseHardware = pythClasses.ns.SysExecution()
            assocDatabaseHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocDatabaseHardware.sysExecutedApps=[plexigriddatabase]
            assocVulnHardwareDatabase = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDatabase.vulnerabilities = [plexigridAppDataBaseHardwarevuln]
            assocVulnHardwareDatabase.hardware = [plexigridAppDatabaseHardware]
            # Connect web application to conn
            assocConnApplication = pythClasses.ns.ApplicationConnection()
            assocConnApplication.applications = [plexigridApplication]
            assocConnApplication.appConnections = [plexiApplicationcloudconn]
            assocConnApplicationCloud = pythClasses.ns.NetworkConnection()
            assocConnApplicationCloud.networks = [cloudNetwork]
            assocConnApplicationCloud.netConnections = [plexiApplicationcloudconn]
            assocApplicationHardware = pythClasses.ns.SysExecution()
            assocApplicationHardware.hostHardware = [plexigridAppDatabaseHardware]
            assocApplicationHardware.sysExecutedApps=[plexigridApplication]
            # Connect Dev user to OneDrive
            assocDevtoOneDrive = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDevtoOneDrive.lowPrivAppIAMs = [plexigridDevOneDriveIdentity]
            assocDevtoOneDrive.lowPrivApps = [cloudOneDrive]
            # Connect Pm to OneDrive
            assocSalestoOneDrive = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoOneDrive.lowPrivAppIAMs = [plexigridPMOneDriveIdentity]
            assocSalestoOneDrive.lowPrivApps = [cloudOneDrive]
            # Connect credentials to dev user
            assocCredDevIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDevIdentity.identities = [plexigridDevOneDriveIdentity]
            assocCredDevIdentity.credentials = [OneDriveDevCreds]
            # Connect MFA
            assocCredMFADevIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADevIdentity.requiredFactors = [OneDriveMFADevCreds]
            assocCredMFADevIdentity.credentials = [OneDriveDevCreds]
            # Connect credentials to sales user
            assocCredSalesOneDriveIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesOneDriveIdentity.identities = [plexigridPMOneDriveIdentity]
            assocCredSalesOneDriveIdentity.credentials = [OneDriveSalesCreds]
            # Connect MFA
            assocCredMFASalesOneDriveIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesOneDriveIdentity.requiredFactors = [OneDriveMFASalesCreds]
            assocCredMFASalesOneDriveIdentity.credentials = [OneDriveSalesCreds]
            # Connect pm user to new identity
            assocOneDriveIdentityPMUser = pythClasses.ns.UserAssignedIdentities()
            assocOneDriveIdentityPMUser.users = [plexigridPMUser]
            assocOneDriveIdentityPMUser.userIds = [plexigridPMOneDriveIdentity]
            # Connect dev user to new identity
            assocOneDriveIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocOneDriveIdentityDevUser.users = [plexigridRegularUser]
            assocOneDriveIdentityDevUser.userIds = [plexigridDevOneDriveIdentity]
            # Connect Pm to SFTP
            assocSalestoSFTP = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoSFTP.lowPrivAppIAMs = [plexigridPMSFTPIdentity]
            assocSalestoSFTP.lowPrivApps = [plexigridSftp]
            # Connect credentials to sales user
            assocCredSalesSFTPIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesSFTPIdentity.identities = [plexigridPMSFTPIdentity]
            assocCredSalesSFTPIdentity.credentials = [SFTPSalesCreds]
            # Connect MFA
            assocCredMFASalesSFTPIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesSFTPIdentity.requiredFactors = [SFTPMFASalesCreds]
            assocCredMFASalesSFTPIdentity.credentials = [SFTPSalesCreds]
            # Connect pm user to new identity
            assocSFTPIdentityPMUser = pythClasses.ns.UserAssignedIdentities()
            assocSFTPIdentityPMUser.users = [plexigridPMUser]
            assocSFTPIdentityPMUser.userIds = [plexigridPMSFTPIdentity]
            # Add credData to PM
            assocCredPM = pythClasses.ns.AppContainment()
            assocCredPM.containedData = [PMOneDriveEncryptedCreds]
            assocCredPM.containingApp = [plexigridSalesOffice]
            # Add credentials to meteringData
            assocEncOneDrivePM = pythClasses.ns.EncryptionCredentials()
            assocEncOneDrivePM.encryptCreds = [PMOneDriveCreds]
            assocEncOneDrivePM.encryptedData = [plexigridDataPMOneDrive]
            # Add credentials data to credentials
            assocCredOneDrivePM = pythClasses.ns.InfoContainment()
            assocCredOneDrivePM.containerData = [PMOneDriveEncryptedCreds]
            assocCredOneDrivePM.information = [PMOneDriveCreds]
            # Add credData to OneDrive
            assocCredOneDrive1 = pythClasses.ns.AppContainment()
            assocCredOneDrive1.containedData = [PMOneDriveEncryptedCreds]
            assocCredOneDrive1.containingApp = [cloudOneDrive]
            # Add replicated information to unencrypted metering data
            assocreplicatedDataPMOneDrive = pythClasses.ns.Replica()
            assocreplicatedDataPMOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedDataPMOneDrive.dataReplicas = [plexigridDataPMOneDrive]
            # Add credData to Dev
            assocCredDev = pythClasses.ns.AppContainment()
            assocCredDev.containedData = [DevOneDriveEncryptedCreds]
            assocCredDev.containingApp = [plexigridDevOffice]
            # Add credentials to meteringData
            assocEncOneDriveDev = pythClasses.ns.EncryptionCredentials()
            assocEncOneDriveDev.encryptCreds = [DevOneDriveCreds]
            assocEncOneDriveDev.encryptedData = [plexigridDataDevOneDrive]
            # Add credentials data to credentials
            assocCredOneDriveDev = pythClasses.ns.InfoContainment()
            assocCredOneDriveDev.containerData = [DevOneDriveEncryptedCreds]
            assocCredOneDriveDev.information = [DevOneDriveCreds]
            # Add credData to OneDrive
            assocCredOneDrive2 = pythClasses.ns.AppContainment()
            assocCredOneDrive2.containedData = [DevOneDriveEncryptedCreds]
            assocCredOneDrive2.containingApp = [cloudOneDrive]
            # Add replicated information to unencrypted metering data
            assocreplicatedDataDevOneDrive = pythClasses.ns.Replica()
            assocreplicatedDataDevOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
            assocreplicatedDataDevOneDrive.dataReplicas = [plexigridDataDevOneDrive]
            # Add every association to the model
            
            honorModel.add_association(assocConnSalesnetworkInternet)
            
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
            
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocInternetSalesFirewallVuln)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            
            honorModel.add_association(assocConnSftpSalesNetwork)
            honorModel.add_association(assocConnSftpSales)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredSFTP)
            honorModel.add_association(assocVulnSFTP)
            honorModel.add_association(assocEncryptedData)
            honorModel.add_association(assocUnencryptedData)
            honorModel.add_association(assocDataCloud)
            honorModel.add_association(assocConnOneDriveCloud)
            honorModel.add_association(assocConnCloudOneDrive)
            honorModel.add_association(assocVulnOneDrive)
            honorModel.add_association(assocCloudInternet)

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)
            honorModel.add_association(assocIdentityDevOffice)
            honorModel.add_association(assocIdentityDevUser)

            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocDatabaseData)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocDevtoOneDrive)
            honorModel.add_association(assocSalestoOneDrive)
            honorModel.add_association(assocCredDevIdentity)
            honorModel.add_association(assocCredSalesOneDriveIdentity)
            honorModel.add_association(assocCredMFADevIdentity)
            honorModel.add_association(assocCredMFASalesOneDriveIdentity)
            honorModel.add_association(assocOneDriveIdentityDevUser)
            honorModel.add_association(assocOneDriveIdentityPMUser)
            honorModel.add_association(assocSalestoSFTP)
            honorModel.add_association(assocCredSalesSFTPIdentity)
            honorModel.add_association(assocCredMFASalesSFTPIdentity)
            honorModel.add_association(assocSFTPIdentityPMUser)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)

            honorModel.add_association(assocCredPM)
            honorModel.add_association(assocEncOneDrivePM)
            honorModel.add_association(assocCredOneDrivePM)
            honorModel.add_association(assocCredOneDrive1)
            honorModel.add_association(assocreplicatedDataPMOneDrive)
            honorModel.add_association(assocCredDev)
            honorModel.add_association(assocEncOneDriveDev)
            honorModel.add_association(assocCredOneDriveDev)
            honorModel.add_association(assocCredOneDrive2)
            honorModel.add_association(assocreplicatedDataDevOneDrive)
            honorModel.add_association(assocDataCloudDev)
            honorModel.add_association(assocDataDevTransit)
            honorModel.add_association(assocDataPMTransit)
        
    

################################################## Test 5 ######################################################################## 
        if test_case5:
            pass
################################################## Test 6 ########################################################################       
        if test_case6:
            pass
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

    if addDSO:
        """ For case 5 and 6 the whole system is built in this section"""
################################################## Test 1 ########################################################################       
        if test_case1:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"
            # Internet connected to the salesnetwork
            assocSalesInternet = pythClasses.ns.NetworkConnection()
            assocSalesInternet.networks = [internet]
            assocSalesInternet.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevInternet = pythClasses.ns.NetworkConnection()
            assocDevInternet.networks = [internet]
            assocDevInternet.netConnections = [plexiDevConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User" 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]


            # Smart phone application

            # hardware vuln

            # conn for smartphone

            # office apps application

            # identity office apps

            # user office apps

            # conn for office apps application

            
            
            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DSODMZConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            DMZMailserver.supplyChainAuditing = 1
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]
            

            # data exchanges
            # Data goes is sent from DSO office station
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be sent from DMZ mail server to sales Mail server
            assocSendDMZMail = pythClasses.ns.SendData()
            assocSendDMZMail.senderApp = [DMZMailserver]
            assocSendDMZMail.sentData = [plexigridDataDSO]
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataDSO]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataDSO]

            # Add to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)

            honorModel.add_association(assocSalesInternet)
            honorModel.add_association(assocDevInternet)
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            # Data
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocSendDMZMail)
            honorModel.add_association(assocDataInternet)


            # Save test case
            honorModel.save_to_file("./TestCases/case1.json")
            return "./TestCases/case1.json"

################################################## Test 2 ######################################################################## 
        if test_case2:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"
            # Internet connected to the salesnetwork
            assocSalesInternet = pythClasses.ns.NetworkConnection()
            assocSalesInternet.networks = [internet]
            assocSalesInternet.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevInternet = pythClasses.ns.NetworkConnection()
            assocDevInternet.networks = [internet]
            assocDevInternet.netConnections = [plexiDevConn]
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"
            DMZInternetConn.payloadInspection = 0.95 # shall probably have some kind of IDPS
            DMZInternetConn.restricted = 0.6 # protocols that can be used for exploit are closed

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            DSOOfficeHardwareVuln.effortRequiredToExploit = 1 # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            DSOOfficeHardwareVuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired = 0.8 # difficult but not more than microsoft
            vulnerabilityDSOOffice.userInteractionRequired = 1 # The user has to click something malicious
            vulnerabilityDSOOffice.highPrivilegesRequired = 1 # Need to have admin role
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User" 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            DSOOfficeStationConn.payloadInspection = 0.95 # shall probably have some kind of IDPS
            DSOOfficeStationConn.restricted = 0.6 # protocols that can be used for exploit are closed
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]


            # Smart phone application

            # hardware vuln

            # conn for smartphone

            # office apps application

            # identity office apps

            # user office apps

            # conn for office apps application

            
            
            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DSODMZConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            vulnerabilityDMZMail.highComplexityExploitRequired = 0.95 # hard to exploit
            vulnerabilityDMZMail.networkAccessRequired = 0.95 # need to have network access
            vulnerabilityDMZMail.highPrivilegesRequired = 0.95 # need admin privilege to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]
            

            # data exchanges
            # Data goes is sent from DSO office station
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be sent from DMZ mail server to sales Mail server
            assocSendDMZMail = pythClasses.ns.SendData()
            assocSendDMZMail.senderApp = [DMZMailserver]
            assocSendDMZMail.sentData = [plexigridDataDSO]
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataDSO]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataDSO]
            # The data is accessable from the internet
            assocDataInternetDevTransit = pythClasses.ns.DataInTransit()
            assocDataInternetDevTransit.transitNetwork = [internet]
            assocDataInternetDevTransit.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole PM's network
            assocDataPMTransit = pythClasses.ns.DataInTransit()
            assocDataPMTransit.transitNetwork = [plexiSalesNetwork]
            assocDataPMTransit.transitData = [plexigridDataPMOneDrive]
            # The data is accessable from the internet
            assocDataInternetPMTransit = pythClasses.ns.DataInTransit()
            assocDataInternetPMTransit.transitNetwork = [internet]
            assocDataInternetPMTransit.transitData = [plexigridDataPMOneDrive]
            
            # Add locally downloaded data
            assocLocallyDSO = pythClasses.ns.DataHosting()
            assocLocallyDSO.hostedData = [plexigridDataDSO]
            assocLocallyDSO.hardware = [DSOOfficeHardware]


            # Add to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)

            honorModel.add_association(assocSalesInternet)
            honorModel.add_association(assocDevInternet)
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            honorModel.add_association(assocInternetCloud)
            # Data
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocSendDMZMail)
            honorModel.add_association(assocDataInternet)

            honorModel.add_association(assocDataInternetDevTransit)
            honorModel.add_association(assocDataInternetPMTransit)
            honorModel.add_association(assocLocallyDSO)
            
            # Save test case

            honorModel.save_to_file("./TestCases/case2.json")
            return "./TestCases/case2.json"
        
################################################## Test 3 ######################################################################## 
        if test_case3:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"
            # Internet connected to the salesnetwork
            assocSalesInternet = pythClasses.ns.NetworkConnection()
            assocSalesInternet.networks = [internet]
            assocSalesInternet.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevInternet = pythClasses.ns.NetworkConnection()
            assocDevInternet.networks = [internet]
            assocDevInternet.netConnections = [plexiDevConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User" 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]


            # Smart phone application

            # hardware vuln

            # conn for smartphone

            # office apps application

            # identity office apps

            # user office apps

            # conn for office apps application

            
            
            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DSODMZConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            DMZMailserver.supplyChainAuditing = 1
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]
            

            # data exchanges
            # Data goes is sent from DSO office station
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be in transit through the internet
            assocDataInternet2= pythClasses.ns.DataInTransit()
            assocDataInternet2.transitNetwork = [internet]
            assocDataInternet2.transitData = [plexigridDataPM]
            # Add credData to SFTP
            assocCredSDSO = pythClasses.ns.AppContainment()
            assocCredSDSO.containedData = [DSOEncryptedCreds]
            assocCredSDSO.containingApp = [DSOOfficeStation]
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataDSO]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataDSO]

            # Add to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)

            honorModel.add_association(assocSalesInternet)
            honorModel.add_association(assocDevInternet)
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            # Data
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocCredSDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocDataInternet2)
            # Save test case

            honorModel.save_to_file("./TestCases/case3.json")
            return "./TestCases/case3.json"

################################################## Test 4 ######################################################################## 
        if test_case4:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"
            # Internet connected to the salesnetwork
            assocSalesInternet = pythClasses.ns.NetworkConnection()
            assocSalesInternet.networks = [internet]
            assocSalesInternet.netConnections = [plexiSalesConn]
            # connect dev network to the internet
            assocDevInternet = pythClasses.ns.NetworkConnection()
            assocDevInternet.networks = [internet]
            assocDevInternet.netConnections = [plexiDevConn]
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            DSOOfficeNetwork.networkAccessControl = 0.95
            DSOOfficeNetwork.adversaryInTheMiddleDefense = 0.8
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired = 0.8 # difficult but not more than microsoft
            vulnerabilityDSOOffice.userInteractionRequired = 1 # The user has to click something malicious
            vulnerabilityDSOOffice.highPrivilegesRequired = 1 # Need to have admin role
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User"
            DSORegularUser.securityAwareness = 0.4 # Not very high
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]


            # Smart phone application

            # hardware vuln

            # conn for smartphone

            # office apps application

            # identity office apps

            # user office apps

            # conn for office apps application

            
            
            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DMZInternetConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            DMZNetwork.networkAccessControl = 0.95
            DMZNetwork.adversaryInTheMiddleDefense = 0.8
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            vulnerabilityDMZMail.highComplexityExploitRequired = 0.95 # needs really advanced exploits
            vulnerabilityDMZMail.confidentialityImpactLimitations = 0.95 # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilityDMZMail.availabilityImpactLimitations = 0.95 # microsoft have great resources, related to deny
            vulnerabilityDMZMail.integrityImpactLimitations = 0.95 # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilityDMZMail.highPrivilegesRequired = 1 # need admin access to change anything (microsoft staff)
            vulnerabilityDMZMail.highPrivilegesRequired = 1 # need admin access to change anything (microsoft staff)
            vulnerabilityDMZMail.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]
            

            # data exchanges
            # Data goes is sent from DSO office station
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [plexigridDataDSO]
            # Data will be in transit through the internet
            assocDataInternet2= pythClasses.ns.DataInTransit()
            assocDataInternet2.transitNetwork = [internet]
            assocDataInternet2.transitData = [plexigridDataPM]
            # Add credData to SFTP
            assocCredSDSO = pythClasses.ns.AppContainment()
            assocCredSDSO.containedData = [DSOEncryptedCreds]
            assocCredSDSO.containingApp = [DSOOfficeStation]
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataDSO]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataDSO]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataDSO]
            # The data is accessable from the whole PM's network
            assocDataPMTransit = pythClasses.ns.DataInTransit()
            assocDataPMTransit.transitNetwork = [plexiSalesNetwork]
            assocDataPMTransit.transitData = [plexigridDataPMOneDrive]
            # The data is accessable from the internet
            assocDataInternetPMTransit = pythClasses.ns.DataInTransit()
            assocDataInternetPMTransit.transitNetwork = [internet]
            assocDataInternetPMTransit.transitData = [plexigridDataPMOneDrive]

            # Add to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)

            honorModel.add_association(assocSalesInternet)
            honorModel.add_association(assocDevInternet)
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            honorModel.add_association(assocInternetCloud)
            # Data
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocCredSDSO)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocDataInternet2)

            honorModel.add_association(assocDataInternetDevTransit)
            honorModel.add_association(assocDataInternetPMTransit)
            
            # Save test case

            honorModel.save_to_file("./TestCases/case4.json")
            return "./TestCases/case4.json"
        
################################################## Test 5 ######################################################################## 
        if test_case5:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User" 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]

            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DSODMZConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            DMZMailserver.supplyChainAuditing = 1
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]


            # Add data from DSO -> database
            DataDSO = pythClasses.ns.Data()
            DataDSO.metaconcept = "Data"
            DataDSO.name = "Metering Data"
            # Credentials for encryption
            DSOCreds = pythClasses.ns.Credentials()
            DSOCreds.metaconcept = "Credentials"
            DSOCreds.name = "Encryption keys"
            # Credentials data
            DSOEncryptedCreds = pythClasses.ns.Data()
            DSOEncryptedCreds.metaconcept = "Data"
            DSOEncryptedCreds.name = "Encrypted keys data"
            # SFTP server
            DSOSftp = pythClasses.ns.Application()
            DSOSftp.metaconcept = "Application"
            DSOSftp.name = "Plexigrid SFTP server"
            DSOSftp.supplyChainAuditing = 1
            # Software vulnerability related to SFTP
            vulnerabilitySftp = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySftp.metaconcept = "SoftwareVulnerability"
            vulnerabilitySftp.name = "SoftwareVulnerability SFTP"
            # Connection between SFTP
            DSOSFTPConn = pythClasses.ns.ConnectionRule()
            DSOSFTPConn.metaconcept = "ConnectionRule"
            DSOSFTPConn.name = "ConnectionRule"
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud  
            assocConnSftpSales = pythClasses.ns.ApplicationConnection()
            assocConnSftpSales.applications = [DSOSftp]
            assocConnSftpSales.appConnections = [DSOSFTPConn]
            # Add softwareVuln. to SFTP
            assocVulnSFTP = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnSFTP.application = [DSOSftp]
            assocVulnSFTP.vulnerabilities = [vulnerabilitySftp]
            # Add credentials to meteringData
            assocEncData = pythClasses.ns.EncryptionCredentials()
            assocEncData.encryptCreds = [DSOCreds]
            assocEncData.encryptedData = [DataDSO]
            # Add credentials data to credentials
            assocCredData = pythClasses.ns.InfoContainment()
            assocCredData.containerData = [DSOEncryptedCreds]
            assocCredData.information = [DSOCreds]
            # Add credData to SFTP
            assocCredSFTP = pythClasses.ns.AppContainment()
            assocCredSFTP.containedData = [DSOEncryptedCreds]
            assocCredSFTP.containingApp = [DSOSftp]
            # Add credData to office station
            assocCredoffice = pythClasses.ns.AppContainment()
            assocCredoffice.containedData = [DSOEncryptedCreds]
            assocCredoffice.containingApp = [DSOOfficeStation]
            # Connect SFTP to DSO
            assocConnSftpDSONetwork = pythClasses.ns.NetworkConnection()
            assocConnSftpDSONetwork.networks = [DSOOfficeNetwork]
            assocConnSftpDSONetwork.netConnections = [DSOSFTPConn]
            

            # Send data from DSO to SFTP
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [DataDSO]
            # receive data to SFTP
            assocRecSFTP = pythClasses.ns.ReceiveData()
            assocRecSFTP.receiverApp = [DSOSftp]
            assocRecSFTP.receivedData = [DataDSO]
            # Send data from SFTP to database 
            assocSendSFTP = pythClasses.ns.SendData()
            assocSendSFTP.senderApp = [DSOSftp]
            assocSendSFTP.sentData = [DataDSO]
            # The data is accessable from the whole DSO network
            assocDataDSO = pythClasses.ns.DataInTransit()
            assocDataDSO.transitNetwork = [DSOOfficeNetwork]
            assocDataDSO.transitData = [DataDSO]
            # The data is accessable from the internet
            assocDatainternet = pythClasses.ns.DataInTransit()
            assocDatainternet.transitNetwork = [internet]
            assocDatainternet.transitData = [DataDSO]
            # receive data to database
            assocRecDatabase = pythClasses.ns.ReceiveData()
            assocRecDatabase.receiverApp = [plexigriddatabase]
            assocRecDatabase.receivedData = [DataDSO]
            # Add credentials to the DSO identity connected to sftp
            SFTPDSOCreds = pythClasses.ns.Credentials()
            SFTPDSOCreds.metaconcept = "Credentials"
            SFTPDSOCreds.name = "Password/Username or Key authentication" 
            # Add MFA to this identity
            SFTPMFADSOCreds = pythClasses.ns.Credentials()
            SFTPMFADSOCreds.metaconcept = "Credentials"
            SFTPMFADSOCreds.name = "MFA"
            # Add identity that the PM use for SFTP
            DSOSFTPIdentity = pythClasses.ns.Identity()
            DSOSFTPIdentity.metaconcept = "Identity"
            DSOSFTPIdentity.name = "DSO Identity"
            # Connect DSO identity to SFTP
            assocDSOtoSFTP = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDSOtoSFTP.lowPrivAppIAMs = [DSOSFTPIdentity]
            assocDSOtoSFTP.lowPrivApps = [DSOSftp]
            # Connect credentials to DSO user
            assocCredDSOIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDSOIdentity.identities = [DSOSFTPIdentity]
            assocCredDSOIdentity.credentials = [SFTPDSOCreds]
            # Connect MFA
            assocCredMFADSOIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADSOIdentity.requiredFactors = [SFTPMFADSOCreds]
            assocCredMFADSOIdentity.credentials = [SFTPDSOCreds]
            # Connect pm user to new identity
            assocSFTPIdentityDSOUser = pythClasses.ns.UserAssignedIdentities()
            assocSFTPIdentityDSOUser.users = [DSORegularUser]
            assocSFTPIdentityDSOUser.userIds = [DSOSFTPIdentity]
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
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
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            # Identity symbolyzing a regular User
            plexigridRegularIdentity = pythClasses.ns.Identity()
            plexigridRegularIdentity.metaconcept = "Identity"
            plexigridRegularIdentity.name = "Regular User"
            # User symbolyzing the real human (PM)
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User" 
            # Add dev sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
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
            plexigridDevOffice.name = "Devs Office station"
            plexigridDevOffice.supplyChainAuditing = 1

            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            # Add user to identity to enable social engineering attacks
            assocIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityDevUser.users = [plexigridRegularUser]
            assocIdentityDevUser.userIds = [plexigridRegularIdentity]
            # Add identity to dev office so they have the same privs
            assocIdentityDevOffice = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityDevOffice.lowPrivAppIAMs = [plexigridRegularIdentity]
            assocIdentityDevOffice.lowPrivApps = [plexigridDevOffice]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections internet (conn to DEV)
            assocConnInternettoDev = pythClasses.ns.NetworkConnection()
            assocConnInternettoDev.networks = [internet]
            assocConnInternettoDev.netConnections = [plexiDevConn]
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
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]



            # add assets to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)
            honorModel.add_asset(DataDSO)
            honorModel.add_asset(DSOCreds)
            honorModel.add_asset(DSOEncryptedCreds)
            honorModel.add_asset(DSOSftp)
            honorModel.add_asset(vulnerabilitySftp)
            honorModel.add_asset(DSOSFTPConn)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(SFTPDSOCreds)
            honorModel.add_asset(SFTPMFADSOCreds)
            honorModel.add_asset(DSOSFTPIdentity)
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiDevConn)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityOfficeDev)
            honorModel.add_asset(plexigridRegularIdentity)
            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridDevOffice)



            # add associations
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            honorModel.add_association(assocConnSftpSales)
            honorModel.add_association(assocVulnSFTP)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredSFTP)
            honorModel.add_association(assocCredoffice)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocRecSFTP)
            honorModel.add_association(assocDataDSO)
            honorModel.add_association(assocDatainternet)
            honorModel.add_association(assocRecDatabase)
            honorModel.add_association(assocConnSftpDSONetwork)
            honorModel.add_association(assocDSOtoSFTP)
            honorModel.add_association(assocCredDSOIdentity)
            honorModel.add_association(assocCredMFADSOIdentity)
            honorModel.add_association(assocSFTPIdentityDSOUser)
            honorModel.add_association(assocSendSFTP)
            honorModel.add_association(assocDevSoftwareVuln)
            honorModel.add_association(assocIdentityDevUser)
            honorModel.add_association(assocIdentityDevOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocConnInternettoDev)
           
            

            # Save test case
            honorModel.save_to_file("./TestCases/case5.json")
            return "./TestCases/case5.json"

################################################## Test 6 ########################################################################       
        if test_case6:
            # Internet asset
            internet = pythClasses.ns.Network()
            internet.metaconcept = "Network"
            internet.name = "Internet"

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            DSOOfficeStation.supplyChainAuditing = 1
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User" 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            # connect DSO application to office
            assocConnOfficeDSO = pythClasses.ns.ApplicationConnection()
            assocConnOfficeDSO.applications = [DSOOfficeStation]
            assocConnOfficeDSO.appConnections = [DSOOfficeStationConn]
            # connect DSO network to office station
            assocConnDSOOffice = pythClasses.ns.NetworkConnection()
            assocConnDSOOffice.networks = [DSOOfficeNetwork]
            assocConnDSOOffice.netConnections = [DSOOfficeStationConn]
            # connect hardware to office application
            assocDSOOfficeHardware = pythClasses.ns.SysExecution()
            assocDSOOfficeHardware.hostHardware = [DSOOfficeHardware]
            assocDSOOfficeHardware.sysExecutedApps=[DSOOfficeStation]
            # connect Vulnerability to office stations hardware
            assocVulnHardwareDSOOffice = pythClasses.ns.hardwareVulnerability()    
            assocVulnHardwareDSOOffice.vulnerabilities = [DSOOfficeHardwareVuln]
            assocVulnHardwareDSOOffice.hardware = [DSOOfficeHardware]
            # connect Software vuln. to office station
            assocDSOOfficeVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDSOOfficeVulnerability.application = [DSOOfficeStation]
            assocDSOOfficeVulnerability.vulnerabilities = [vulnerabilityDSOOffice]
            # connect identity to office station
            assocIdentityDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocIdentityDSOOffice.executionPrivIAMs = [DSORegularIdentity]
            assocIdentityDSOOffice.execPrivApps = [DSOOfficeStation]
            # Add user to identity to enable social engineering attacks
            assocDSOIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOIdentityUser.users = [DSORegularUser]
            assocDSOIdentityUser.userIds = [DSORegularIdentity]

            # Connection between DMZ and DSO Office
            DSODMZConn = pythClasses.ns.ConnectionRule()
            DSODMZConn.metaconcept = "ConnectionRule"
            DSODMZConn.name = "ConnectionRule"
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            # connect DSO network to dmz
            assocConnDSODMZ = pythClasses.ns.NetworkConnection()
            assocConnDSODMZ.networks = [DSOOfficeNetwork]
            assocConnDSODMZ.netConnections = [DSODMZConn]
            # Connect firewall to conn
            assocFirewallDMZDSO = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZDSO.connectionRules = [DSODMZConn]
            assocFirewallDMZDSO.routingFirewalls = [DSOFirewallDMZ]
            # connect Vulnerability firewall
            assocDMZDSOFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZDSOFirewallVuln.application = [DSOFirewallDMZ]
            assocDMZDSOFirewallVuln.vulnerabilities = [vulnerabilityFirewallDSODMZ]
            
            # Add DMZ Public LAN network
            DMZNetwork = pythClasses.ns.Network()
            DMZNetwork.metaconcept = "Network"
            DMZNetwork.name = "Public DMZ LAN"
            # connect DMZ network to DSO
            assocConnDSOOfficeDMZ = pythClasses.ns.NetworkConnection()
            assocConnDSOOfficeDMZ.networks = [DMZNetwork]
            assocConnDSOOfficeDMZ.netConnections = [DSODMZConn]
            # Add mail server application
            DMZMailserver = pythClasses.ns.Application()
            DMZMailserver.metaconcept = "Application"
            DMZMailserver.name = "Mail server"
            DMZMailserver.supplyChainAuditing = 1
            # Add mail server software vuln
            vulnerabilityDMZMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDMZMail.metaconcept = "SoftwareVulnerability"
            vulnerabilityDMZMail.name = "SoftwareVulnerability"
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            # connect mail to dmz network
            assocConnMailDmz = pythClasses.ns.ApplicationConnection()
            assocConnMailDmz.applications = [DMZMailserver]
            assocConnMailDmz.appConnections = [DMZMailConn]
            # connect dmz network to mail
            assocConnDmzMail = pythClasses.ns.NetworkConnection()
            assocConnDmzMail.networks = [DMZNetwork]
            assocConnDmzMail.netConnections = [DMZMailConn]
            # connect software vuln to mail server
            assocDMZMailVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZMailVulnerability.application = [DMZMailserver]
            assocDMZMailVulnerability.vulnerabilities = [vulnerabilityDMZMail]
            # connect dmz network to internet
            assocConnDmzInternet = pythClasses.ns.NetworkConnection()
            assocConnDmzInternet.networks = [DMZNetwork]
            assocConnDmzInternet.netConnections = [DMZInternetConn]


            # Add data from DSO -> database
            DataDSO = pythClasses.ns.Data()
            DataDSO.metaconcept = "Data"
            DataDSO.name = "Metering Data"
            # Credentials for encryption
            DSOCreds = pythClasses.ns.Credentials()
            DSOCreds.metaconcept = "Credentials"
            DSOCreds.name = "Encryption keys"
            # Credentials data
            DSOEncryptedCreds = pythClasses.ns.Data()
            DSOEncryptedCreds.metaconcept = "Data"
            DSOEncryptedCreds.name = "Encrypted keys data"
            
            # OneDrive
            OneDriveApp = pythClasses.ns.Application()
            OneDriveApp.metaconcept = "Application"
            OneDriveApp.name = "OneDrive"
            OneDriveApp.supplyChainAuditing = 1
            # Software vulnerability related to OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability"
            # Connection between OneDrive and cloud
            OneDriveCloudConn = pythClasses.ns.ConnectionRule()
            OneDriveCloudConn.metaconcept = "ConnectionRule"
            OneDriveCloudConn.name = "ConnectionRule"
            # Add cloud network
            Cloudnetwork = pythClasses.ns.Network()
            Cloudnetwork.metaconcept = "Network"
            Cloudnetwork.name = "Cloud"
            # Connection between cloud and internet
            internetCloudConn = pythClasses.ns.ConnectionRule()
            internetCloudConn.metaconcept = "ConnectionRule"
            internetCloudConn.name = "ConnectionRule"
            
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud  
            assocConnOneDriveCloud = pythClasses.ns.ApplicationConnection()
            assocConnOneDriveCloud.applications = [OneDriveApp]
            assocConnOneDriveCloud.appConnections = [OneDriveCloudConn]
            assocConnCloudOneDrive = pythClasses.ns.NetworkConnection()
            assocConnCloudOneDrive.networks = [Cloudnetwork]
            assocConnCloudOneDrive.netConnections = [OneDriveCloudConn]
            # Conn between cloud and internet
            assocConnCloudInternet= pythClasses.ns.NetworkConnection()
            assocConnCloudInternet.networks = [Cloudnetwork]
            assocConnCloudInternet.netConnections = [internetCloudConn]
            assocConninternetCloud= pythClasses.ns.NetworkConnection()
            assocConninternetCloud.networks = [internet]
            assocConninternetCloud.netConnections = [internetCloudConn]

            # Add softwareVuln. to SFTP
            assocVulnOneDrive = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocVulnOneDrive.application = [OneDriveApp]
            assocVulnOneDrive.vulnerabilities = [vulnerabilityOneDrive]
            # Add credentials to meteringData
            assocEncData = pythClasses.ns.EncryptionCredentials()
            assocEncData.encryptCreds = [DSOCreds]
            assocEncData.encryptedData = [DataDSO]
            # Add credentials data to credentials
            assocCredData = pythClasses.ns.InfoContainment()
            assocCredData.containerData = [DSOEncryptedCreds]
            assocCredData.information = [DSOCreds]
            # Add credData to OneDrive
            assocCredOnedrive = pythClasses.ns.AppContainment()
            assocCredOnedrive.containedData = [DSOEncryptedCreds]
            assocCredOnedrive.containingApp = [OneDriveApp]
            # Add credData to office station
            assocCredoffice = pythClasses.ns.AppContainment()
            assocCredoffice.containedData = [DSOEncryptedCreds]
            assocCredoffice.containingApp = [DSOOfficeStation]
            

            # Send data from DSO to OneDrive
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [DataDSO]
            # receive data to onedrive
            assocRecOneDrive = pythClasses.ns.ReceiveData()
            assocRecOneDrive.receiverApp = [OneDriveApp]
            assocRecOneDrive.receivedData = [DataDSO]
            # Send data from onedrive to database 
            assocSendOnedrive = pythClasses.ns.SendData()
            assocSendOnedrive.senderApp = [OneDriveApp]
            assocSendOnedrive.sentData = [DataDSO]
            # The data is accessable from the whole DSO network
            assocDataDSO = pythClasses.ns.DataInTransit()
            assocDataDSO.transitNetwork = [DSOOfficeNetwork]
            assocDataDSO.transitData = [DataDSO]
            # The data is accessable from the internet
            assocDatainternet = pythClasses.ns.DataInTransit()
            assocDatainternet.transitNetwork = [internet]
            assocDatainternet.transitData = [DataDSO]
            # receive data to database
            assocRecDatabase = pythClasses.ns.ReceiveData()
            assocRecDatabase.receiverApp = [plexigriddatabase]
            assocRecDatabase.receivedData = [DataDSO]
            # Add credentials to the DSO identity connected to onedrive
            OneDriveDSOCreds = pythClasses.ns.Credentials()
            OneDriveDSOCreds.metaconcept = "Credentials"
            OneDriveDSOCreds.name = "Password/Username" 
            # Add MFA to this identity
            onedriveMFADSOCreds = pythClasses.ns.Credentials()
            onedriveMFADSOCreds.metaconcept = "Credentials"
            onedriveMFADSOCreds.name = "MFA"
            # Add identity that the DSO use for onedrive
            DSOOnedriveIdentity = pythClasses.ns.Identity()
            DSOOnedriveIdentity.metaconcept = "Identity"
            DSOOnedriveIdentity.name = "DSO Identity"
            # Connect DSO identity to SFTP
            assocDSOtoonedrive = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDSOtoonedrive.lowPrivAppIAMs = [DSOOnedriveIdentity]
            assocDSOtoonedrive.lowPrivApps = [OneDriveApp]
            # Connect credentials to DSO user
            assocCredDSOIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDSOIdentity.identities = [DSOOnedriveIdentity]
            assocCredDSOIdentity.credentials = [OneDriveDSOCreds]
            # Connect MFA
            assocCredMFADSOIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADSOIdentity.requiredFactors = [onedriveMFADSOCreds]
            assocCredMFADSOIdentity.credentials = [OneDriveDSOCreds]
            # Connect pm user to new identity
            assocOneDriveIdentityDSOUser = pythClasses.ns.UserAssignedIdentities()
            assocOneDriveIdentityDSOUser.users = [DSORegularUser]
            assocOneDriveIdentityDSOUser.userIds = [DSOOnedriveIdentity]
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
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
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            # Identity symbolyzing a regular User
            plexigridRegularIdentity = pythClasses.ns.Identity()
            plexigridRegularIdentity.metaconcept = "Identity"
            plexigridRegularIdentity.name = "Regular User"
            # User symbolyzing the real human (PM)
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User" 
            # Add dev sophos security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "Sophos"
            plexigridDevIDPS.supplyChainAuditing = 1
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
            plexigridDevOffice.name = "Devs Office station"
            plexigridDevOffice.supplyChainAuditing = 1

            # SoftwareVuln to devs
            assocDevSoftwareVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDevSoftwareVuln.application = [plexigridDevOffice]
            assocDevSoftwareVuln.vulnerabilities = [vulnerabilityOfficeDev]
            # Add user to identity to enable social engineering attacks
            assocIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityDevUser.users = [plexigridRegularUser]
            assocIdentityDevUser.userIds = [plexigridRegularIdentity]
            # Add identity to dev office so they have the same privs
            assocIdentityDevOffice = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocIdentityDevOffice.lowPrivAppIAMs = [plexigridRegularIdentity]
            assocIdentityDevOffice.lowPrivApps = [plexigridDevOffice]
            # Add networkconnections Dev (conn to internet)
            assocConnDevnetworkInternet = pythClasses.ns.NetworkConnection()
            assocConnDevnetworkInternet.networks = [plexiDevNetwork]
            assocConnDevnetworkInternet.netConnections = [plexiDevConn]
            # Add networkconnections internet (conn to DEV)
            assocConnInternettoDev = pythClasses.ns.NetworkConnection()
            assocConnInternettoDev.networks = [internet]
            assocConnInternettoDev.netConnections = [plexiDevConn]
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
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexiDevConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add idps to office stations
            assocIDPSDevOffice = pythClasses.ns.AppProtection()
            assocIDPSDevOffice.protectorIDPSs = [plexigridDevIDPS]
            assocIDPSDevOffice.protectedApps = [plexigridDevOffice]



            # add assets to model
            honorModel.add_asset(internet)
            honorModel.add_asset(DSOOfficeNetwork)
            honorModel.add_asset(DSOOfficeStation)
            honorModel.add_asset(DSOOfficeHardwareVuln)
            honorModel.add_asset(DSOOfficeHardware)
            honorModel.add_asset(vulnerabilityDSOOffice)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSORegularIdentity)
            honorModel.add_asset(DSORegularUser)
            honorModel.add_asset(DSOOfficeStationConn)
            honorModel.add_asset(DSODMZConn)
            honorModel.add_asset(DSOFirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDSODMZ)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZMailserver)
            honorModel.add_asset(DMZMailConn)
            honorModel.add_asset(DMZNetwork)
            honorModel.add_asset(vulnerabilityDMZMail)
            honorModel.add_asset(DMZInternetConn)
            honorModel.add_asset(DataDSO)
            honorModel.add_asset(DSOCreds)
            honorModel.add_asset(DSOEncryptedCreds)
            
            honorModel.add_asset(OneDriveApp)
            honorModel.add_asset(vulnerabilityOneDrive)
            honorModel.add_asset(OneDriveCloudConn)
            honorModel.add_asset(Cloudnetwork)
            honorModel.add_asset(internetCloudConn)
            honorModel.add_asset(plexigriddatabase)
            honorModel.add_asset(OneDriveDSOCreds)
            honorModel.add_asset(onedriveMFADSOCreds)
            honorModel.add_asset(DSOOnedriveIdentity)
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiDevConn)
            honorModel.add_asset(plexigridDevOfficeConn)
            honorModel.add_asset(plexiInternetDevFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityOfficeDev)
            honorModel.add_asset(plexigridRegularIdentity)
            honorModel.add_asset(plexigridRegularUser)
            honorModel.add_asset(plexigridDevIDPS)
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridDevOffice)



            # add associations
            honorModel.add_association(assocConnInternetDMZ)
            honorModel.add_association(assocConnOfficeDSO)
            honorModel.add_association(assocConnDSOOffice)
            honorModel.add_association(assocDSOOfficeHardware)
            honorModel.add_association(assocDSOOfficeVulnerability)
            honorModel.add_association(assocIdentityDSOOffice)
            honorModel.add_association(assocDSOIdentityUser)
            honorModel.add_association(assocConnDSODMZ)
            honorModel.add_association(assocDMZDSOFirewallVuln)
            honorModel.add_association(assocDMZMailVulnerability)
            honorModel.add_association(assocConnDmzMail)
            honorModel.add_association(assocConnDmzInternet)
            honorModel.add_association(assocFirewallDMZDSO)
            honorModel.add_association(assocConnDSOOfficeDMZ)
            honorModel.add_association(assocVulnHardwareDSOOffice)
            honorModel.add_association(assocConnMailDmz)
            honorModel.add_association(assocConnOneDriveCloud)
            honorModel.add_association(assocConnCloudOneDrive)
            honorModel.add_association(assocConnCloudInternet)
            honorModel.add_association(assocConninternetCloud)
            honorModel.add_association(assocVulnOneDrive)
            honorModel.add_association(assocEncData)
            honorModel.add_association(assocCredData)
            honorModel.add_association(assocCredOnedrive)
            honorModel.add_association(assocCredoffice)
            honorModel.add_association(assocSendDSO)
            honorModel.add_association(assocRecOneDrive)
            honorModel.add_association(assocDataDSO)
            honorModel.add_association(assocDatainternet)
            honorModel.add_association(assocRecDatabase)
            honorModel.add_association(assocCredDSOIdentity)
            honorModel.add_association(assocCredMFADSOIdentity)
            honorModel.add_association(assocOneDriveIdentityDSOUser)
            honorModel.add_association(assocSendOnedrive)
            honorModel.add_association(assocDevSoftwareVuln)
            honorModel.add_association(assocIdentityDevUser)
            honorModel.add_association(assocIdentityDevOffice)
            honorModel.add_association(assocConnDevnetworkInternet)
            honorModel.add_association(assocConnDevOffice)
            honorModel.add_association(assocConnOfficeDev)
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocInternetDevFirewall)
            honorModel.add_association(assocInternetDevFirewallVuln)
            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocConnInternettoDev)
            honorModel.add_association(assocDSOtoonedrive)

            # Save test case
            honorModel.save_to_file("./TestCases/case6.json")
            return "./TestCases/case6.json"