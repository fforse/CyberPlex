
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

import random

""" Add Plexigrid assets"""
add_association = True
add_assets = True
# Use the relevant parts of the DSO
addDSO = True

# Case1: Email->Email
# Case2: Email->Onedrive
# Case3: SFTP->Email
# Case4: SFTP->Onedrive
# Case5: DSO SFTP-> database (skip PM)
# Case6: DSO OneDrive -> database (skip PM)

def bernoulli_sample(defenceInPlaceProb):
    """
    Generates a random sample from a bernoulli distribution with probability of implemented defense defenceInPlaceProb.
    """
    if random.random() < defenceInPlaceProb:
        # Defense in place
        return 1.0
    else:
        # No defense
        return 0.0


def add_plexigrid_assets(pythClasses, honorModel, test_case1, test_case2, test_case3, test_case4, test_case5, test_case6, lastTestAttack, replica):
    if add_assets:
################################################## Test 1 ########################################################################       
        if test_case1:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            cloudNetwork.networkAccessControl = bernoulli_sample(0.95)
            cloudNetwork.eavesdropDefense = bernoulli_sample(0.95)
            cloudNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.95)
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            CloudInternetConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            CloudInternetConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network for PM"
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
            plexiMailSalesConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiMailSalesConn.payloadInspection = bernoulli_sample(0.9) #  try to filter malicous payloads
            
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            plexigridDevOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridDevOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall for cloud
            CloudFirewall = pythClasses.ns.RoutingFirewall()
            CloudFirewall.metaconcept = "RoutingFirewall"
            CloudFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetDev.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetDev.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetSales.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetSales.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall for the cloud
            vulnerabilityFirewallCloud = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallCloud.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallCloud.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallCloud.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallCloud.integrityImpactLimitations = bernoulli_sample(0.25)
            
            
            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeSales.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeSales.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.userInteractionRequired =  bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeSales.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeSales.localAccessRequired = bernoulli_sample(0.95) # Need network access to exploit
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeDev.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeDev.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeDev.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeDev.localAccessRequired = bernoulli_sample(0.95) # Need network access to exploit
            # User symbolyzing the real human 
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User"
            plexigridRegularUser.securityAwareness = bernoulli_sample(0.5)
            plexigridRegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # Add pm IDPS security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "IDPS"
            plexigridSalesIDPS.effectiveness = bernoulli_sample(0.9)
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
            plexigridDevIDPS.effectiveness = bernoulli_sample(0.9)
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            plexidatabasecloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexidatabasecloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            plexiApplicationcloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiApplicationcloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.confidentialityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.availabilityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.integrityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95)
            
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            SSHCreds.notGuessable = bernoulli_sample(1)# Almost impossible to guess 
            SSHCreds.unique = bernoulli_sample(1) # completely unique
            SSHCreds.notPhishable = bernoulli_sample(0.95)
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            if replica:
                # Replicated information (to symbolize the same data)
                replicatedMeterDatatoDatabase = pythClasses.ns.Information()
                replicatedMeterDatatoDatabase.metaconcept = "Information"
                replicatedMeterDatatoDatabase.name = "Metering Information"
                honorModel.add_asset(replicatedMeterDatatoDatabase)
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"

            # Add credentials to the dev identity connected to onedrive
            MicrosoftDevCreds = pythClasses.ns.Credentials()
            MicrosoftDevCreds.metaconcept = "Credentials"
            MicrosoftDevCreds.name = "Password/Username" 
            MicrosoftDevCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            MicrosoftDevCreds.unique = bernoulli_sample(0.6)# assume that the password is not used for multiple services
            # Add MFA to this identity
            MicrosoftMFADevCreds = pythClasses.ns.Credentials()
            MicrosoftMFADevCreds.metaconcept = "Credentials"
            MicrosoftMFADevCreds.name = "MFA"
            MicrosoftMFADevCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            MicrosoftMFADevCreds.unique = 1
            # Add credentials to the sales identity connected to onedrive
            MicrosoftSalesCreds = pythClasses.ns.Credentials()
            MicrosoftSalesCreds.metaconcept = "Credentials"
            MicrosoftSalesCreds.name = "Password/Username" 
            MicrosoftSalesCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            MicrosoftSalesCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Add MFA to this identity
            MicrosoftMFASalesCreds = pythClasses.ns.Credentials()
            MicrosoftMFASalesCreds.metaconcept = "Credentials"
            MicrosoftMFASalesCreds.name = "MFA"
            MicrosoftMFASalesCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            MicrosoftMFASalesCreds.unique = 1 # unique
            # Add identity that the dev user use for Microsoft
            plexigridDevMicrosoftIdentity = pythClasses.ns.Identity()
            plexigridDevMicrosoftIdentity.metaconcept = "Identity"
            plexigridDevMicrosoftIdentity.name = "Dev Identity"    
            
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "PM's Office station"
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "PM's Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.8) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.8) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Devs Office station"
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            plexigridSalesOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridSalesOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Mail-Server for Plexigrid project/sales (microsoft server)
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM User" 
            plexigridPMUser.securityAwareness = bernoulli_sample(0.7) # not very aware
            plexigridPMUser.noPasswordReuse = bernoulli_sample(0.5)
            # Software vulnreability for Project/sales mail microsoft server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            vulnerabilitySalesMail.highComplexityExploitRequired = bernoulli_sample(0.95) # needs really advanced exploits
            vulnerabilitySalesMail.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilitySalesMail.availabilityImpactLimitations = bernoulli_sample(0.95)# microsoft have great resources, related to deny
            vulnerabilitySalesMail.integrityImpactLimitations = bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilitySalesMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
            vulnerabilitySalesMail.networkAccessRequired = bernoulli_sample(0.95) # need to be connected to the network to even try to exploit
            # Unencrypted metering Data
            # unencryptedData = pythClasses.ns.Data()
            # unencryptedData.metaconcept = "Data"
            # unencryptedData.name = "Unencrypted Metering Data"

            # Credentials to private dev office station
            plexidevCredentials = pythClasses.ns.Credentials()
            plexidevCredentials.metaconcept = "Credentials"
            plexidevCredentials.name = "Password/Username" 
            plexidevCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexidevCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            plexiPMCredentials.notGuessable = bernoulli_sample(0.6)
            plexiPMCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Metering Data going from DSO->PM
            plexigridDataDSO = pythClasses.ns.Data()
            plexigridDataDSO.metaconcept = "Data"
            plexigridDataDSO.name = "Metering Data"


            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemorySales = pythClasses.ns.Data()
            microsoftAuthAppMemorySales.metaconcept = "Data"
            microsoftAuthAppMemorySales.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppSales = pythClasses.ns.Application()
            microsoftAuthenticatorAppSales.metaconcept = "Application"
            microsoftAuthenticatorAppSales.name = "Microsoft Authenticator App"

            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemoryDev = pythClasses.ns.Data()
            microsoftAuthAppMemoryDev.metaconcept = "Data"
            microsoftAuthAppMemoryDev.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppDev = pythClasses.ns.Application()
            microsoftAuthenticatorAppDev.metaconcept = "Application"
            microsoftAuthenticatorAppDev.name = "Microsoft Authenticator App"


    

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
            honorModel.add_asset(CloudFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityFirewallCloud)
        
        
            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(cloudNetwork)
            honorModel.add_asset(CloudInternetConn)
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
            honorModel.add_asset(plexigridDataSSH)
            honorModel.add_asset(MicrosoftDevCreds)
            honorModel.add_asset(MicrosoftMFADevCreds)
            honorModel.add_asset(MicrosoftSalesCreds)
            honorModel.add_asset(MicrosoftMFASalesCreds)

            honorModel.add_asset(plexigridDevMicrosoftIdentity)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

            # honorModel.add_asset(unencryptedData)

            honorModel.add_asset(plexidevCredentials)
            honorModel.add_asset(plexiDevIdentityOffice)
            honorModel.add_asset(plexiPMIdentityOffice)
            honorModel.add_asset(plexiPMCredentials)

            honorModel.add_asset(microsoftAuthAppMemorySales)
            honorModel.add_asset(microsoftAuthenticatorAppSales)
            honorModel.add_asset(microsoftAuthAppMemoryDev)
            honorModel.add_asset(microsoftAuthenticatorAppDev)

################################################## Test 2 ########################################################################       

        if test_case2:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            cloudNetwork.networkAccessControl = bernoulli_sample(0.95)
            cloudNetwork.eavesdropDefense = bernoulli_sample(0.95)
            cloudNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.95)
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            CloudInternetConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            CloudInternetConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # OneDrive for Plexigrid project/sales
            cloudOneDrive = pythClasses.ns.Application()
            cloudOneDrive.metaconcept = "Application"
            cloudOneDrive.name = "OneDrive"
            # connection between cloud network and OneDrive
            plexiCloudOneDriveConn = pythClasses.ns.ConnectionRule()
            plexiCloudOneDriveConn.metaconcept = "ConnectionRule"
            plexiCloudOneDriveConn.name = "ConnectionRule"
            plexiCloudOneDriveConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiCloudOneDriveConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Software vulnreability for OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability OneDrive"
            vulnerabilityOneDrive.highComplexityExploitRequired = bernoulli_sample(0.95) # needs really advanced exploits
            vulnerabilityOneDrive.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilityOneDrive.availabilityImpactLimitations = bernoulli_sample(0.95) # microsoft have great resources, related to deny
            vulnerabilityOneDrive.integrityImpactLimitations =bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilityOneDrive.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
            vulnerabilityOneDrive.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network for PM"
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
            plexiMailSalesConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiMailSalesConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            plexigridDevOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridDevOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall for cloud
            CloudFirewall = pythClasses.ns.RoutingFirewall()
            CloudFirewall.metaconcept = "RoutingFirewall"
            CloudFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetDev.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetDev.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetSales.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetSales.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall for the cloud
            vulnerabilityFirewallCloud = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallCloud.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallCloud.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallCloud.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallCloud.integrityImpactLimitations = bernoulli_sample(0.25)

            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeSales.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeSales.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.userInteractionRequired = bernoulli_sample(0.9) # The user has to click something malicious
            vulnerabilityOfficeSales.highPrivilegesRequired = bernoulli_sample(0.8) # Need to have admin role
            vulnerabilityOfficeSales.localAccessRequired = 1 # Need network access to exploit
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeDev.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeDev.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.userInteractionRequired = bernoulli_sample(0.9) # The user has to click something malicious
            vulnerabilityOfficeDev.highPrivilegesRequired = bernoulli_sample(0.8) # Need to have admin role
            vulnerabilityOfficeDev.localAccessRequired = 1 # Need network access to exploit
            # User symbolyzing the real human 
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User"
            plexigridRegularUser.securityAwareness = bernoulli_sample(0.5)
            plexigridRegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # Add pm IDPS security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "IDPS"
            plexigridSalesIDPS.effectiveness = bernoulli_sample(0.9)
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
            plexigridDevIDPS.effectiveness = bernoulli_sample(0.9)
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            plexidatabasecloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexidatabasecloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            plexiApplicationcloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiApplicationcloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.confidentialityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.availabilityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.integrityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95)
            
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            SSHCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            SSHCreds.unique = 1 # completely unique
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            if replica:
                # Replicated information (to symbolize the same data)
                replicatedMeterDatatoDatabase = pythClasses.ns.Information()
                replicatedMeterDatatoDatabase.metaconcept = "Information"
                replicatedMeterDatatoDatabase.name = "Metering Information"
                honorModel.add_asset(replicatedMeterDatatoDatabase)
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
            # Add credentials to the dev identity connected to onedrive
            OneDriveDevCreds = pythClasses.ns.Credentials()
            OneDriveDevCreds.metaconcept = "Credentials"
            OneDriveDevCreds.name = "Password/Username" 
            OneDriveDevCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveDevCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            OneDriveSalesCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveSalesCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            PMOneDriveCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
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
            DevOneDriveCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            DevOneDriveCreds.unique = 1 # completely unique
            # Credentials data
            DevOneDriveEncryptedCreds = pythClasses.ns.Data()
            DevOneDriveEncryptedCreds.metaconcept = "Data"
            DevOneDriveEncryptedCreds.name = "Encrypted keys data"
            
            
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "PM's Office station"
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "PM's Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Devs Office station"
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            plexigridSalesOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridSalesOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Mail-Server for Plexigrid project/sales (microsoft server)
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM User" 
            plexigridPMUser.securityAwareness = bernoulli_sample(0.7) # not very aware
            plexigridRegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # Software vulnreability for Project/sales mail microsoft server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            vulnerabilitySalesMail.highComplexityExploitRequired = bernoulli_sample(0.95) # needs really advanced exploits
            vulnerabilitySalesMail.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilitySalesMail.availabilityImpactLimitations = bernoulli_sample(0.95) # microsoft have great resources, related to deny
            vulnerabilitySalesMail.integrityImpactLimitations = bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilitySalesMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
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
            plexidevCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexidevCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            plexiPMCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexiPMCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services


            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemorySales = pythClasses.ns.Data()
            microsoftAuthAppMemorySales.metaconcept = "Data"
            microsoftAuthAppMemorySales.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppSales = pythClasses.ns.Application()
            microsoftAuthenticatorAppSales.metaconcept = "Application"
            microsoftAuthenticatorAppSales.name = "Microsoft Authenticator App"

            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemoryDev = pythClasses.ns.Data()
            microsoftAuthAppMemoryDev.metaconcept = "Data"
            microsoftAuthAppMemoryDev.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppDev = pythClasses.ns.Application()
            microsoftAuthenticatorAppDev.metaconcept = "Application"
            microsoftAuthenticatorAppDev.name = "Microsoft Authenticator App"
            

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
            honorModel.add_asset(CloudFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityFirewallCloud)

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

            honorModel.add_asset(microsoftAuthAppMemorySales)
            honorModel.add_asset(microsoftAuthenticatorAppSales)
            honorModel.add_asset(microsoftAuthAppMemoryDev)
            honorModel.add_asset(microsoftAuthenticatorAppDev)


            

################################################## Test 3 ########################################################################       

        if test_case3:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            cloudNetwork.networkAccessControl = bernoulli_sample(0.95)
            cloudNetwork.eavesdropDefense = bernoulli_sample(0.95)
            cloudNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.95)
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            CloudInternetConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            CloudInternetConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network for PM"
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
            plexiMailSalesConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiMailSalesConn.payloadInspection = bernoulli_sample(0.9) #  try to filter malicous payloads
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            plexigridDevOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridDevOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall for cloud
            CloudFirewall = pythClasses.ns.RoutingFirewall()
            CloudFirewall.metaconcept = "RoutingFirewall"
            CloudFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetDev.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetDev.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetSales.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetSales.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall for the cloud
            vulnerabilityFirewallCloud = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallCloud.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallCloud.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallCloud.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallCloud.integrityImpactLimitations = bernoulli_sample(0.25)

            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeSales.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeSales.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeSales.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeSales.localAccessRequired = bernoulli_sample(0.95) # Need network access to exploit
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeDev.highComplexityExploitRequired = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeDev.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeDev.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeDev.localAccessRequired = bernoulli_sample(0.95) # Need network access to exploit
            # User symbolyzing the real human 
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User"
            plexigridRegularUser.securityAwareness = bernoulli_sample(0.5)
            plexigridRegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # Add pm IDPS security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "IDPS"
            plexigridSalesIDPS.effectiveness = bernoulli_sample(0.9)
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
            plexigridDevIDPS.effectiveness = bernoulli_sample(0.9)
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            plexidatabasecloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexidatabasecloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            plexiApplicationcloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiApplicationcloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.confidentialityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.availabilityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.integrityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95)
            

            # SFTP assets
            # Credentials for encryption to SFTP
            SFTPCreds = pythClasses.ns.Credentials()
            SFTPCreds.metaconcept = "Credentials"
            SFTPCreds.name = "Encryption keys"
            SFTPCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            SFTPCreds.unique = 1 # completely unique
            # Credentials data
            SFTPEncryptedCreds = pythClasses.ns.Data()
            SFTPEncryptedCreds.metaconcept = "Data"
            SFTPEncryptedCreds.name = "Encrypted keys data"
            # Metering Data going from DSO-> SFTP
            plexigridDataSFTP = pythClasses.ns.Data()
            plexigridDataSFTP.metaconcept = "Data"
            plexigridDataSFTP.name = "Metering Data"
            # Add credentials to the dev identity connected to SFTP
            SFTPPMCreds = pythClasses.ns.Credentials()
            SFTPPMCreds.metaconcept = "Credentials"
            SFTPPMCreds.name = "Key-pair" 
            SFTPPMCreds.notGuessable = bernoulli_sample(1) # How hard it is to guess the password (not a part of the most common password dictionary)
            SFTPPMCreds.unique = 1 # assume that the password is not used for multiple services
            SFTPPMCreds.notPhishable = bernoulli_sample(0.95)
            # Add passphrase to this identity
            SFTPMFAPMCreds = pythClasses.ns.Credentials()
            SFTPMFAPMCreds.metaconcept = "Credentials"
            SFTPMFAPMCreds.name = "passPhrase"
            SFTPMFAPMCreds.unique = bernoulli_sample(0.6) 
            SFTPMFAPMCreds.notGuessable = bernoulli_sample(0.6)
            # Add identity to PM to SFTP
            plexigridPMSFTPIdentity = pythClasses.ns.Identity()
            plexigridPMSFTPIdentity.metaconcept = "Identity"
            plexigridPMSFTPIdentity.name = "PM SFTP Identity"    

            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            SSHCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            SSHCreds.unique = 1 # completely unique
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            if replica:
                # Replicated information (to symbolize the same data)
                replicatedMeterDatatoDatabase = pythClasses.ns.Information()
                replicatedMeterDatatoDatabase.metaconcept = "Information"
                replicatedMeterDatatoDatabase.name = "Metering Information"
                honorModel.add_asset(replicatedMeterDatatoDatabase)
            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"


            # Add credentials to the dev identity connected to onedrive
            MicrosoftDevCreds = pythClasses.ns.Credentials()
            MicrosoftDevCreds.metaconcept = "Credentials"
            MicrosoftDevCreds.name = "Password/Username" 
            MicrosoftDevCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            MicrosoftDevCreds.unique = bernoulli_sample(0.6)# assume that the password is not used for multiple services
            # Add MFA to this identity
            MicrosoftMFADevCreds = pythClasses.ns.Credentials()
            MicrosoftMFADevCreds.metaconcept = "Credentials"
            MicrosoftMFADevCreds.name = "MFA"
            MicrosoftMFADevCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            MicrosoftMFADevCreds.unique = 1
            # Add credentials to the sales identity connected to onedrive
            MicrosoftSalesCreds = pythClasses.ns.Credentials()
            MicrosoftSalesCreds.metaconcept = "Credentials"
            MicrosoftSalesCreds.name = "Password/Username" 
            MicrosoftSalesCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            MicrosoftSalesCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Add MFA to this identity
            MicrosoftMFASalesCreds = pythClasses.ns.Credentials()
            MicrosoftMFASalesCreds.metaconcept = "Credentials"
            MicrosoftMFASalesCreds.name = "MFA"
            MicrosoftMFASalesCreds.notPhishable = 1 # cannot phish the phone needed to authenticate
            MicrosoftMFASalesCreds.unique = 1 # unique
            # Add identity that the dev user use for Microsoft
            plexigridDevMicrosoftIdentity = pythClasses.ns.Identity()
            plexigridDevMicrosoftIdentity.metaconcept = "Identity"
            plexigridDevMicrosoftIdentity.name = "Dev Identity"    
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "PM's Office station"
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "PM's Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Devs Office station"
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            plexigridSalesOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridSalesOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Mail-Server for Plexigrid project/sales (microsoft server)
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM User"
            plexigridPMUser.securityAwareness = bernoulli_sample(0.5) # not very aware
            plexigridPMUser.noPasswordReuse = bernoulli_sample(0.5)
            # Software vulnreability for Project/sales mail microsoft server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            vulnerabilitySalesMail.highComplexityExploitRequired = 1 # needs really advanced exploits
            vulnerabilitySalesMail.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilitySalesMail.availabilityImpactLimitations = bernoulli_sample(0.95) # microsoft have great resources, related to deny
            vulnerabilitySalesMail.integrityImpactLimitations = bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilitySalesMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
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
            plexidevCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexidevCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            plexiPMCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexiPMCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services

            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemorySales = pythClasses.ns.Data()
            microsoftAuthAppMemorySales.metaconcept = "Data"
            microsoftAuthAppMemorySales.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppSales = pythClasses.ns.Application()
            microsoftAuthenticatorAppSales.metaconcept = "Application"
            microsoftAuthenticatorAppSales.name = "Microsoft Authenticator App"

            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemoryDev = pythClasses.ns.Data()
            microsoftAuthAppMemoryDev.metaconcept = "Data"
            microsoftAuthAppMemoryDev.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppDev = pythClasses.ns.Application()
            microsoftAuthenticatorAppDev.metaconcept = "Application"
            microsoftAuthenticatorAppDev.name = "Microsoft Authenticator App"
            

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
            honorModel.add_asset(CloudFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityFirewallCloud)

            honorModel.add_asset(plexigridDevHardware)
            honorModel.add_asset(plexigridSalesHardware)
            honorModel.add_asset(plexigridDevHardwarevuln)
            honorModel.add_asset(plexigridSalesHardwarevuln)
            honorModel.add_asset(cloudNetwork)
            honorModel.add_asset(CloudInternetConn)
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
            honorModel.add_asset(plexigridDataSSH)
            honorModel.add_asset(MicrosoftDevCreds)
            honorModel.add_asset(MicrosoftMFADevCreds)
            honorModel.add_asset(MicrosoftSalesCreds)
            honorModel.add_asset(MicrosoftMFASalesCreds)

            honorModel.add_asset(plexigridDevMicrosoftIdentity)

            honorModel.add_asset(plexigridApplication)
            honorModel.add_asset(plexiApplicationcloudconn)
            honorModel.add_asset(plexigridAppDatabaseHardware)
            honorModel.add_asset(plexigridAppDataBaseHardwarevuln)

            # honorModel.add_asset(unencryptedData)

            honorModel.add_asset(plexidevCredentials)
            honorModel.add_asset(plexiDevIdentityOffice)
            honorModel.add_asset(plexiPMIdentityOffice)
            honorModel.add_asset(plexiPMCredentials)
            
            # SFTP assets
            honorModel.add_asset(SFTPCreds)
            honorModel.add_asset(SFTPEncryptedCreds)
            honorModel.add_asset(plexigridDataSFTP)
            honorModel.add_asset(plexigridPMSFTPIdentity)
            honorModel.add_asset(SFTPPMCreds)
            honorModel.add_asset(SFTPMFAPMCreds)

            honorModel.add_asset(microsoftAuthAppMemorySales)
            honorModel.add_asset(microsoftAuthenticatorAppSales)
            honorModel.add_asset(microsoftAuthAppMemoryDev)
            honorModel.add_asset(microsoftAuthenticatorAppDev)
            


################################################## Test 4 ########################################################################       

        if test_case4:
            # Network (Cloud network)
            cloudNetwork = pythClasses.ns.Network()
            cloudNetwork.metaconcept = "Network"
            cloudNetwork.name = "Cloud network"
            cloudNetwork.networkAccessControl = bernoulli_sample(0.95)
            cloudNetwork.eavesdropDefense = bernoulli_sample(0.95)
            cloudNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.95)
            # connection node between cloud and internet
            CloudInternetConn = pythClasses.ns.ConnectionRule()
            CloudInternetConn.metaconcept = "ConnectionRule"
            CloudInternetConn.name = "ConnectionRule"
            CloudInternetConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            CloudInternetConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # OneDrive for Plexigrid project/sales
            cloudOneDrive = pythClasses.ns.Application()
            cloudOneDrive.metaconcept = "Application"
            cloudOneDrive.name = "OneDrive"
            # connection between cloud network and OneDrive
            plexiCloudOneDriveConn = pythClasses.ns.ConnectionRule()
            plexiCloudOneDriveConn.metaconcept = "ConnectionRule"
            plexiCloudOneDriveConn.name = "ConnectionRule"
            plexiCloudOneDriveConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiCloudOneDriveConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Software vulnreability for OneDrive
            vulnerabilityOneDrive = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOneDrive.metaconcept = "SoftwareVulnerability"
            vulnerabilityOneDrive.name = "SoftwareVulnerability OneDrive"
            vulnerabilityOneDrive.highComplexityExploitRequired = bernoulli_sample(0.95) # needs really advanced exploits
            vulnerabilityOneDrive.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilityOneDrive.availabilityImpactLimitations = bernoulli_sample(0.95) # microsoft have great resources, related to deny
            vulnerabilityOneDrive.integrityImpactLimitations= bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilityOneDrive.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
            vulnerabilityOneDrive.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
            vulnerabilityOneDrive.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Network (Plexigrid Development LAN)
            plexiDevNetwork = pythClasses.ns.Network()
            plexiDevNetwork.metaconcept = "Network"
            plexiDevNetwork.name = "Open/Home network"
            # Network (Plexigrid project/sales LAN)
            plexiSalesNetwork = pythClasses.ns.Network()
            plexiSalesNetwork.metaconcept = "Network"
            plexiSalesNetwork.name = "Open/Home network for PM"
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
            plexiMailSalesConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiMailSalesConn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # connection between Dev network and Dev office
            plexigridDevOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridDevOfficeConn.metaconcept = "ConnectionRule"
            plexigridDevOfficeConn.name = "ConnectionRule"
            plexigridDevOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridDevOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Add firewall between internet and dev
            plexiInternetDevFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetDevFirewall.metaconcept = "RoutingFirewall"
            plexiInternetDevFirewall.name = "Firewall"
            # Add firewall between internet and sales
            plexiInternetSalesFirewall = pythClasses.ns.RoutingFirewall()
            plexiInternetSalesFirewall.metaconcept = "RoutingFirewall"
            plexiInternetSalesFirewall.name = "Firewall"
            # Add firewall for cloud
            CloudFirewall = pythClasses.ns.RoutingFirewall()
            CloudFirewall.metaconcept = "RoutingFirewall"
            CloudFirewall.name = "Firewall"
            # Add software vulnerabilities to firewall internet/dev
            vulnerabilityFirewallInternetDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetDev.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetDev.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetDev.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall internet/sales
            vulnerabilityFirewallInternetSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallInternetSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallInternetSales.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallInternetSales.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallInternetSales.integrityImpactLimitations = bernoulli_sample(0.25)
            # Add software vulnerabilities to firewall for the cloud
            vulnerabilityFirewallCloud = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallCloud.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallCloud.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallCloud.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallCloud.integrityImpactLimitations = bernoulli_sample(0.7)
            # Add software vulnerabilities to sales office
            vulnerabilityOfficeSales = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeSales.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeSales.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeSales.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeSales.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeSales.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeSales.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeSales.localAccessRequired = 1 # Need network access to exploit
            # Add software vulnerabilities to devs office
            vulnerabilityOfficeDev = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityOfficeDev.metaconcept = "SoftwareVulnerability"
            vulnerabilityOfficeDev.name = "SoftwareVulnerability Office"
            vulnerabilityOfficeDev.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityOfficeDev.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityOfficeDev.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityOfficeDev.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityOfficeDev.localAccessRequired = 1 # Need network access to exploit
            # User symbolyzing the real human 
            plexigridRegularUser = pythClasses.ns.User()
            plexigridRegularUser.metaconcept = "User"
            plexigridRegularUser.name = "Dev User"
            plexigridRegularUser.securityAwareness = bernoulli_sample(0.7)
            plexigridRegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # Add pm IDPS security suite
            plexigridSalesIDPS = pythClasses.ns.IDPS()
            plexigridSalesIDPS.metaconcept = "IDPS"
            plexigridSalesIDPS.name = "IDPS"
            plexigridSalesIDPS.effectiveness = bernoulli_sample(0.9)
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
            plexigridDevIDPS.effectiveness = bernoulli_sample(0.9)
            # Add plexigrid database
            plexigriddatabase = pythClasses.ns.Application()
            plexigriddatabase.metaconcept = "Application"
            plexigriddatabase.name = "Plexigrid Database"
            # Conn between database and cloud
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            plexidatabasecloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexidatabasecloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            # Add plexigrid application
            plexigridApplication = pythClasses.ns.Application()
            plexigridApplication.metaconcept = "Application"
            plexigridApplication.name = "Plexigrid Web Application"
            # Conn between application och cloud
            plexiApplicationcloudconn = pythClasses.ns.ConnectionRule()
            plexiApplicationcloudconn.metaconcept = "ConnectionRule"
            plexiApplicationcloudconn.name = "ConnectionRule"
            plexiApplicationcloudconn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexiApplicationcloudconn.payloadInspection = bernoulli_sample(0.9) # Microsoft has IDPS or firewall that try to filter malicous payloads
            
            # Add hardware that holds web application and database
            plexigridAppDatabaseHardware = pythClasses.ns.Hardware()
            plexigridAppDatabaseHardware.metaconcept = "Hardware"
            plexigridAppDatabaseHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridAppDataBaseHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridAppDataBaseHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.name = "HardwareVulnerability"
            plexigridAppDataBaseHardwarevuln.confidentialityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.availabilityImpactLimitations = bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.integrityImpactLimitations= bernoulli_sample(0.95) # assume CIA triad is provided by the cloud provider
            plexigridAppDataBaseHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95)
            
            # Credentials for encryption to database
            SSHCreds = pythClasses.ns.Credentials()
            SSHCreds.metaconcept = "Credentials"
            SSHCreds.name = "Encryption keys"
            SSHCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            SSHCreds.unique = 1.0 # completely unique
            # Credentials data
            SSHEncryptedCreds = pythClasses.ns.Data()
            SSHEncryptedCreds.metaconcept = "Data"
            SSHEncryptedCreds.name = "Encrypted keys data"
            if replica:
                # Replicated information (to symbolize the same data)
                replicatedMeterDatatoDatabase = pythClasses.ns.Information()
                replicatedMeterDatatoDatabase.metaconcept = "Information"
                replicatedMeterDatatoDatabase.name = "Metering Information"
                honorModel.add_asset(replicatedMeterDatatoDatabase)

            # Metering Data going from dev-> database
            plexigridDataSSH = pythClasses.ns.Data()
            plexigridDataSSH.metaconcept = "Data"
            plexigridDataSSH.name = "Metering Data"
            # Add credentials to the dev identity connected to onedrive
            OneDriveDevCreds = pythClasses.ns.Credentials()
            OneDriveDevCreds.metaconcept = "Credentials"
            OneDriveDevCreds.name = "Password/Username" 
            OneDriveDevCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveDevCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Add MFA to this identity
            OneDriveMFADevCreds = pythClasses.ns.Credentials()
            OneDriveMFADevCreds.metaconcept = "Credentials"
            OneDriveMFADevCreds.name = "MFA"
            OneDriveMFADevCreds.notPhishable = bernoulli_sample(1) # cannot phish the phone needed to authenticate
            OneDriveMFADevCreds.unique = bernoulli_sample(1)
            # Add credentials to the sales identity connected to onedrive
            OneDriveSalesCreds = pythClasses.ns.Credentials()
            OneDriveSalesCreds.metaconcept = "Credentials"
            OneDriveSalesCreds.name = "Password/Username" 
            OneDriveSalesCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            OneDriveSalesCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Add MFA to this identity
            OneDriveMFASalesCreds = pythClasses.ns.Credentials()
            OneDriveMFASalesCreds.metaconcept = "Credentials"
            OneDriveMFASalesCreds.name = "MFA"
            OneDriveMFASalesCreds.notPhishable = bernoulli_sample(1) # cannot phish the phone needed to authenticate
            OneDriveMFASalesCreds.unique = bernoulli_sample(1) # unique
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
            PMOneDriveCreds.notGuessable = bernoulli_sample(0.95) # Almost impossible to guess 
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
            DevOneDriveCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            DevOneDriveCreds.unique = 1 # completely unique
            # Credentials data
            DevOneDriveEncryptedCreds = pythClasses.ns.Data()
            DevOneDriveEncryptedCreds.metaconcept = "Data"
            DevOneDriveEncryptedCreds.name = "Encrypted keys data"
            
            
            # Add PM office
            plexigridSalesOffice = pythClasses.ns.Application()
            plexigridSalesOffice.metaconcept = "Application"
            plexigridSalesOffice.name = "PM's Office station"
            # Add hardware (computer) to Sales office
            plexigridSalesHardware = pythClasses.ns.Hardware()
            plexigridSalesHardware.metaconcept = "Hardware"
            plexigridSalesHardware.name = "PM's Hardware"
            # Add hardware vulnerability
            plexigridSalesHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridSalesHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridSalesHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add hardware (computer) to Dev office
            plexigridDevHardware = pythClasses.ns.Hardware()
            plexigridDevHardware.metaconcept = "Hardware"
            plexigridDevHardware.name = "Hardware"
            # Add hardware vulnerability
            plexigridDevHardwarevuln = pythClasses.ns.HardwareVulnerability()
            plexigridDevHardwarevuln.metaconcept = "HardwareVulnerability"
            plexigridDevHardwarevuln.name = "HardwareVulnerability"
            plexigridSalesHardwarevuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            plexigridSalesHardwarevuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Add dev office
            plexigridDevOffice = pythClasses.ns.Application()
            plexigridDevOffice.metaconcept = "Application"
            plexigridDevOffice.name = "Devs Office station"
            # connection between sales network PM office computer
            plexigridSalesOfficeConn = pythClasses.ns.ConnectionRule()
            plexigridSalesOfficeConn.metaconcept = "ConnectionRule"
            plexigridSalesOfficeConn.name = "ConnectionRule"
            plexigridSalesOfficeConn.restricted = bernoulli_sample(0.8) # ports on the computer that are blocked
            plexigridSalesOfficeConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Mail-Server for Plexigrid project/sales (microsoft server)
            plexigridSalesMail = pythClasses.ns.Application()
            plexigridSalesMail.metaconcept = "Application"
            plexigridSalesMail.name = "mail server"
            # Identity symbolyzing the Admin (PM)
            plexigridPMIdentity = pythClasses.ns.Identity()
            plexigridPMIdentity.metaconcept = "Identity"
            plexigridPMIdentity.name = "PM identity"
            # User symbolyzing the real human (PM)
            plexigridPMUser = pythClasses.ns.User()
            plexigridPMUser.metaconcept = "User"
            plexigridPMUser.name = "PM User" 
            plexigridPMUser.securityAwareness = bernoulli_sample(0.5) # not very aware
            plexigridPMUser.noPasswordReuse = bernoulli_sample(0.5)
            # Software vulnreability for Project/sales mail microsoft server
            vulnerabilitySalesMail = pythClasses.ns.SoftwareVulnerability()
            vulnerabilitySalesMail.metaconcept = "SoftwareVulnerability"
            vulnerabilitySalesMail.name = "SoftwareVulnerability Mail server"
            vulnerabilitySalesMail.highComplexityExploitRequired = bernoulli_sample(0.95) # needs really advanced exploits
            vulnerabilitySalesMail.confidentialityImpactLimitations = bernoulli_sample(0.95) # Even if an exploit works it has limited effect on the confidentiality, stolen encryption keys and password can't be used on data directly due to the in "rest" encryption 
            vulnerabilitySalesMail.availabilityImpactLimitations = bernoulli_sample(0.95) # microsoft have great resources, related to deny
            vulnerabilitySalesMail.integrityImpactLimitations= bernoulli_sample(0.95) # Tough to modify the data the attacker want since the data is stored encrypted as chunks in different containers
            vulnerabilitySalesMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin access to change anything (microsoft staff)
            vulnerabilitySalesMail.networkAccessRequired = 1 # need to be connected to the network to even try to exploit
            # Unencrypted metering Data
            unencryptedData = pythClasses.ns.Data()
            unencryptedData.metaconcept = "Data"
            unencryptedData.name = "Unencrypted Metering Data"
            
            # SFTP assets
            # Credentials for encryption to SFTP
            SFTPCreds = pythClasses.ns.Credentials()
            SFTPCreds.metaconcept = "Credentials"
            SFTPCreds.name = "Encryption keys"
            SFTPCreds.notGuessable = bernoulli_sample(1) # Almost impossible to guess 
            SFTPCreds.unique = 1 # completely unique
            # Credentials data
            SFTPEncryptedCreds = pythClasses.ns.Data()
            SFTPEncryptedCreds.metaconcept = "Data"
            SFTPEncryptedCreds.name = "Encrypted keys data"
            # Metering Data going from DSO-> SFTP
            plexigridDataSFTP = pythClasses.ns.Data()
            plexigridDataSFTP.metaconcept = "Data"
            plexigridDataSFTP.name = "Metering Data"
            # Add credentials to the dev identity connected to SFTP
            SFTPPMCreds = pythClasses.ns.Credentials()
            SFTPPMCreds.metaconcept = "Credentials"
            SFTPPMCreds.name = "Key-pair" 
            SFTPPMCreds.notGuessable = bernoulli_sample(1) # How hard it is to guess the password (not a part of the most common password dictionary)
            SFTPPMCreds.unique = 1.0 # assume that the password is not used for multiple services
            SFTPPMCreds.notPhishable = bernoulli_sample(0.95)
            # Add MFA to this identity
            SFTPMFAPMCreds = pythClasses.ns.Credentials()
            SFTPMFAPMCreds.metaconcept = "Credentials"
            SFTPMFAPMCreds.name = "passPhrase"
            SFTPMFAPMCreds.unique = bernoulli_sample(0.6) # cannot phish the phone needed to authenticate
            SFTPMFAPMCreds.notGuessable = bernoulli_sample(0.6)
            # Add identity to PM to SFTP
            plexigridPMSFTPIdentity = pythClasses.ns.Identity()
            plexigridPMSFTPIdentity.metaconcept = "Identity"
            plexigridPMSFTPIdentity.name = "PM SFTP Identity"   

            # Credentials to private dev office station
            plexidevCredentials = pythClasses.ns.Credentials()
            plexidevCredentials.metaconcept = "Credentials"
            plexidevCredentials.name = "Password/Username" 
            plexidevCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexidevCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
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
            plexiPMCredentials.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            plexiPMCredentials.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services


            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemorySales = pythClasses.ns.Data()
            microsoftAuthAppMemorySales.metaconcept = "Data"
            microsoftAuthAppMemorySales.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppSales = pythClasses.ns.Application()
            microsoftAuthenticatorAppSales.metaconcept = "Application"
            microsoftAuthenticatorAppSales.name = "Microsoft Authenticator App"

            # Add the microsoft data required to use the credentials related to MFA
            microsoftAuthAppMemoryDev = pythClasses.ns.Data()
            microsoftAuthAppMemoryDev.metaconcept = "Data"
            microsoftAuthAppMemoryDev.name = "Microsoft Auth App Memory"
            # Add the application microsoft authenticator
            microsoftAuthenticatorAppDev = pythClasses.ns.Application()
            microsoftAuthenticatorAppDev.metaconcept = "Application"
            microsoftAuthenticatorAppDev.name = "Microsoft Authenticator App"
            

            # Add to model
            honorModel.add_asset(plexiDevNetwork)
            honorModel.add_asset(plexiSalesNetwork)
            
            honorModel.add_asset(plexiSalesConn)
            honorModel.add_asset(plexigridSalesMail)
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
            honorModel.add_asset(CloudFirewall)
            honorModel.add_asset(vulnerabilityFirewallInternetSales)
            honorModel.add_asset(vulnerabilityFirewallInternetDev)
            honorModel.add_asset(vulnerabilityFirewallCloud)

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
            honorModel.add_asset(unencryptedData)

            honorModel.add_asset(plexidevCredentials)
            honorModel.add_asset(plexiDevIdentityOffice)
            honorModel.add_asset(plexiPMIdentityOffice)
            honorModel.add_asset(plexiPMCredentials)

            # SFTP assets
            honorModel.add_asset(SFTPCreds)
            honorModel.add_asset(SFTPEncryptedCreds)
            honorModel.add_asset(plexigridDataSFTP)
            honorModel.add_asset(plexigridPMSFTPIdentity)
            honorModel.add_asset(SFTPPMCreds)
            honorModel.add_asset(SFTPMFAPMCreds)

            honorModel.add_asset(microsoftAuthAppMemorySales)
            honorModel.add_asset(microsoftAuthenticatorAppSales)
            honorModel.add_asset(microsoftAuthAppMemoryDev)
            honorModel.add_asset(microsoftAuthenticatorAppDev)
        
################################################## Test 5 ######################################################################## 
        if test_case5:
            pass
################################################## Test 6 ########################################################################       
        if test_case6:
            pass


    if add_association:
################################################## Test 1 ########################################################################       

        if test_case1:
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
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            
             # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexigridDevOfficeConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexigridSalesOfficeConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewall to cloud network
            assocInternetCloudFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetCloudFirewall.connectionRules = [CloudInternetConn]
            assocInternetCloudFirewall.routingFirewalls = [CloudFirewall]
            # Vulnerability firewall
            assocInternetCloudFirewallvuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetCloudFirewallvuln.application = [CloudFirewall]
            assocInternetCloudFirewallvuln.vulnerabilities = [vulnerabilityFirewallCloud]
        
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
            if replica:
                # Add replicated information to unencrypted metering data
                assocreplicatedData = pythClasses.ns.Replica()
                assocreplicatedData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedData.dataReplicas = [plexigridDataDSO]
                honorModel.add_association(assocreplicatedData)
                # Add replicated information to encrypted data
                assocDatabaseData = pythClasses.ns.Replica()
                assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocDatabaseData.dataReplicas = [plexigridDataSSH]
                honorModel.add_association(assocDatabaseData)
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Transit in cloud network
            assocSSHDataCloudTransit = pythClasses.ns.DataInTransit()
            assocSSHDataCloudTransit.transitNetwork = [cloudNetwork]
            assocSSHDataCloudTransit.transitData = [plexigridDataSSH]
            # Transit in dev network
            assocSSHDataDevTransit = pythClasses.ns.DataInTransit()
            assocSSHDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocSSHDataDevTransit.transitData = [plexigridDataSSH]
            
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
            # Connect Dev user to Microsoft
            assocDevtoMicrosoft = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDevtoMicrosoft.lowPrivAppIAMs = [plexigridDevMicrosoftIdentity]
            assocDevtoMicrosoft.lowPrivApps = [plexigridSalesMail]
            # Connect Pm to Microsoft
            assocSalestoMicrosoft = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoMicrosoft.lowPrivAppIAMs = [plexigridPMIdentity]
            assocSalestoMicrosoft.lowPrivApps = [plexigridSalesMail]
            # Connect credentials to dev user
            assocCredDevIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDevIdentity.identities = [plexigridDevMicrosoftIdentity]
            assocCredDevIdentity.credentials = [MicrosoftDevCreds]
            # Connect MFA
            assocCredMFADevIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADevIdentity.requiredFactors = [MicrosoftMFADevCreds]
            assocCredMFADevIdentity.credentials = [MicrosoftDevCreds]
            # Connect credentials to sales user
            assocCredSalesIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesIdentity.identities = [plexigridPMIdentity]
            assocCredSalesIdentity.credentials = [MicrosoftSalesCreds]
            # Connect MFA
            assocCredMFASalesIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesIdentity.requiredFactors = [MicrosoftMFASalesCreds]
            assocCredMFASalesIdentity.credentials = [MicrosoftSalesCreds]
            # Connect dev user to new identity
            assocMicrosoftIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocMicrosoftIdentityDevUser.users = [plexigridRegularUser]
            assocMicrosoftIdentityDevUser.userIds = [plexigridDevMicrosoftIdentity]

            # Connect auth microsoft memory with MFA (Sales)
            assocMFAInfoSales = pythClasses.ns.InfoContainment()
            assocMFAInfoSales.containerData = [microsoftAuthAppMemorySales]
            assocMFAInfoSales.information = [MicrosoftMFASalesCreds]
            # Connect microsoft app to its memory(Sales)
            assocAuthMemoryAuthenticatorAppSales = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppSales.containedData = [microsoftAuthAppMemorySales]
            assocAuthMemoryAuthenticatorAppSales.containingApp = [microsoftAuthenticatorAppSales]
            # Connect auth microsoft memory with MFA (Dev)
            assocMFAInfoDev = pythClasses.ns.InfoContainment()
            assocMFAInfoDev.containerData = [microsoftAuthAppMemoryDev]
            assocMFAInfoDev.information = [MicrosoftMFADevCreds]
            # Connect microsoft app to its memory(Dev)
            assocAuthMemoryAuthenticatorAppDev = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppDev.containedData = [microsoftAuthAppMemoryDev]
            assocAuthMemoryAuthenticatorAppDev.containingApp = [microsoftAuthenticatorAppDev]

           
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataDSO]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDSO]
            # receive data to dev office from sales office
            assocRecPM = pythClasses.ns.ReceiveData()
            assocRecPM.receiverApp = [plexigridSalesOffice]
            assocRecPM.receivedData = [plexigridDataDSO]
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
            # Send data from mail server to dev
            assocSendMailServer = pythClasses.ns.SendData()
            assocSendMailServer.senderApp = [plexigridSalesMail]
            assocSendMailServer.sentData = [plexigridDataDSO]

            # ReadPrivs to data from PM identity
            assocReadPrivPMMailData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMMailData.readingIAMs = [plexigridPMIdentity]
            assocReadPrivPMMailData.readPrivData = [plexigridDataDSO]
            # ReadPrivs to data from Dev identity
            assocReadPrivDevMailData = pythClasses.ns.ReadPrivileges()
            assocReadPrivDevMailData.readingIAMs = [plexigridDevMicrosoftIdentity]
            assocReadPrivDevMailData.readPrivData = [plexigridDataDSO]


            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDev = pythClasses.ns.DataHosting()
                assocLocallyDev.hostedData = [plexigridDataDSO]
                assocLocallyDev.hardware = [plexigridDevHardware]
                # Add locally downloaded data
                assocLocallyPM = pythClasses.ns.DataHosting()
                assocLocallyPM.hostedData = [plexigridDataDSO]
                assocLocallyPM.hardware = [plexigridSalesHardware]
            else:
                # Add locally downloaded data on the dev office
                assocLocallyDev = pythClasses.ns.AppContainment()
                assocLocallyDev.containedData = [plexigridDataDSO]
                assocLocallyDev.containingApp = [plexigridDevOffice]
                # Add locally downloaded data on the PM office
                assocLocallyPM = pythClasses.ns.AppContainment()
                assocLocallyPM.containedData = [plexigridDataDSO]
                assocLocallyPM.containingApp = [plexigridSalesOffice]

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
            honorModel.add_association(assocRecPM)
            
            honorModel.add_association(assocSSHDataCloudTransit)
            honorModel.add_association(assocSSHDataDevTransit)

            honorModel.add_association(assocSendMailServer)
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
            honorModel.add_association(assocInternetCloudFirewall)
            honorModel.add_association(assocInternetCloudFirewallvuln)

            
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            
            honorModel.add_association(assocCloudInternet)
            honorModel.add_association(assocDataCloud)
            

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)


            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocCredDevIdentity)
            honorModel.add_association(assocCredSalesIdentity)
            honorModel.add_association(assocCredMFADevIdentity)
            honorModel.add_association(assocCredMFASalesIdentity)
            honorModel.add_association(assocMicrosoftIdentityDevUser)
            honorModel.add_association(assocDevtoMicrosoft)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)
            

            honorModel.add_association(assocLocallyDev)
            honorModel.add_association(assocLocallyPM)
            honorModel.add_association(assocCredPMOfficeIdentity)
            honorModel.add_association(assocPMOfficeIdentity)
            honorModel.add_association(assocCredDevOfficeIdentity)
            honorModel.add_association(assocDevOfficeIdentity)
            honorModel.add_association(assocIdentityOfficeDevUser)
            honorModel.add_association(assocIdentityOfficePMUser)

            honorModel.add_association(assocMFAInfoSales)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppSales)
            honorModel.add_association(assocMFAInfoDev)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppDev)
            
            honorModel.add_association(assocReadPrivPMMailData)
            honorModel.add_association(assocReadPrivPMMailData)

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
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
            
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexigridDevOfficeConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexigridSalesOfficeConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewall to cloud network
            assocInternetCloudFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetCloudFirewall.connectionRules = [CloudInternetConn]
            assocInternetCloudFirewall.routingFirewalls = [CloudFirewall]
            # Vulnerability firewall
            assocInternetCloudFirewallvuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetCloudFirewallvuln.application = [CloudFirewall]
            assocInternetCloudFirewallvuln.vulnerabilities = [vulnerabilityFirewallCloud]
            
            
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
            if replica:
                # Add replicated information to unencrypted metering data
                assocreplicatedData = pythClasses.ns.Replica()
                assocreplicatedData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedData.dataReplicas = [plexigridDataDSO]
                honorModel.add_association(assocreplicatedData)
                # Add replicated information to encrypted data
                assocDatabaseData = pythClasses.ns.Replica()
                assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocDatabaseData.dataReplicas = [plexigridDataSSH]
                honorModel.add_association(assocDatabaseData)
                # Add replicated information to unencrypted metering data
                assocreplicatedDataPMOneDrive = pythClasses.ns.Replica()
                assocreplicatedDataPMOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedDataPMOneDrive.dataReplicas = [plexigridDataPMOneDrive]
                honorModel.add_association(assocreplicatedDataPMOneDrive)
                # Add replicated information to unencrypted metering data
                assocreplicatedDataDevOneDrive = pythClasses.ns.Replica()
                assocreplicatedDataDevOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedDataDevOneDrive.dataReplicas = [plexigridDataDevOneDrive]
                honorModel.add_association(assocreplicatedDataDevOneDrive)

            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Transit in cloud network
            assocSSHDataCloudTransit = pythClasses.ns.DataInTransit()
            assocSSHDataCloudTransit.transitNetwork = [cloudNetwork]
            assocSSHDataCloudTransit.transitData = [plexigridDataSSH]
            # Transit in dev network
            assocSSHDataDevTransit = pythClasses.ns.DataInTransit()
            assocSSHDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocSSHDataDevTransit.transitData = [plexigridDataSSH]

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

            # Connect auth microsoft memory with MFA (Sales)
            assocMFAInfoSales = pythClasses.ns.InfoContainment()
            assocMFAInfoSales.containerData = [microsoftAuthAppMemorySales]
            assocMFAInfoSales.information = [OneDriveMFASalesCreds]
            # Connect microsoft app to its memory(Sales)
            assocAuthMemoryAuthenticatorAppSales = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppSales.containedData = [microsoftAuthAppMemorySales]
            assocAuthMemoryAuthenticatorAppSales.containingApp = [microsoftAuthenticatorAppSales]
            # Connect auth microsoft memory with MFA (Dev)
            assocMFAInfoDev = pythClasses.ns.InfoContainment()
            assocMFAInfoDev.containerData = [microsoftAuthAppMemoryDev]
            assocMFAInfoDev.information = [OneDriveMFADevCreds]
            # Connect microsoft app to its memory(Dev)
            assocAuthMemoryAuthenticatorAppDev = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppDev.containedData = [microsoftAuthAppMemoryDev]
            assocAuthMemoryAuthenticatorAppDev.containingApp = [microsoftAuthenticatorAppDev]

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

           
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataPMOneDrive]
            # Receive data from Mail server to Pm office
            assocRecPMOffice = pythClasses.ns.ReceiveData()
            assocRecPMOffice.receiverApp = [plexigridSalesOffice]
            assocRecPMOffice.receivedData = [plexigridDataDSO]
            # receive data to oneDrive from sales office
            assocRecOnedrive = pythClasses.ns.ReceiveData()
            assocRecOnedrive.receiverApp = [cloudOneDrive]
            assocRecOnedrive.receivedData = [plexigridDataPMOneDrive]
            # receive data to dev office from sales office
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDevOneDrive]
            #  Send data from onedrive to dev
            assocSendOneDriveDev = pythClasses.ns.SendData()
            assocSendOneDriveDev.senderApp = [cloudOneDrive]
            assocSendOneDriveDev.sentData = [plexigridDataDevOneDrive]
            # Receive data from DSO to Sales
            assocDSOSales = pythClasses.ns.ReceiveData()
            assocDSOSales.receiverApp = [plexigridSalesMail]
            assocDSOSales.receivedData = [plexigridDataDSO]
            # Send data from mail server to pm office
            assocMailServerSales = pythClasses.ns.SendData()
            assocMailServerSales.senderApp = [plexigridSalesMail]
            assocMailServerSales.sentData = [plexigridDataDSO]
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
            # The data is accessable from the whole PM's network
            assocDataPMTransit = pythClasses.ns.DataInTransit()
            assocDataPMTransit.transitNetwork = [plexiSalesNetwork]
            assocDataPMTransit.transitData = [plexigridDataPMOneDrive]

            # ReadPrivs to data from PM identity
            assocReadPrivPMMailData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMMailData.readingIAMs = [plexigridPMIdentity]
            assocReadPrivPMMailData.readPrivData = [plexigridDataDSO]
            # ReadPrivs to data from PM identity
            assocReadPrivPMOneDriveData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMOneDriveData.readingIAMs = [plexigridPMIdentity]
            assocReadPrivPMOneDriveData.readPrivData = [plexigridDataPMOneDrive]
            # ReadPrivs to data from Dev identity
            assocReadPrivDevOneDriveData = pythClasses.ns.ReadPrivileges()
            assocReadPrivDevOneDriveData.readingIAMs = [plexigridDevOneDriveIdentity]
            assocReadPrivDevOneDriveData.readPrivData = [plexigridDataDevOneDrive]

            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDev = pythClasses.ns.DataHosting()
                assocLocallyDev.hostedData = [plexigridDataDSO]
                assocLocallyDev.hardware = [plexigridDevHardware]
                # Add locally downloaded data
                assocLocallyPM = pythClasses.ns.DataHosting()
                assocLocallyPM.hostedData = [plexigridDataDSO]
                assocLocallyPM.hardware = [plexigridSalesHardware]
            else:
                # Add locally downloaded data on the dev office
                assocLocallyDev = pythClasses.ns.AppContainment()
                assocLocallyDev.containedData = [plexigridDataDSO]
                assocLocallyDev.containingApp = [plexigridDevOffice]
                # Add locally downloaded data on the PM office
                assocLocallyPM = pythClasses.ns.AppContainment()
                assocLocallyPM.containedData = [plexigridDataDSO]
                assocLocallyPM.containingApp = [plexigridSalesOffice]

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

            honorModel.add_association(assocSSHDataCloudTransit)
            honorModel.add_association(assocSSHDataDevTransit)

            honorModel.add_association(assocMailServerSales)
            honorModel.add_association(assocRecPMOffice)
            honorModel.add_association(assocSendOneDriveDev)
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
            honorModel.add_association(assocInternetCloudFirewall)
            honorModel.add_association(assocInternetCloudFirewallvuln)
            
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
            honorModel.add_association(assocCredDev)
            honorModel.add_association(assocEncOneDriveDev)
            honorModel.add_association(assocCredOneDriveDev)
            honorModel.add_association(assocCredOneDrive2)
            honorModel.add_association(assocDataCloudDev)
            honorModel.add_association(assocDataPMTransit)

            honorModel.add_association(assocLocallyDev)
            honorModel.add_association(assocLocallyPM)
            honorModel.add_association(assocCredPMOfficeIdentity)
            honorModel.add_association(assocPMOfficeIdentity)
            honorModel.add_association(assocCredDevOfficeIdentity)
            honorModel.add_association(assocDevOfficeIdentity)
            honorModel.add_association(assocIdentityOfficeDevUser)
            honorModel.add_association(assocIdentityOfficePMUser)

            honorModel.add_association(assocMFAInfoSales)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppSales)
            honorModel.add_association(assocMFAInfoDev)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppDev)

            honorModel.add_association(assocReadPrivPMMailData)
            honorModel.add_association(assocReadPrivDevOneDriveData)
            honorModel.add_association(assocReadPrivPMOneDriveData)
            

################################################## Test 3 ########################################################################
        if test_case3:
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
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
             # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexigridDevOfficeConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexigridSalesOfficeConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewall to cloud network
            assocInternetCloudFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetCloudFirewall.connectionRules = [CloudInternetConn]
            assocInternetCloudFirewall.routingFirewalls = [CloudFirewall]
            # Vulnerability firewall
            assocInternetCloudFirewallvuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetCloudFirewallvuln.application = [CloudFirewall]
            assocInternetCloudFirewallvuln.vulnerabilities = [vulnerabilityFirewallCloud]
            
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
            if replica:
                # Add replicated information to unencrypted metering data
                assocreplicatedData = pythClasses.ns.Replica()
                assocreplicatedData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedData.dataReplicas = [plexigridDataDSO]
                honorModel.add_association(assocreplicatedData)
                # Add replicated information to encrypted data
                assocDatabaseData = pythClasses.ns.Replica()
                assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocDatabaseData.dataReplicas = [plexigridDataSSH]
                honorModel.add_association(assocDatabaseData)

            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Transit in cloud network
            assocSSHDataCloudTransit = pythClasses.ns.DataInTransit()
            assocSSHDataCloudTransit.transitNetwork = [cloudNetwork]
            assocSSHDataCloudTransit.transitData = [plexigridDataSSH]
            # Transit in dev network
            assocSSHDataDevTransit = pythClasses.ns.DataInTransit()
            assocSSHDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocSSHDataDevTransit.transitData = [plexigridDataSSH]

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
            # Connect Dev user to Microsoft
            assocDevtoMicrosoft = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocDevtoMicrosoft.lowPrivAppIAMs = [plexigridDevMicrosoftIdentity]
            assocDevtoMicrosoft.lowPrivApps = [plexigridSalesMail]
            # Connect Pm to Microsoft
            assocSalestoMicrosoft = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocSalestoMicrosoft.lowPrivAppIAMs = [plexigridPMIdentity]
            assocSalestoMicrosoft.lowPrivApps = [plexigridSalesMail]
            # Connect credentials to dev user
            assocCredDevIdentity = pythClasses.ns.IdentityCredentials()
            assocCredDevIdentity.identities = [plexigridDevMicrosoftIdentity]
            assocCredDevIdentity.credentials = [MicrosoftDevCreds]
            # Connect MFA
            assocCredMFADevIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFADevIdentity.requiredFactors = [MicrosoftMFADevCreds]
            assocCredMFADevIdentity.credentials = [MicrosoftDevCreds]
            # Connect credentials to sales user
            assocCredSalesIdentity = pythClasses.ns.IdentityCredentials()
            assocCredSalesIdentity.identities = [plexigridPMIdentity]
            assocCredSalesIdentity.credentials = [MicrosoftSalesCreds]
            # Connect MFA
            assocCredMFASalesIdentity = pythClasses.ns.ConditionalAuthentication()
            assocCredMFASalesIdentity.requiredFactors = [MicrosoftMFASalesCreds]
            assocCredMFASalesIdentity.credentials = [MicrosoftSalesCreds]
            # Connect dev user to new identity
            assocMicrosoftIdentityDevUser = pythClasses.ns.UserAssignedIdentities()
            assocMicrosoftIdentityDevUser.users = [plexigridRegularUser]
            assocMicrosoftIdentityDevUser.userIds = [plexigridDevMicrosoftIdentity]

            # Connect auth microsoft memory with MFA (Sales)
            assocMFAInfoSales = pythClasses.ns.InfoContainment()
            assocMFAInfoSales.containerData = [microsoftAuthAppMemorySales]
            assocMFAInfoSales.information = [MicrosoftMFASalesCreds]
            # Connect microsoft app to its memory(Sales)
            assocAuthMemoryAuthenticatorAppSales = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppSales.containedData = [microsoftAuthAppMemorySales]
            assocAuthMemoryAuthenticatorAppSales.containingApp = [microsoftAuthenticatorAppSales]
            # Connect auth microsoft memory with MFA (Dev)
            assocMFAInfoDev = pythClasses.ns.InfoContainment()
            assocMFAInfoDev.containerData = [microsoftAuthAppMemoryDev]
            assocMFAInfoDev.information = [MicrosoftMFADevCreds]
            # Connect microsoft app to its memory(Dev)
            assocAuthMemoryAuthenticatorAppDev = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppDev.containedData = [microsoftAuthAppMemoryDev]
            assocAuthMemoryAuthenticatorAppDev.containingApp = [microsoftAuthenticatorAppDev]

            # SFTP associations
            # Connect PM SFTP user to new identity
            assocPMSFTPUser = pythClasses.ns.UserAssignedIdentities()
            assocPMSFTPUser.users = [plexigridPMUser]
            assocPMSFTPUser.userIds = [plexigridPMSFTPIdentity]
            # Connect credentials to sales user
            assocSFTPCredPMIdentity = pythClasses.ns.IdentityCredentials()
            assocSFTPCredPMIdentity.identities = [plexigridPMSFTPIdentity]
            assocSFTPCredPMIdentity.credentials = [SFTPPMCreds]
            # Connect MFA
            assocSFTPCredMFAPMIdentity = pythClasses.ns.ConditionalAuthentication()
            assocSFTPCredMFAPMIdentity.requiredFactors = [SFTPMFAPMCreds]
            assocSFTPCredMFAPMIdentity.credentials = [SFTPPMCreds]
            # Connect the credentials data from decryption of the data
            assocSFTPCredPMoffice = pythClasses.ns.AppContainment()
            assocSFTPCredPMoffice.containedData = [SFTPEncryptedCreds]
            assocSFTPCredPMoffice.containingApp = [plexigridSalesOffice]
            # Receive data from SFTP to office station
            assocRecSFTPPM = pythClasses.ns.ReceiveData()
            assocRecSFTPPM.receiverApp = [plexigridSalesOffice]
            assocRecSFTPPM.receivedData = [plexigridDataSFTP]
            # The data is accessable from the whole sales network
            assocSFTPTransitPM = pythClasses.ns.DataInTransit()
            assocSFTPTransitPM.transitNetwork = [plexiSalesNetwork]
            assocSFTPTransitPM.transitData = [plexigridDataSFTP]

            


           
            # Send data from Sales office to outlook
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataDSO]
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
            # Send data from mail server to dev
            assocSendMailServer = pythClasses.ns.SendData()
            assocSendMailServer.senderApp = [plexigridSalesMail]
            assocSendMailServer.sentData = [plexigridDataDSO]

            # ReadPrivs to data from PM identity
            assocReadPrivPMMailData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMMailData.readingIAMs = [plexigridPMIdentity]
            assocReadPrivPMMailData.readPrivData = [plexigridDataDSO]
            # ReadPrivs to data from PM identity
            assocReadPrivPMSFTPData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMSFTPData.readingIAMs = [plexigridPMSFTPIdentity]
            assocReadPrivPMSFTPData.readPrivData = [plexigridDataSFTP]
            # ReadPrivs to data from Dev identity
            assocReadPrivDevMailData = pythClasses.ns.ReadPrivileges()
            assocReadPrivDevMailData.readingIAMs = [plexigridDevMicrosoftIdentity]
            assocReadPrivDevMailData.readPrivData = [plexigridDataDSO]


            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDev = pythClasses.ns.DataHosting()
                assocLocallyDev.hostedData = [plexigridDataDSO]
                assocLocallyDev.hardware = [plexigridDevHardware]
                # Add locally downloaded data
                assocLocallyPM = pythClasses.ns.DataHosting()
                assocLocallyPM.hostedData = [plexigridDataDSO]
                assocLocallyPM.hardware = [plexigridSalesHardware]
            else:
                # Add locally downloaded data on the dev office
                assocLocallyDev = pythClasses.ns.AppContainment()
                assocLocallyDev.containedData = [plexigridDataDSO]
                assocLocallyDev.containingApp = [plexigridDevOffice]
                # Add locally downloaded data on the PM office
                assocLocallyPM = pythClasses.ns.AppContainment()
                assocLocallyPM.containedData = [plexigridDataDSO]
                assocLocallyPM.containingApp = [plexigridSalesOffice]

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

            honorModel.add_association(assocSSHDataCloudTransit)
            honorModel.add_association(assocSSHDataDevTransit)

            honorModel.add_association(assocSFTPTransitPM)
            honorModel.add_association(assocSendMailServer)
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
            honorModel.add_association(assocInternetCloudFirewall)
            honorModel.add_association(assocInternetCloudFirewallvuln)
            
            honorModel.add_association(assocDevHardware)
            honorModel.add_association(assocSalesHardware)
            honorModel.add_association(assocVulnHardwareDev)
            honorModel.add_association(assocVulnHardwareSales)
            
            honorModel.add_association(assocCloudInternet)
            honorModel.add_association(assocDataCloud)

            honorModel.add_association(assocSalesSoftwareVuln)
            honorModel.add_association(assocDevSoftwareVuln)


            honorModel.add_association(assocIDPSDevOffice)
            honorModel.add_association(assocIDPSSalesOffice)
            honorModel.add_association(assocCreddevoffice)
            honorModel.add_association(assocEncSSHData)
            honorModel.add_association(assocCredSSHData)
            honorModel.add_association(assocCredDatabase)
            honorModel.add_association(assocDatabasefromDev)
            honorModel.add_association(assocDevtoDatabase)
            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocCredDevIdentity)
            honorModel.add_association(assocCredSalesIdentity)
            honorModel.add_association(assocCredMFADevIdentity)
            honorModel.add_association(assocCredMFASalesIdentity)
            honorModel.add_association(assocMicrosoftIdentityDevUser)
            honorModel.add_association(assocDevtoMicrosoft)

            honorModel.add_association(assocConndatabase)
            honorModel.add_association(assocConndatabaseCloud)
            honorModel.add_association(assocDatabaseHardware)
            honorModel.add_association(assocVulnHardwareDatabase)
            honorModel.add_association(assocConnApplication)
            honorModel.add_association(assocConnApplicationCloud)
            honorModel.add_association(assocApplicationHardware)
            

            honorModel.add_association(assocLocallyDev)
            honorModel.add_association(assocLocallyPM)
            honorModel.add_association(assocCredPMOfficeIdentity)
            honorModel.add_association(assocPMOfficeIdentity)
            honorModel.add_association(assocCredDevOfficeIdentity)
            honorModel.add_association(assocDevOfficeIdentity)
            honorModel.add_association(assocIdentityOfficeDevUser)
            honorModel.add_association(assocIdentityOfficePMUser)

            # SFTP associations
            honorModel.add_association(assocPMSFTPUser)
            honorModel.add_association(assocSFTPCredPMIdentity)
            honorModel.add_association(assocSFTPCredMFAPMIdentity)
            honorModel.add_association(assocSFTPCredPMoffice)
            honorModel.add_association(assocRecSFTPPM)

            honorModel.add_association(assocMFAInfoSales)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppSales)
            honorModel.add_association(assocMFAInfoDev)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppDev)

            honorModel.add_association(assocReadPrivPMMailData)
            honorModel.add_association(assocReadPrivPMSFTPData)
            honorModel.add_association(assocReadPrivDevMailData)




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
            # Add user to identity to enable social engineering attacks
            assocIdentityUser = pythClasses.ns.UserAssignedIdentities()
            assocIdentityUser.users = [plexigridPMUser]
            assocIdentityUser.userIds = [plexigridPMIdentity]
             
            # Add firewall internet dev
            assocInternetDevFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetDevFirewall.connectionRules = [plexigridDevOfficeConn]
            assocInternetDevFirewall.routingFirewalls = [plexiInternetDevFirewall]
            # Vulnerability firewall
            assocInternetDevFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetDevFirewallVuln.application = [plexiInternetDevFirewall]
            assocInternetDevFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetDev]
            # Add firewalls internet sales
            assocInternetSalesFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetSalesFirewall.connectionRules = [plexigridSalesOfficeConn]
            assocInternetSalesFirewall.routingFirewalls = [plexiInternetSalesFirewall]
            # Vulnerability firewall
            assocInternetSalesFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetSalesFirewallVuln.application = [plexiInternetSalesFirewall]
            assocInternetSalesFirewallVuln.vulnerabilities = [vulnerabilityFirewallInternetSales]
            # Add firewall to cloud network
            assocInternetCloudFirewall = pythClasses.ns.FirewallConnectionRule()
            assocInternetCloudFirewall.connectionRules = [CloudInternetConn]
            assocInternetCloudFirewall.routingFirewalls = [CloudFirewall]
            # Vulnerability firewall
            assocInternetCloudFirewallvuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocInternetCloudFirewallvuln.application = [CloudFirewall]
            assocInternetCloudFirewallvuln.vulnerabilities = [vulnerabilityFirewallCloud]
            
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

            if replica:
                # Add replicated information to encrypted data
                assocDatabaseData = pythClasses.ns.Replica()
                assocDatabaseData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocDatabaseData.dataReplicas = [plexigridDataSSH]
                honorModel.add_association(assocDatabaseData)
                # Add replicated information to unencrypted metering data
                assocreplicatedDataPMOneDrive = pythClasses.ns.Replica()
                assocreplicatedDataPMOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedDataPMOneDrive.dataReplicas = [plexigridDataPMOneDrive]
                honorModel.add_association(assocreplicatedDataPMOneDrive)
                 # Add replicated information to unencrypted metering data
                assocreplicatedDataDevOneDrive = pythClasses.ns.Replica()
                assocreplicatedDataDevOneDrive.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedDataDevOneDrive.dataReplicas = [plexigridDataDevOneDrive]
                honorModel.add_association(assocreplicatedDataDevOneDrive)

                
            
            # Receive data to database
            assocDatabasefromDev = pythClasses.ns.ReceiveData()
            assocDatabasefromDev.receiverApp = [plexigriddatabase]
            assocDatabasefromDev.receivedData = [plexigridDataSSH]
            # Send data from dev to database
            assocDevtoDatabase = pythClasses.ns.SendData()
            assocDevtoDatabase.senderApp = [plexigridDevOffice]
            assocDevtoDatabase.sentData = [plexigridDataSSH]
            # Transit in cloud network
            assocSSHDataCloudTransit = pythClasses.ns.DataInTransit()
            assocSSHDataCloudTransit.transitNetwork = [cloudNetwork]
            assocSSHDataCloudTransit.transitData = [plexigridDataSSH]
            # Transit in dev network
            assocSSHDataDevTransit = pythClasses.ns.DataInTransit()
            assocSSHDataDevTransit.transitNetwork = [plexiDevNetwork]
            assocSSHDataDevTransit.transitData = [plexigridDataSSH]

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

            # Connect auth microsoft memory with MFA (Sales)
            assocMFAInfoSales = pythClasses.ns.InfoContainment()
            assocMFAInfoSales.containerData = [microsoftAuthAppMemorySales]
            assocMFAInfoSales.information = [OneDriveMFASalesCreds]
            # Connect microsoft app to its memory(Sales)
            assocAuthMemoryAuthenticatorAppSales = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppSales.containedData = [microsoftAuthAppMemorySales]
            assocAuthMemoryAuthenticatorAppSales.containingApp = [microsoftAuthenticatorAppSales]
            # Connect auth microsoft memory with MFA (Dev)
            assocMFAInfoDev = pythClasses.ns.InfoContainment()
            assocMFAInfoDev.containerData = [microsoftAuthAppMemoryDev]
            assocMFAInfoDev.information = [OneDriveMFADevCreds]
            # Connect microsoft app to its memory(Dev)
            assocAuthMemoryAuthenticatorAppDev = pythClasses.ns.AppContainment()
            assocAuthMemoryAuthenticatorAppDev.containedData = [microsoftAuthAppMemoryDev]
            assocAuthMemoryAuthenticatorAppDev.containingApp = [microsoftAuthenticatorAppDev]

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
           

           
            # Send data from Sales office to onedrive
            assocSendSales = pythClasses.ns.SendData()
            assocSendSales.senderApp = [plexigridSalesOffice]
            assocSendSales.sentData = [plexigridDataPMOneDrive]
            # receive data from SFTP server to sales office
            assocRecSFTPPMOffice = pythClasses.ns.ReceiveData()
            assocRecSFTPPMOffice.receiverApp = [plexigridSalesOffice]
            assocRecSFTPPMOffice.receivedData = [plexigridDataSFTP]
            # receive data to oneDrive from sales office
            assocRecOnedrive = pythClasses.ns.ReceiveData()
            assocRecOnedrive.receiverApp = [cloudOneDrive]
            assocRecOnedrive.receivedData = [plexigridDataPMOneDrive]
            # Send data from onedrive to Dev office
            assocSendOneDrive = pythClasses.ns.SendData()
            assocSendOneDrive.senderApp = [cloudOneDrive]
            assocSendOneDrive.sentData = [plexigridDataDevOneDrive]
            # receive data to dev office from OneDrive
            assocRecDevs = pythClasses.ns.ReceiveData()
            assocRecDevs.receiverApp = [plexigridDevOffice]
            assocRecDevs.receivedData = [plexigridDataDevOneDrive]
            
            # Transit data to networks
            # The data is accessable from the whole sales network
            assocSFTPDataSales = pythClasses.ns.DataInTransit()
            assocSFTPDataSales.transitNetwork = [plexiSalesNetwork]
            assocSFTPDataSales.transitData = [plexigridDataSFTP]
            # The data is accessable from the whole sales network
            assocOneDriveDataSales = pythClasses.ns.DataInTransit()
            assocOneDriveDataSales.transitNetwork = [plexiSalesNetwork]
            assocOneDriveDataSales.transitData = [plexigridDataPMOneDrive]
            # The data is accessable from the whole Dev network
            assocDataDev = pythClasses.ns.DataInTransit()
            assocDataDev.transitNetwork = [plexiDevNetwork]
            assocDataDev.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the whole cloud network
            assocDataCloud = pythClasses.ns.DataInTransit()
            assocDataCloud.transitNetwork = [cloudNetwork]
            assocDataCloud.transitData = [plexigridDataPMOneDrive]
            # The data is accessable from the whole Dev network
            assocDataCloudDev = pythClasses.ns.DataInTransit()
            assocDataCloudDev.transitNetwork = [cloudNetwork]
            assocDataCloudDev.transitData = [plexigridDataDevOneDrive]

            # ReadPrivs to data from PM identity
            assocReadPrivPMOneDriveData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMOneDriveData.readingIAMs = [plexigridPMIdentity]
            assocReadPrivPMOneDriveData.readPrivData = [plexigridDataPMOneDrive]
            # ReadPrivs to data from PM identity
            assocReadPrivPMSFTPData = pythClasses.ns.ReadPrivileges()
            assocReadPrivPMSFTPData.readingIAMs = [plexigridPMSFTPIdentity]
            assocReadPrivPMSFTPData.readPrivData = [plexigridDataSFTP]
            # ReadPrivs to data from Dev identity
            assocReadPrivDevOneDriveData = pythClasses.ns.ReadPrivileges()
            assocReadPrivDevOneDriveData.readingIAMs = [plexigridDevOneDriveIdentity]
            assocReadPrivDevOneDriveData.readPrivData = [plexigridDataDevOneDrive]

            
            
            if lastTestAttack == True:
                if replica:
                    # Connect the unencrypted data to use for local storage
                    assocLocallyUnencryptedData = pythClasses.ns.Replica()
                    assocLocallyUnencryptedData.replicatedInformation = [replicatedMeterDatatoDatabase]
                    assocLocallyUnencryptedData.dataReplicas = [unencryptedData]
                    honorModel.add_association(assocLocallyUnencryptedData)
                # Add locally downloaded data
                assocLocallyDev = pythClasses.ns.DataHosting()
                assocLocallyDev.hostedData = [unencryptedData]
                assocLocallyDev.hardware = [plexigridDevHardware]
                # Add locally downloaded data
                assocLocallyPM = pythClasses.ns.DataHosting()
                assocLocallyPM.hostedData = [unencryptedData]
                assocLocallyPM.hardware = [plexigridSalesHardware]
            else:
                if replica:
                    # Connect the unencrypted data to use for local storage
                    assocLocallyUnencryptedData = pythClasses.ns.Replica()
                    assocLocallyUnencryptedData.replicatedInformation = [replicatedMeterDatatoDatabase]
                    assocLocallyUnencryptedData.dataReplicas = [unencryptedData]
                    honorModel.add_association(assocLocallyUnencryptedData)
                # Add locally downloaded data on the dev office
                assocLocallyDev = pythClasses.ns.AppContainment()
                assocLocallyDev.containedData = [unencryptedData]
                assocLocallyDev.containingApp = [plexigridDevOffice]
                # Add locally downloaded data on the PM office
                assocLocallyPM = pythClasses.ns.AppContainment()
                assocLocallyPM.containedData = [unencryptedData]
                assocLocallyPM.containingApp = [plexigridSalesOffice]

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

            # SFTP associations
            # Connect PM SFTP user to new identity
            assocPMSFTPUser = pythClasses.ns.UserAssignedIdentities()
            assocPMSFTPUser.users = [plexigridPMUser]
            assocPMSFTPUser.userIds = [plexigridPMSFTPIdentity]
            # Connect credentials to sales user
            assocSFTPCredPMIdentity = pythClasses.ns.IdentityCredentials()
            assocSFTPCredPMIdentity.identities = [plexigridPMSFTPIdentity]
            assocSFTPCredPMIdentity.credentials = [SFTPPMCreds]
            # Connect MFA
            assocSFTPCredMFAPMIdentity = pythClasses.ns.ConditionalAuthentication()
            assocSFTPCredMFAPMIdentity.requiredFactors = [SFTPMFAPMCreds]
            assocSFTPCredMFAPMIdentity.credentials = [SFTPPMCreds]
            # Connect the credentials data from decryption of the data
            assocSFTPCredPMoffice = pythClasses.ns.AppContainment()
            assocSFTPCredPMoffice.containedData = [SFTPEncryptedCreds]
            assocSFTPCredPMoffice.containingApp = [plexigridSalesOffice]
            # Receive data from SFTP to office station
            assocRecSFTPPM = pythClasses.ns.ReceiveData()
            assocRecSFTPPM.receiverApp = [plexigridSalesOffice]
            assocRecSFTPPM.receivedData = [plexigridDataSFTP]

            # Add every association to the model
            
            honorModel.add_association(assocConnSalesnetworkInternet)
            
            honorModel.add_association(assocVulnSales)
            honorModel.add_association(assocSendSales)
            honorModel.add_association(assocRecDevs)
            honorModel.add_association(assocSFTPDataSales)
            honorModel.add_association(assocRecSFTPPMOffice)
            honorModel.add_association(assocDataDev)
            honorModel.add_association(assocSendOneDrive)
            honorModel.add_association(assocRecOnedrive)
            honorModel.add_association(assocOneDriveDataSales)
            honorModel.add_association(assocSSHDataCloudTransit)
            honorModel.add_association(assocSSHDataDevTransit)
            
            honorModel.add_association(assocConnSalesMail)
            honorModel.add_association(assocConnMailSales)
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
            honorModel.add_association(assocInternetCloudFirewall)
            honorModel.add_association(assocInternetCloudFirewallvuln)
            
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
            honorModel.add_association(assocCredDev)
            honorModel.add_association(assocEncOneDriveDev)
            honorModel.add_association(assocCredOneDriveDev)
            honorModel.add_association(assocCredOneDrive2)
            honorModel.add_association(assocDataCloudDev)

            honorModel.add_association(assocLocallyDev)
            honorModel.add_association(assocLocallyPM)
            honorModel.add_association(assocCredPMOfficeIdentity)
            honorModel.add_association(assocPMOfficeIdentity)
            honorModel.add_association(assocCredDevOfficeIdentity)
            honorModel.add_association(assocDevOfficeIdentity)
            honorModel.add_association(assocIdentityOfficeDevUser)
            honorModel.add_association(assocIdentityOfficePMUser)

            # SFTP associations
            honorModel.add_association(assocPMSFTPUser)
            honorModel.add_association(assocSFTPCredPMIdentity)
            honorModel.add_association(assocSFTPCredMFAPMIdentity)
            honorModel.add_association(assocSFTPCredPMoffice)
            honorModel.add_association(assocRecSFTPPM)

            honorModel.add_association(assocMFAInfoSales)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppSales)
            honorModel.add_association(assocMFAInfoDev)
            honorModel.add_association(assocAuthMemoryAuthenticatorAppDev)

            honorModel.add_association(assocReadPrivPMOneDriveData)
            honorModel.add_association(assocReadPrivPMSFTPData)
            honorModel.add_association(assocReadPrivDevOneDriveData)
        
    

################################################## Test 5 ######################################################################## 
        if test_case5:
            pass
################################################## Test 6 ########################################################################       
        if test_case6:
            pass
    
    
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
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"
            DMZInternetConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DMZInternetConn.restricted = bernoulli_sample(0.6) # protocols that can be used for exploit are closed

            # Firewall for the connection between DMZ and internet
            FirewallDMZ = pythClasses.ns.RoutingFirewall()
            FirewallDMZ.metaconcept = "RoutingFirewall"
            FirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDMZ.integrityImpactLimitations = bernoulli_sample(0.25)
            # Connect firewall to conn
            assocFirewallDMZ = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZ.connectionRules = [DMZInternetConn]
            assocFirewallDMZ.routingFirewalls = [FirewallDMZ]
            # connect Vulnerability firewall
            assocDMZFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZFirewallVuln.application = [FirewallDMZ]
            assocDMZFirewallVuln.vulnerabilities = [vulnerabilityFirewallDMZ]

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            DSOOfficeNetwork.networkAccessControl = bernoulli_sample(0.8)
            DSOOfficeNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DSOOfficeNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            DSOOfficeHardwareVuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            DSOOfficeHardwareVuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityDSOOffice.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityDSOOffice.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User"
            DSORegularUser.securityAwareness = bernoulli_sample(0.5)
            DSORegularUser.noPasswordReuse = bernoulli_sample(0.5)
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            DSOOfficeStationConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DSOOfficeStationConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed
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
            # Password to DSO user
            DSOSOfficeCreds = pythClasses.ns.Credentials()
            DSOSOfficeCreds.metaconcept = "Credentials"
            DSOSOfficeCreds.name = "Password/Username" 
            DSOSOfficeCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSOfficeCreds.unique = bernoulli_sample(0.8) # assume that the password is not used for multiple services
            # Connect cred to DSO user
            assocDSOCredIdentity = pythClasses.ns.IdentityCredentials()
            assocDSOCredIdentity.identities = [DSORegularIdentity]
            assocDSOCredIdentity.credentials = [DSOSOfficeCreds]


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
            DSODMZConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DSODMZConn.payloadInspection = bernoulli_sample(0.) # IDPS try to filter malicous payloads
            
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDSODMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDSODMZ.integrityImpactLimitations = bernoulli_sample(0.25)
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
            DMZNetwork.networkAccessControl = bernoulli_sample(0.8)
            DMZNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DMZNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            vulnerabilityDMZMail.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            vulnerabilityDMZMail.networkAccessRequired = 1 # need to have network access
            vulnerabilityDMZMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            DMZMailConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DMZMailConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
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
            # SSH data in transit through the internet
            assocSSHDataInternetTransit= pythClasses.ns.DataInTransit()
            assocSSHDataInternetTransit.transitNetwork = [internet]
            assocSSHDataInternetTransit.transitData = [plexigridDataSSH]
            
            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDSO = pythClasses.ns.DataHosting()
                assocLocallyDSO.hostedData = [plexigridDataDSO]
                assocLocallyDSO.hardware = [DSOOfficeHardware]
            else:
                # Add data locally on application
                assocLocallyDSO = pythClasses.ns.AppContainment()
                assocLocallyDSO.containedData = [plexigridDataDSO]
                assocLocallyDSO.containingApp = [DSOOfficeStation]


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
            honorModel.add_asset(DSOSOfficeCreds)

            honorModel.add_asset(FirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDMZ)
            honorModel.add_association(assocFirewallDMZ)
            honorModel.add_association(assocDMZFirewallVuln)

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
            honorModel.add_association(assocSSHDataInternetTransit)

           
            honorModel.add_association(assocLocallyDSO)

            honorModel.add_association(assocDSOCredIdentity)

            # A compromised or attacker-owned computer
            AttackerComputer = pythClasses.ns.Application()
            AttackerComputer.metaconcept = "Application"
            AttackerComputer.name = "Compromised computer"
            honorModel.add_asset(AttackerComputer)
            # Connected to the internet
            assocAttackerInternet = pythClasses.ns.NetworkExposure()
            assocAttackerInternet.networks = [internet]
            assocAttackerInternet.applications = [AttackerComputer]
            honorModel.add_association(assocAttackerInternet)
            

            
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
            DMZInternetConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DMZInternetConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed

            # Firewall for the connection between DMZ and internet
            FirewallDMZ = pythClasses.ns.RoutingFirewall()
            FirewallDMZ.metaconcept = "RoutingFirewall"
            FirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDMZ.integrityImpactLimitations = bernoulli_sample(0.25)
            # Connect firewall to conn
            assocFirewallDMZ = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZ.connectionRules = [DMZInternetConn]
            assocFirewallDMZ.routingFirewalls = [FirewallDMZ]
            # connect Vulnerability firewall
            assocDMZFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZFirewallVuln.application = [FirewallDMZ]
            assocDMZFirewallVuln.vulnerabilities = [vulnerabilityFirewallDMZ]
            
            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            DSOOfficeNetwork.networkAccessControl = bernoulli_sample(0.8)
            DSOOfficeNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DSOOfficeNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            DSOOfficeHardwareVuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            DSOOfficeHardwareVuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityDSOOffice.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityDSOOffice.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User"
            DSORegularUser.securityAwareness = bernoulli_sample(0.5)
            DSORegularUser.noPasswordReuse = bernoulli_sample(0.5) 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            DSOOfficeStationConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DSOOfficeStationConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed
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
            # Password to DSO user
            DSOSOfficeCreds = pythClasses.ns.Credentials()
            DSOSOfficeCreds.metaconcept = "Credentials"
            DSOSOfficeCreds.name = "Password/Username" 
            DSOSOfficeCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSOfficeCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Connect cred to DSO user
            assocDSOCredIdentity = pythClasses.ns.IdentityCredentials()
            assocDSOCredIdentity.identities = [DSORegularIdentity]
            assocDSOCredIdentity.credentials = [DSOSOfficeCreds]


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
            DSODMZConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DSODMZConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDSODMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDSODMZ.integrityImpactLimitations = bernoulli_sample(0.25)
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
            DMZNetwork.networkAccessControl = bernoulli_sample(0.8)
            DMZNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DMZNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            vulnerabilityDMZMail.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            vulnerabilityDMZMail.networkAccessRequired = 1 # need to have network access
            vulnerabilityDMZMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            DMZMailConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DMZMailConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
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
            # Data is sent from DSO office station
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
            # The data is accessable from the internet
            assocDataInternetPMTransit = pythClasses.ns.DataInTransit()
            assocDataInternetPMTransit.transitNetwork = [internet]
            assocDataInternetPMTransit.transitData = [plexigridDataPMOneDrive]
            # SSH data in transit through the internet
            assocSSHDataInternetTransit= pythClasses.ns.DataInTransit()
            assocSSHDataInternetTransit.transitNetwork = [internet]
            assocSSHDataInternetTransit.transitData = [plexigridDataSSH]
            
            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDSO = pythClasses.ns.DataHosting()
                assocLocallyDSO.hostedData = [plexigridDataDSO]
                assocLocallyDSO.hardware = [DSOOfficeHardware]
            else:
                # Add data locally on application
                assocLocallyDSO = pythClasses.ns.AppContainment()
                assocLocallyDSO.containedData = [plexigridDataDSO]
                assocLocallyDSO.containingApp = [DSOOfficeStation]


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
            honorModel.add_asset(DSOSOfficeCreds)

            honorModel.add_asset(FirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDMZ)
            honorModel.add_association(assocFirewallDMZ)
            honorModel.add_association(assocDMZFirewallVuln)

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
            honorModel.add_association(assocSSHDataInternetTransit)

            honorModel.add_association(assocDSOCredIdentity)

            # A compromised or attacker-owned computer
            AttackerComputer = pythClasses.ns.Application()
            AttackerComputer.metaconcept = "Application"
            AttackerComputer.name = "Compromised computer"
            honorModel.add_asset(AttackerComputer)
            # Connected to the internet
            assocAttackerInternet = pythClasses.ns.NetworkExposure()
            assocAttackerInternet.networks = [internet]
            assocAttackerInternet.applications = [AttackerComputer]
            honorModel.add_association(assocAttackerInternet)
            
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
            # connect cloud network to internet
            assocInternetCloud = pythClasses.ns.NetworkConnection()
            assocInternetCloud.networks = [internet]
            assocInternetCloud.netConnections = [CloudInternetConn]

            # Add conn to internet
            DMZInternetConn = pythClasses.ns.ConnectionRule()
            DMZInternetConn.metaconcept = "ConnectionRule"
            DMZInternetConn.name = "ConnectionRule"
            DMZInternetConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DMZInternetConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed

            # Firewall for the connection between DMZ and internet
            FirewallDMZ = pythClasses.ns.RoutingFirewall()
            FirewallDMZ.metaconcept = "RoutingFirewall"
            FirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDMZ.integrityImpactLimitations = bernoulli_sample(0.25)
            # Connect firewall to conn
            assocFirewallDMZ = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZ.connectionRules = [DMZInternetConn]
            assocFirewallDMZ.routingFirewalls = [FirewallDMZ]
            # connect Vulnerability firewall
            assocDMZFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZFirewallVuln.application = [FirewallDMZ]
            assocDMZFirewallVuln.vulnerabilities = [vulnerabilityFirewallDMZ]

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            DSOOfficeNetwork.networkAccessControl = bernoulli_sample(0.8)
            DSOOfficeNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DSOOfficeNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            DSOOfficeHardwareVuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            DSOOfficeHardwareVuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityDSOOffice.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityDSOOffice.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"
            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User"
            DSORegularUser.securityAwareness = bernoulli_sample(0.5)
            DSORegularUser.noPasswordReuse = bernoulli_sample(0.5) 
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            DSOOfficeStationConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DSOOfficeStationConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed


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
            # Password to DSO user
            DSOSOfficeCreds = pythClasses.ns.Credentials()
            DSOSOfficeCreds.metaconcept = "Credentials"
            DSOSOfficeCreds.name = "Password/Username" 
            DSOSOfficeCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSOfficeCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Connect cred to DSO user
            assocDSOCredIdentity = pythClasses.ns.IdentityCredentials()
            assocDSOCredIdentity.identities = [DSORegularIdentity]
            assocDSOCredIdentity.credentials = [DSOSOfficeCreds]
        


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
            DSODMZConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DSODMZConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDSODMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDSODMZ.integrityImpactLimitations = bernoulli_sample(0.25)
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
            DMZNetwork.networkAccessControl = bernoulli_sample(0.8)
            DMZNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DMZNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            vulnerabilityDMZMail.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            vulnerabilityDMZMail.networkAccessRequired = 0.95 # need to have network access
            vulnerabilityDMZMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            DMZMailConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DMZMailConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
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

            # SFTP Assets
            # Add PM identity to SFTP
            DSOSFTPIdentity = pythClasses.ns.Identity()
            DSOSFTPIdentity.metaconcept = "Identity"
            DSOSFTPIdentity.name = "DSO SFTP identity"
            # Add SFTP server
            DSOSFTPServer = pythClasses.ns.Application()
            DSOSFTPServer.metaconcept = "Application"
            DSOSFTPServer.name = "DSO's SFTP server"
            # Vulnerability to SFTP
            VulnerabilitySFTP = pythClasses.ns.SoftwareVulnerability()
            VulnerabilitySFTP.metaconcept = "SoftwareVulnerability"
            VulnerabilitySFTP.name = "SoftwareVulnerability"
            VulnerabilitySFTP.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            VulnerabilitySFTP.networkAccessRequired = 0.95 # need to have network access
            VulnerabilitySFTP.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            VulnerabilitySFTP.integrityImpactLimitations = bernoulli_sample(0.5)
            VulnerabilitySFTP.confidentialityImpactLimitations = bernoulli_sample(0.5)
            VulnerabilitySFTP.availabilityImpactLimitations = bernoulli_sample(0.5)
            # Add conn between DMZ and SFTP
            SFTPConn = pythClasses.ns.ConnectionRule()
            SFTPConn.metaconcept = "ConnectionRule"
            SFTPConn.name = "ConnectionRule"
            SFTPConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            SFTPConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Add credentials to the dev identity connected to SFTP
            DSOSFTPCreds = pythClasses.ns.Credentials()
            DSOSFTPCreds.metaconcept = "Credentials"
            DSOSFTPCreds.name = "Key-pair" 
            DSOSFTPCreds.notGuessable = bernoulli_sample(1) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSFTPCreds.unique = 1 # assume that the password is not used for multiple services
            DSOSFTPCreds.notPhishable = bernoulli_sample(0.95)
            # Add passphrase to this identity
            SFTPMFADSOCreds = pythClasses.ns.Credentials()
            SFTPMFADSOCreds.metaconcept = "Credentials"
            SFTPMFADSOCreds.name = "passPhrase"
            SFTPMFADSOCreds.unique = bernoulli_sample(0.6) # cannot phish the phone needed to authenticate
            SFTPMFADSOCreds.notGuessable = bernoulli_sample(0.6)

            # SFTP associations
             # Connect Pm to SFTP
            assocPMtoSFTP = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocPMtoSFTP.lowPrivAppIAMs = [plexigridPMSFTPIdentity]
            assocPMtoSFTP.lowPrivApps = [DSOSFTPServer]
            # Connect DSO SFTP user to new identity
            assocDSOSFTPUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOSFTPUser.users = [DSORegularUser]
            assocDSOSFTPUser.userIds = [DSOSFTPIdentity]
            # Connect credentials to sales user
            assocSFTPCredDSOIdentity = pythClasses.ns.IdentityCredentials()
            assocSFTPCredDSOIdentity.identities = [DSOSFTPIdentity]
            assocSFTPCredDSOIdentity.credentials = [DSOSFTPCreds]
            # Connect MFA
            assocSFTPCredMFADSOIdentity = pythClasses.ns.ConditionalAuthentication()
            assocSFTPCredMFADSOIdentity.requiredFactors = [SFTPMFADSOCreds]
            assocSFTPCredMFADSOIdentity.credentials = [DSOSFTPCreds]
            # Connect the credentials data from decryption of the data
            assocSFTPCredDSOoffice = pythClasses.ns.AppContainment()
            assocSFTPCredDSOoffice.containedData = [SFTPEncryptedCreds]
            assocSFTPCredDSOoffice.containingApp = [DSOOfficeStation]
            # send data to SFTP from dso office station
            assocSFTPSentDSO = pythClasses.ns.SendData()
            assocSFTPSentDSO.senderApp = [DSOOfficeStation]
            assocSFTPSentDSO.sentData = [plexigridDataSFTP]
            # Add credentials to meteringData
            assocEncSFTPData = pythClasses.ns.EncryptionCredentials()
            assocEncSFTPData.encryptCreds = [SFTPCreds]
            assocEncSFTPData.encryptedData = [plexigridDataSFTP]
            # Add credentials data to credentials
            assocCredSFTPData = pythClasses.ns.InfoContainment()
            assocCredSFTPData.containerData = [SFTPEncryptedCreds]
            assocCredSFTPData.information = [SFTPCreds]
            if replica:
                # Connect to information replica
                assocreplicatedSFTPData = pythClasses.ns.Replica()
                assocreplicatedSFTPData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedSFTPData.dataReplicas = [plexigridDataSFTP]
                honorModel.add_association(assocreplicatedSFTPData)
            # Connect sftp to dmz network
            assocConnSFTPDmz = pythClasses.ns.ApplicationConnection()
            assocConnSFTPDmz.applications = [DSOSFTPServer]
            assocConnSFTPDmz.appConnections = [SFTPConn]
            # connect dmz network to sftp
            assocConnDmzSFTP = pythClasses.ns.NetworkConnection()
            assocConnDmzSFTP.networks = [DMZNetwork]
            assocConnDmzSFTP.netConnections = [SFTPConn]
            # vulnerability to SFTP
            assocSFTPVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSFTPVulnerability.application = [DSOSFTPServer]
            assocSFTPVulnerability.vulnerabilities = [VulnerabilitySFTP]
            # Connect DSO office to SFTP
            assocSFTPHighPrivDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocSFTPHighPrivDSOOffice.executionPrivIAMs = [DSOSFTPIdentity]
            assocSFTPHighPrivDSOOffice.execPrivApps = [DSOSFTPServer]
            # SFTP server send data
            assocSFTPSentToPM = pythClasses.ns.SendData()
            assocSFTPSentToPM.senderApp = [DSOSFTPServer]
            assocSFTPSentToPM.sentData = [plexigridDataSFTP]
            # SFTP receive data
            assocSFTPRecFromDSO = pythClasses.ns.ReceiveData()
            assocSFTPRecFromDSO.receiverApp = [DSOSFTPServer]
            assocSFTPRecFromDSO.receivedData = [plexigridDataSFTP]
            # SSH data in transit through the internet
            assocSSHDataInternetTransit= pythClasses.ns.DataInTransit()
            assocSSHDataInternetTransit.transitNetwork = [internet]
            assocSSHDataInternetTransit.transitData = [plexigridDataSSH]


            # Conn between database and Internet
            plexidatabasecloudconn = pythClasses.ns.ConnectionRule()
            plexidatabasecloudconn.metaconcept = "ConnectionRule"
            plexidatabasecloudconn.name = "ConnectionRule"
            

        
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataSFTP]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataSFTP]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataSFTP]
            # Data goes is sent from DSO office station
            assocSendDSO = pythClasses.ns.SendData()
            assocSendDSO.senderApp = [DSOOfficeStation]
            assocSendDSO.sentData = [plexigridDataSFTP]
            
            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDSO = pythClasses.ns.DataHosting()
                assocLocallyDSO.hostedData = [plexigridDataDSO]
                assocLocallyDSO.hardware = [DSOOfficeHardware]
            else:
                # Add data locally on application
                assocLocallyDSO = pythClasses.ns.AppContainment()
                assocLocallyDSO.containedData = [plexigridDataDSO]
                assocLocallyDSO.containingApp = [DSOOfficeStation]


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
            honorModel.add_asset(DSOSOfficeCreds)

            honorModel.add_asset(FirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDMZ)
            honorModel.add_association(assocFirewallDMZ)
            honorModel.add_association(assocDMZFirewallVuln)
            
            # SFTP assets
            honorModel.add_asset(DSOSFTPIdentity)
            honorModel.add_asset(DSOSFTPCreds)
            honorModel.add_asset(SFTPMFADSOCreds)
            honorModel.add_asset(DSOSFTPServer)
            honorModel.add_asset(VulnerabilitySFTP)
            honorModel.add_asset(SFTPConn)

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
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocSendDSO)

           
            honorModel.add_association(assocLocallyDSO)

            # SFTP Associations
            honorModel.add_association(assocPMtoSFTP)
            honorModel.add_association(assocDSOSFTPUser)
            honorModel.add_association(assocSFTPCredDSOIdentity)
            honorModel.add_association(assocSFTPCredMFADSOIdentity)
            honorModel.add_association(assocSFTPCredDSOoffice)
            honorModel.add_association(assocSFTPSentDSO)
            honorModel.add_association(assocEncSFTPData)
            honorModel.add_association(assocCredSFTPData)
            honorModel.add_association(assocConnSFTPDmz)
            honorModel.add_association(assocConnDmzSFTP)
            honorModel.add_association(assocSFTPVulnerability)
            honorModel.add_association(assocSFTPHighPrivDSOOffice)
            honorModel.add_association(assocSFTPSentToPM)
            honorModel.add_association(assocSFTPRecFromDSO)
            honorModel.add_association(assocSSHDataInternetTransit)

            honorModel.add_association(assocDSOCredIdentity)

            # A compromised or attacker-owned computer
            AttackerComputer = pythClasses.ns.Application()
            AttackerComputer.metaconcept = "Application"
            AttackerComputer.name = "Compromised computer"
            honorModel.add_asset(AttackerComputer)
            # Connected to the internet
            assocAttackerInternet = pythClasses.ns.NetworkExposure()
            assocAttackerInternet.networks = [internet]
            assocAttackerInternet.applications = [AttackerComputer]
            honorModel.add_association(assocAttackerInternet)

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
            DMZInternetConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DMZInternetConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed

            # Firewall for the connection between DMZ and internet
            FirewallDMZ = pythClasses.ns.RoutingFirewall()
            FirewallDMZ.metaconcept = "RoutingFirewall"
            FirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDMZ.integrityImpactLimitations = bernoulli_sample(0.25)
            # Connect firewall to conn
            assocFirewallDMZ = pythClasses.ns.FirewallConnectionRule()
            assocFirewallDMZ.connectionRules = [DMZInternetConn]
            assocFirewallDMZ.routingFirewalls = [FirewallDMZ]
            # connect Vulnerability firewall
            assocDMZFirewallVuln = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocDMZFirewallVuln.application = [FirewallDMZ]
            assocDMZFirewallVuln.vulnerabilities = [vulnerabilityFirewallDMZ]

            # Internet connected to public DMZ
            assocConnInternetDMZ = pythClasses.ns.NetworkConnection()
            assocConnInternetDMZ.networks = [internet]
            assocConnInternetDMZ.netConnections = [DMZInternetConn]

            # Add DSO Office Zone LAN network
            DSOOfficeNetwork = pythClasses.ns.Network()
            DSOOfficeNetwork.metaconcept = "Network"
            DSOOfficeNetwork.name = "DSO Office Zone LAN"
            DSOOfficeNetwork.networkAccessControl = bernoulli_sample(0.8)
            DSOOfficeNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DSOOfficeNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
            # Office Station application
            DSOOfficeStation = pythClasses.ns.Application()
            DSOOfficeStation.metaconcept = "Application"
            DSOOfficeStation.name = "DSO Office station"
            # Add hardware (computer) to DSO office
            DSOOfficeHardware = pythClasses.ns.Hardware()
            DSOOfficeHardware.metaconcept = "Hardware"
            DSOOfficeHardware.name = "Hardware"
            # Add hardware vulnerability
            DSOOfficeHardwareVuln = pythClasses.ns.HardwareVulnerability()
            DSOOfficeHardwareVuln.metaconcept = "HardwareVulnerability"
            DSOOfficeHardwareVuln.name = "HardwareVulnerability"
            DSOOfficeHardwareVuln.effortRequiredToExploit = bernoulli_sample(0.95) # they keep the hardware up to date and even if stolen the hackers need to spend alot of time to compromise
            DSOOfficeHardwareVuln.physicalAccessRequired = 1 # They need physical access to be able to exploit hardware
            # Software vulnerability
            vulnerabilityDSOOffice = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityDSOOffice.metaconcept = "SoftwareVulnerability"
            vulnerabilityDSOOffice.name = "SoftwareVulnerability"
            vulnerabilityDSOOffice.highComplexityExploitRequired  = bernoulli_sample(0.8) # difficult but not more than microsoft
            vulnerabilityDSOOffice.userInteractionRequired = bernoulli_sample(0.95) # The user has to click something malicious
            vulnerabilityDSOOffice.highPrivilegesRequired = bernoulli_sample(0.95) # Need to have admin role
            vulnerabilityDSOOffice.integrityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.confidentialityImpactLimitations = bernoulli_sample(0.25)
            vulnerabilityDSOOffice.networkAccessRequired = 1 # Need network access to exploit
            # Identity symbolyzing a regular User
            DSORegularIdentity = pythClasses.ns.Identity()
            DSORegularIdentity.metaconcept = "Identity"
            DSORegularIdentity.name = "Regular User"

            # User symbolyzing the real human
            DSORegularUser = pythClasses.ns.User()
            DSORegularUser.metaconcept = "User"
            DSORegularUser.name = "DSO User"
            DSORegularUser.securityAwareness = bernoulli_sample(0.5)
            DSORegularUser.noPasswordReuse = bernoulli_sample(0.5)

            # Password to DSO user
            DSOSOfficeCreds = pythClasses.ns.Credentials()
            DSOSOfficeCreds.metaconcept = "Credentials"
            DSOSOfficeCreds.name = "Password/Username" 
            DSOSOfficeCreds.notGuessable = bernoulli_sample(0.6) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSOfficeCreds.unique = bernoulli_sample(0.6) # assume that the password is not used for multiple services
            # Connect cred to DSO user
            assocDSOCredIdentity = pythClasses.ns.IdentityCredentials()
            assocDSOCredIdentity.identities = [DSORegularIdentity]
            assocDSOCredIdentity.credentials = [DSOSOfficeCreds]
             
            # conn for office station
            DSOOfficeStationConn = pythClasses.ns.ConnectionRule()
            DSOOfficeStationConn.metaconcept = "ConnectionRule"
            DSOOfficeStationConn.name = "ConnectionRule"
            DSOOfficeStationConn.payloadInspection = bernoulli_sample(0.9) # shall probably have some kind of IDPS
            DSOOfficeStationConn.restricted = bernoulli_sample(0.9) # protocols that can be used for exploit are closed
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
            DSODMZConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DSODMZConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Firewall for the connection between DMZ and DSO office
            DSOFirewallDMZ = pythClasses.ns.RoutingFirewall()
            DSOFirewallDMZ.metaconcept = "RoutingFirewall"
            DSOFirewallDMZ.name = "Firewall"
            # Add software vulnerabilities to firewall DMZ/DSO
            vulnerabilityFirewallDSODMZ = pythClasses.ns.SoftwareVulnerability()
            vulnerabilityFirewallDSODMZ.metaconcept = "SoftwareVulnerability"
            vulnerabilityFirewallDSODMZ.name = "SoftwareVulnerability Firewall"
            vulnerabilityFirewallDSODMZ.highComplexityExploitRequired = bernoulli_sample(0.8)
            vulnerabilityFirewallDSODMZ.integrityImpactLimitations = bernoulli_sample(0.25)
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
            DMZNetwork.networkAccessControl = bernoulli_sample(0.8)
            DMZNetwork.eavesdropDefense = bernoulli_sample(0.8)
            DMZNetwork.adversaryInTheMiddleDefense = bernoulli_sample(0.8)
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
            vulnerabilityDMZMail.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            vulnerabilityDMZMail.networkAccessRequired = 0.95 # need to have network access
            vulnerabilityDMZMail.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            # Add mail server conn to public dmz
            DMZMailConn = pythClasses.ns.ConnectionRule()
            DMZMailConn.metaconcept = "ConnectionRule"
            DMZMailConn.name = "ConnectionRule"
            DMZMailConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            DMZMailConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
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
            assocSendDSO.sentData = [plexigridDataSFTP]
            # The data is accessable from the internet
            assocDataInternetDevTransit = pythClasses.ns.DataInTransit()
            assocDataInternetDevTransit.transitNetwork = [internet]
            assocDataInternetDevTransit.transitData = [plexigridDataDevOneDrive]
            # The data is accessable from the internet
            assocDataInternetPMTransit = pythClasses.ns.DataInTransit()
            assocDataInternetPMTransit.transitNetwork = [internet]
            assocDataInternetPMTransit.transitData = [plexigridDataPMOneDrive]
            # Data is in transit through internet
            assocDataInternet= pythClasses.ns.DataInTransit()
            assocDataInternet.transitNetwork = [internet]
            assocDataInternet.transitData = [plexigridDataSFTP]
            # Data is in transit through DSO office zone
            assocDataDSOfficeTransit= pythClasses.ns.DataInTransit()
            assocDataDSOfficeTransit.transitNetwork = [DSOOfficeNetwork]
            assocDataDSOfficeTransit.transitData = [plexigridDataSFTP]
            # Data is in transit through Public DMZ
            assocDataDMZTransit= pythClasses.ns.DataInTransit()
            assocDataDMZTransit.transitNetwork = [DMZNetwork]
            assocDataDMZTransit.transitData = [plexigridDataSFTP]
            # SSH data in transit through the internet
            assocSSHDataInternetTransit= pythClasses.ns.DataInTransit()
            assocSSHDataInternetTransit.transitNetwork = [internet]
            assocSSHDataInternetTransit.transitData = [plexigridDataSSH]

            # SFTP Assets
            # Add PM identity to SFTP
            DSOSFTPIdentity = pythClasses.ns.Identity()
            DSOSFTPIdentity.metaconcept = "Identity"
            DSOSFTPIdentity.name = "DSO SFTP identity"
            # Add SFTP server
            DSOSFTPServer = pythClasses.ns.Application()
            DSOSFTPServer.metaconcept = "Application"
            DSOSFTPServer.name = "DSO's SFTP server"
            # Vulnerability to SFTP
            VulnerabilitySFTP = pythClasses.ns.SoftwareVulnerability()
            VulnerabilitySFTP.metaconcept = "SoftwareVulnerability"
            VulnerabilitySFTP.name = "SoftwareVulnerability"
            VulnerabilitySFTP.highComplexityExploitRequired = bernoulli_sample(0.95) # hard to exploit
            VulnerabilitySFTP.networkAccessRequired = 0.95 # need to have network access
            VulnerabilitySFTP.highPrivilegesRequired = bernoulli_sample(0.95) # need admin privilege to exploit
            # Add conn between DMZ and SFTP
            SFTPConn = pythClasses.ns.ConnectionRule()
            SFTPConn.metaconcept = "ConnectionRule"
            SFTPConn.name = "ConnectionRule"
            SFTPConn.restricted = bernoulli_sample(0.9) # ports on the computer that are blocked
            SFTPConn.payloadInspection = bernoulli_sample(0.9) # IDPS try to filter malicous payloads
            # Add credentials to the dev identity connected to SFTP
            DSOSFTPCreds = pythClasses.ns.Credentials()
            DSOSFTPCreds.metaconcept = "Credentials"
            DSOSFTPCreds.name = "Key-pair" 
            DSOSFTPCreds.notGuessable = bernoulli_sample(1) # How hard it is to guess the password (not a part of the most common password dictionary)
            DSOSFTPCreds.unique = 0.95 # assume that the password is not used for multiple services
            DSOSFTPCreds.notPhishable = bernoulli_sample(0.95)
            # Add MFA to this identity
            SFTPMFADSOCreds = pythClasses.ns.Credentials()
            SFTPMFADSOCreds.metaconcept = "Credentials"
            SFTPMFADSOCreds.name = "passPhrase"
            SFTPMFADSOCreds.unique = bernoulli_sample(0.6) # cannot phish the phone needed to authenticate
            SFTPMFADSOCreds.notGuessable = bernoulli_sample(0.6)

            # SFTP associations
             # Connect Pm to SFTP
            assocPMtoSFTP = pythClasses.ns.LowPrivilegeApplicationAccess()
            assocPMtoSFTP.lowPrivAppIAMs = [plexigridPMSFTPIdentity]
            assocPMtoSFTP.lowPrivApps = [DSOSFTPServer]
            # Connect DSO SFTP user to new identity
            assocDSOSFTPUser = pythClasses.ns.UserAssignedIdentities()
            assocDSOSFTPUser.users = [DSORegularUser]
            assocDSOSFTPUser.userIds = [DSOSFTPIdentity]
            # Connect credentials to sales user
            assocSFTPCredDSOIdentity = pythClasses.ns.IdentityCredentials()
            assocSFTPCredDSOIdentity.identities = [DSOSFTPIdentity]
            assocSFTPCredDSOIdentity.credentials = [DSOSFTPCreds]
            # Connect MFA
            assocSFTPCredMFADSOIdentity = pythClasses.ns.ConditionalAuthentication()
            assocSFTPCredMFADSOIdentity.requiredFactors = [SFTPMFADSOCreds]
            assocSFTPCredMFADSOIdentity.credentials = [DSOSFTPCreds]
            # Connect the credentials data from decryption of the data
            assocSFTPCredDSOoffice = pythClasses.ns.AppContainment()
            assocSFTPCredDSOoffice.containedData = [SFTPEncryptedCreds]
            assocSFTPCredDSOoffice.containingApp = [DSOOfficeStation]
            # send data to SFTP from dso office station
            assocSFTPSentDSO = pythClasses.ns.SendData()
            assocSFTPSentDSO.senderApp = [DSOOfficeStation]
            assocSFTPSentDSO.sentData = [plexigridDataSFTP]
            # Add credentials to meteringData
            assocEncSFTPData = pythClasses.ns.EncryptionCredentials()
            assocEncSFTPData.encryptCreds = [SFTPCreds]
            assocEncSFTPData.encryptedData = [plexigridDataSFTP]
            # Add credentials data to credentials
            assocCredSFTPData = pythClasses.ns.InfoContainment()
            assocCredSFTPData.containerData = [SFTPEncryptedCreds]
            assocCredSFTPData.information = [SFTPCreds]
            if replica:
                # Connect to information replica
                assocreplicatedSFTPData = pythClasses.ns.Replica()
                assocreplicatedSFTPData.replicatedInformation = [replicatedMeterDatatoDatabase]
                assocreplicatedSFTPData.dataReplicas = [plexigridDataSFTP]
                honorModel.add_association(assocreplicatedSFTPData)
            # Connect sftp to dmz network
            assocConnSFTPDmz = pythClasses.ns.ApplicationConnection()
            assocConnSFTPDmz.applications = [DSOSFTPServer]
            assocConnSFTPDmz.appConnections = [SFTPConn]
            # connect dmz network to sftp
            assocConnDmzSFTP = pythClasses.ns.NetworkConnection()
            assocConnDmzSFTP.networks = [DMZNetwork]
            assocConnDmzSFTP.netConnections = [SFTPConn]
            # vulnerability to SFTP
            assocSFTPVulnerability = pythClasses.ns.ApplicationVulnerability_SoftwareVulnerability_Application()
            assocSFTPVulnerability.application = [DSOSFTPServer]
            assocSFTPVulnerability.vulnerabilities = [VulnerabilitySFTP]
            # Connect DSO office to SFTP
            assocSFTPHighPrivDSOOffice = pythClasses.ns.ExecutionPrivilegeAccess()
            assocSFTPHighPrivDSOOffice.executionPrivIAMs = [DSOSFTPIdentity]
            assocSFTPHighPrivDSOOffice.execPrivApps = [DSOSFTPServer]
            # SFTP server send data
            assocSFTPSentToPM = pythClasses.ns.SendData()
            assocSFTPSentToPM.senderApp = [DSOSFTPServer]
            assocSFTPSentToPM.sentData = [plexigridDataSFTP]
            # SFTP receive data
            assocSFTPRecFromDSO = pythClasses.ns.ReceiveData()
            assocSFTPRecFromDSO.receiverApp = [DSOSFTPServer]
            assocSFTPRecFromDSO.receivedData = [plexigridDataSFTP]
            
            if lastTestAttack == True:
                # Add locally downloaded data
                assocLocallyDSO = pythClasses.ns.DataHosting()
                assocLocallyDSO.hostedData = [unencryptedData]
                assocLocallyDSO.hardware = [DSOOfficeHardware]
            else:
                # Add data locally on application
                assocLocallyDSO = pythClasses.ns.AppContainment()
                assocLocallyDSO.containedData = [unencryptedData]
                assocLocallyDSO.containingApp = [DSOOfficeStation]


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

            honorModel.add_asset(DSOSOfficeCreds)

            honorModel.add_asset(FirewallDMZ)
            honorModel.add_asset(vulnerabilityFirewallDMZ)
            honorModel.add_association(assocFirewallDMZ)
            honorModel.add_association(assocDMZFirewallVuln)
            

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

            honorModel.add_association(assocDataInternetDevTransit)
            honorModel.add_association(assocDataInternetPMTransit)
            honorModel.add_association(assocDataInternet)
            honorModel.add_association(assocDataDSOfficeTransit)
            honorModel.add_association(assocDataDMZTransit)
            honorModel.add_association(assocLocallyDSO)
            honorModel.add_association(assocSSHDataInternetTransit)

            # SFTP assets
            honorModel.add_asset(DSOSFTPIdentity)
            honorModel.add_asset(DSOSFTPCreds)
            honorModel.add_asset(SFTPMFADSOCreds)
            honorModel.add_asset(DSOSFTPServer)
            honorModel.add_asset(VulnerabilitySFTP)
            honorModel.add_asset(SFTPConn)

            # SFTP Associations
            honorModel.add_association(assocPMtoSFTP)
            honorModel.add_association(assocDSOSFTPUser)
            honorModel.add_association(assocSFTPCredDSOIdentity)
            honorModel.add_association(assocSFTPCredMFADSOIdentity)
            honorModel.add_association(assocSFTPCredDSOoffice)
            honorModel.add_association(assocSFTPSentDSO)
            honorModel.add_association(assocEncSFTPData)
            honorModel.add_association(assocCredSFTPData)
            honorModel.add_association(assocConnSFTPDmz)
            honorModel.add_association(assocConnDmzSFTP)
            honorModel.add_association(assocSFTPVulnerability)
            honorModel.add_association(assocSFTPHighPrivDSOOffice)
            honorModel.add_association(assocSFTPSentToPM)
            honorModel.add_association(assocSFTPRecFromDSO)

            honorModel.add_association(assocDSOCredIdentity)

            # A compromised or attacker-owned computer
            AttackerComputer = pythClasses.ns.Application()
            AttackerComputer.metaconcept = "Application"
            AttackerComputer.name = "Compromised computer"
            honorModel.add_asset(AttackerComputer)
            # Connected to the internet
            assocAttackerInternet = pythClasses.ns.NetworkExposure()
            assocAttackerInternet.networks = [internet]
            assocAttackerInternet.applications = [AttackerComputer]
            honorModel.add_association(assocAttackerInternet)
            
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
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
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
            # Add dev IDPS security suite
            plexigridDevIDPS = pythClasses.ns.IDPS()
            plexigridDevIDPS.metaconcept = "IDPS"
            plexigridDevIDPS.name = "IDPS"
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