####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA

PUSH_CONFIG_TO_PA = True

NEW_PRIVATE_INTRAZONE = "TRUST_L3"
EXISTING_EAST_OBJECTS = {
    "Azure East Commerce Network":"Azure West Commerce Network", 
    "Azure East ASE network":"Commerce Prod ASE",
    "Azrue East Management Network":"Azure West Mgmt Network",
    "Azure East Partner Network":"Azure West Partner Network",
    "Azure East Secure Network":"Azure West Secure Network",
    "Azure East Community Network":"Azure West_Community_Network"
}
WEST_COMMERCE_EXTRA = "Commerce Prod ASE"

####### EDIT ABOVE ############################################################################