####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA

PUSH_CONFIG_TO_PA = True

NEW_PRIVATE_INTRAZONE = "TRUST_L3" # the new trusted/private zone name to be used for all intra-zone traffic.
EXISTING_EAST_OBJECTS = {
    "Existing East Object Name1":"New West Object Name1", 
    "Existing East Object Name2":"New West Object Name2"
}

####### EDIT ABOVE ############################################################################