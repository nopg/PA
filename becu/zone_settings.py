####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA

PUSH_CONFIG_TO_PA = False

NEW_PRIVATE_INTRAZONE = "NEW-PRIVATE-ZONE-NAME"
EXISTING_PRIVATE_ZONES = {
    "dmz":"NEW-DMZ-OBJ", 
    "trusted":"NEW-TRUST-OBJ",
    "onprem":"NEW-ONPREM-OBJ",
}

####### EDIT ABOVE ############################################################################