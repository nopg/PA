####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA

PUSH_CONFIG_TO_PA = False

NEW_EASTWEST_ZONE = "Viawest-TS"
NEW_EASTWEST_SUBNET = "10.5.0.0/24"
EXISTING_TRUST_ZONE = "trusted"
EXISTING_TRUST_SUBNET = "7.7.7.0/24"
EXISTING_UNTRUST_ZONE = "untrusted"


EXISTING_PRIVATE_ZONE = {
    "inside":"NEW-DMZ-OBJ", 
    "trusted":"NEW-TRUST-OBJ",
    "onprem":"NEW-ONPREM-OBJ"
}

####### EDIT ABOVE ############################################################################