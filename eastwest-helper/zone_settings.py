####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA

PUSH_CONFIG_TO_PA = True
REVIEW_TAG = "east-west-helper-review"

EXISTING_TRUST_ZONE = "trusted"
NEW_EASTWEST_ZONE = "Viawest-TS"

#EXISTING_TRUST_SUBNET = " 7.7.7.0/24"
EXISTING_TRUST_SUBNET = "192.168.77.14/32"
#NEW_EASTWEST_SUBNET = "10.5.0.0/24"

EXISTING_UNTRUST_ZONE = "untrusted"


####### EDIT ABOVE ############################################################################