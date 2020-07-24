####### EDIT BELOW #############################################################################################

# Using 'python eastwest-helper.py -x <filename.xml>' from cli will disable PUSH_CONFIG_TO_PA automatically
#   as well as load security rules from <filename.xml> instead of connecting to a PA--currently unsupported.

PUSH_CONFIG_TO_PA = True                # Load new ruleset as partial named config. Push as Candidate config

REVIEW_TAG = "east-west-helper-review"  # Tag name for rules that need to be reviewed (Address Object Name/IP)
CLONED_TAG = "east-west-helper-cloned"  # Tag name for cloned/any rules

EXISTING_TRUST_ZONE = "inside"         # Name of existing 'inside' zone containing subnet(s) to be moved
NEW_EASTWEST_ZONE = "DataBase-Servers"        # Name of new zone that servers will be moving to

EXISTING_TRUST_SUBNET = [
    "172.20.10.0/8",        # Inside subnet(s) that will be moved to the new zone. Must be of type list.
   #"192.168.78.0/24",      # Example if using more than one subnet. Uncomment and update.
   # SECOND SUBNET NOT YET SUPPORTED --- WILL BE SOON.
]
# EXISTING_TRUST_SUBNET = ["192.168.77.14/32"]  # If mask is /32, will check address-objects, not 'any' rules.


####### EDIT ABOVE #############################################################################################
