"""
 - NEW_PRIVATE_INTRAZONE
    type 'string', the new trusted/private zone name to be used for all intra-zone traffic.

 - EXISTING_PRIVATE_ZONES
    type 'dictionary'
    The 'key' is any (typically trusted) zone name that should be converted to NEW_PRIVATE_ZONENAME.
    The 'value' is the name of the address or address-group that is associated with the above zone.
    The address/group object should already exist in the PA configuration. 
    If more than one subnet is desired, an address-group should be used, with this version of the script.
    Support for adding other objects afterwards can be found in becu-west.py

 - PUSH_CONFIG_TO_PA
    type 'boolean'
    Use 'False' to ensure the script won't ask to push any changes to the PA(n). 
    This allows you to pull config from an online PA but compare via .xml before running and pushing.
    If 'True', there are still multiple prompts before anything is pushed. All changes will be
    in the candidate config, the script will NEVER commit.
    Using 'python becu.py -x <filename.xml>' will automatically disable this, in case you forgot to change it to 'True'.

Using 'python becu.py -x <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
As well as load security rules from <filename> instead of connecting to a PA.
"""
####### EDIT BELOW ############################################################################
NEW_PRIVATE_INTRAZONE = "NEW-PRIVATE-ZONE-NAME"

EXISTING_PRIVATE_ZONES = {
    "dmz":"NEW-DMZ-OBJ_OR_OBJ-GROUP", 
    "trusted":"NEW-TRUST-OBJ_OR_OBJ-GROUP",
    "onprem":"NEW-ONPREM-OBJ_OR_OBJ-GROUP"
}

PUSH_CONFIG_TO_PA = True
####### EDIT ABOVE ############################################################################