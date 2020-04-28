"""
Description: 
    Cloud/Intrazone PA Security Rules Migration

    This script can be used to migrate existing PA Security Rules to an 'intrazone' design.
    This rule design may become a typical 'cloud style' design. Let's hope zone-based can make a comeback.
    
    You can stay offline and load XML files and spit out the modified results, or
    You can connect to a PA or Panorama and pull the rules from there.
    Once the rules have been modified a file will be created in the existing directory, with the new rules.
    If PUSH_CONFIG_TO_PA global variable is True, it will then prompt for upload/configuration preferences.
    See 'Cautions' below for more usage info.

Requires:
    requests
    xmltodict
        to install try: pip3 install -r requirements.txt

Author:
    Ryan Gillespie rgillespie@compunet.biz
    Docstring stolen from Devin Callaway

Tested:
    Tested on macos 10.13.6
    Python: 3.6.2
    PA VM100, Panorama

Example usage:
        $ python becu.py <PA(N) mgmt IP> <username>
        Password: 

Cautions:
    This script uses 2 global dictionaries (global for easy end-user modification)
     - EXISTING_PRIVATE_ZONES
        type 'dictionary'
        The key is any (typically trusted) zone name that should be updated, due to intra-zone conversion.
        The value is the name of the address or address-group that is associated with the above zone.
        The address/group object should already exist in the PA configuration.
     - NEW_PRIVATE_INTRAZONE
        type 'string', the new trusted/private zone name to be used for all intra-zone traffic.

Legal:
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from getpass import getpass
import sys
import os
import json
import time
import xml.dom.minidom
import copy

import xmltodict
import api_lib_pa as pa


####### EDIT BELOW ############################################################################

# Using 'python becu.py <filename>' from cli will disable PUSH_CONFIG_TO_PA automatically
# As well as load security rules from <filename> instead of connecting to a PA
PUSH_CONFIG_TO_PA = False

NEW_PRIVATE_INTRAZONE = "NEW-PRIVATE-ZONE-NAME"
EXISTING_PRIVATE_ZONES = {
    "dmz":"NEW-DMZ-OBJ", 
    "trusted":"NEW-TRUST-OBJ",
    "onprem":"NEW-ONPREM-OBJ",
    "untrusted":"NEW-UNTRUST-OBJ",
}

####### EDIT ABOVE ############################################################################


class mem: 
    XPATH_SECURITYRULES = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    XPATH_POST_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/post-rulebase/security/rules"
    XPATH_PRE_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/pre-rulebase/security/rules"
    pa_ip = None
    username = None
    password = None
    fwconn = None
    device_group = None
    filename = ""


def grab_xml_or_json_file(filename):
    """
    Read PA file, return dict based on xml or json
    """
    output = None

    try:
        with open(filename, "r") as fin:
            data = fin.read()
            if filename.endswith(".xml"):
                output = xmltodict.parse(data)
                if "response" in output:
                    output = output["response"]
                else:
                    output = output["config"]["security"]
                    output = {"result": output}
            elif filename.endswith(".json"):
                output = json.loads(data)        
    except FileNotFoundError:
        print("\nFile not found, check filename.\n")
        sys.exit(0)

    return output


def error_check(response, operation):
    if response.status_code != 200 or "error" in response.text:
        print(f"\n\n{operation} Failed.")
        print(f"Response Code: {response.status_code}")
        print(f"Response: {response.text}\n\n")
        sys.exit(0)


def output_and_push_changes(modified_rules, filename=None, xpath=None):

    # Always create an output file with the modified-rules.
    if not filename:
        filename = "modified-pa-rules.xml"
    # Prepare output
    add_entry_tag = {"entry": modified_rules}   # Adds the <entry> tag to each rule
    modified_rules_xml = {"config": {"security": {"rules": add_entry_tag} } } # Provides an xpath for importing
    data = xmltodict.unparse(modified_rules_xml)    # Turn XML into a string
    prettyxml = xml.dom.minidom.parseString(data).toprettyxml() # Pretty-fi the XML before creating file
    prettyxml = prettyxml.replace('<?xml version="1.0" ?>', "") # Can't import with this in the XML, remove it
    # Create output file
    with open(filename, "w") as fout:
        fout.write(prettyxml)
        print(f"\nOutput at: {filename}\n")

    if PUSH_CONFIG_TO_PA:
        # Ask for filename
        print("\n\tUploading to PA/Panorama:")
        new_filename = input(f"\tFilename[{filename}]: ")
        # Accept default, if entered, update and rename on filesystem
        if new_filename:
            os.rename(filename, new_filename)
            filename = new_filename

        # Import Named Configuration .xml via Palo Alto API
        with open(filename) as fin:
            print("\nUploading Configuration, Please Wait....")
            response = mem.fwconn.import_named_configuration(fin)

        error_check(response, "Importing Configuration")

        print("\nConfig Uploaded.")
        
        load_config = ""
        while load_config.lower() not in ("y", "n"):
            load_config = input("\nLoad config as candidate configuration? [y/n]: ")
        if load_config == "n":
            print("\nThank you, finished.\n")
        else:
            load_url = f"https://{mem.fwconn.pa_ip}:443/api/?type=op&key={mem.fwconn.key}&cmd=<load><config><partial><mode>replace</mode><from-xpath>/config/security/rules</from-xpath><to-xpath>{xpath}</to-xpath><from>{filename}</from></partial></config></load>"
            
            response = mem.fwconn.session[mem.fwconn.pa_ip].get(load_url, verify=False)

            error_check(response, "Loading Configuration")

            print("\nCandidate configuration successfully loaded...enjoy the new ruleset!")
            print("Review configuration and Commit manually via the GUI.\n")
    
    return None


def modify_rules(security_rules):
    """
    MODIFY SECURITY RULES
    This accepts a dictionary of rules and modifies them to a cloud-based intra-zone ruleset.
    This script utilizes EXISTING_PRIVATE_ZONES, and NEW_PRIVATE_INTRAZONE

    :param security_rules: existing security rules
    :return: modified_rules, new/modified security rule-set
    """
    def modify(srcdst, tofrom, x_zone, x_addr):
        """
        inner function (possibly to be moved outside later)
        The bulk of the logic for zone modification is done here
        Source & destination behave the same, this allows the same code to be used for both.

        :param srcdst: the xml tag needed for insertion into the new rule
        :param x_zone: from or to, zone name
        :param x_addr: source or destination, address/group object
        """
        
        try:
            if isinstance(x_zone, list):
                cx_zone = x_zone.copy()
                count = 0
                for zone in cx_zone: 
                    if zone in EXISTING_PRIVATE_ZONES:
                        # Zone found, update this zone to the new private intra-zone
                        newrule[tofrom]["member"].remove(zone)
                        if NEW_PRIVATE_INTRAZONE not in newrule[tofrom]["member"]:
                            newrule[tofrom]["member"].append(NEW_PRIVATE_INTRAZONE)

                        # Get the address/group object associated to this zone
                        new_addr_obj = EXISTING_PRIVATE_ZONES[zone]

                        if isinstance(x_addr, list):
                            cx_addr = x_addr.copy()
                            for x in cx_addr:
                                if x == "any":  # The source/destination IP's are 'any', update the rule to use the new object
                                    newrule[srcdst]["member"].remove("any")
                                    newrule[srcdst]["member"].append(new_addr_obj)
                        elif x_addr == "any":   # The source/destination IP's are 'any', update the rule to use the new object
                            if count == 1:  # Corner case; 2 zones, 1 existing address object, convert to list
                                count += 1
                                newrule[srcdst]["member"] = list(newrule[srcdst]["member"].split())
                                newrule[srcdst]["member"].append(new_addr_obj)
                            elif count > 1:
                                newrule[srcdst]["member"].append(new_addr_obj)
                            else:
                                count += 1
                                newrule[srcdst]["member"] = new_addr_obj
                    # Not Found in Existing List, let the user know just in case.
                    else:
                        print(f"'{zone}' not found in existing private zone list")

            elif x_zone in EXISTING_PRIVATE_ZONES:
                # Zone found, update this zone to the new private intra-zone
                newrule[tofrom]["member"] = NEW_PRIVATE_INTRAZONE

                # Get the address/group object associated to this zone
                new_addr_obj = EXISTING_PRIVATE_ZONES[x_zone]
                if isinstance(x_addr, list):
                    cx_addr = x_addr.copy()
                    for x in cx_addr:
                        if x == "any": # The source/destination IP's are 'any', update the rule to use the new object
                            newrule[srcdst]["member"].remove("any")
                            newrule[srcdst]["member"].append(new_addr_obj)

                elif x_addr == "any":   # The source/destination IP's are 'any', update the rule to use the new object
                    newrule[srcdst]["member"] = new_addr_obj

            # Not Found in Existing List, let the user know just in case.
            else:
                print(f"'{x_zone}' not found in existing private zone list")
        except TypeError:
            print("\nError, candidate config detected. Please commit or revert changes before proceeding.\n")
            sys.exit(0)
    
        return None

    modified_rules = []
    print("\nModifying...\n")
    for oldrule in security_rules:
        newrule = copy.deepcopy(oldrule)
        from_zone = oldrule["from"]["member"]
        to_zone = oldrule["to"]["member"]
        src_addr = oldrule["source"]["member"]
        dst_addr = oldrule["destination"]["member"]

        # Check and modify to intra-zone based rules
        modify("source", "from", from_zone,src_addr)
        modify("destination", "to", to_zone,dst_addr)

        modified_rules.append(newrule)

    print("..Done.")
    return modified_rules


def becu(pa_ip, username, password, pa_or_pan, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab security rules from pa/pan.
    Modify them for intra-zone migration.
    """
    mem.pa_ip = pa_ip
    mem.username = username
    mem.password = password
    if pa_or_pan != "xml":
        mem.fwconn = pa.api_lib_pa(mem.pa_ip, mem.username, mem.password)
    mem.pa_or_pan = pa_or_pan
    mem.filename = filename
    to_output = []


    if mem.pa_or_pan == "xml":
        # Grab 'start' time
        start = time.perf_counter()
        # Grab XML file, modify rules, and create output file.
        security_rules = grab_xml_or_json_file(mem.filename)
        modified_rules = modify_rules(security_rules["result"]["rules"]["entry"])
        output_and_push_changes(modified_rules, "modified-xml-rules.xml")

    elif mem.pa_or_pan == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        device_groups, _ = mem.fwconn.grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        mem.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")

        # Grab 'start' time
        start = time.perf_counter()
    
        # Set the XPath now that we have the Device Group
        mem.XPATH_PRE_SECURITY_RULES_PAN = mem.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)
        mem.XPATH_POST_SECURITY_RULES_PAN = mem.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)

        # Grab Rules
        pre_security_rules = mem.fwconn.grab_api_output("xml", mem.XPATH_PRE_SECURITY_RULES_PAN, "api/pre-rules.xml")
        post_security_rules = mem.fwconn.grab_api_output("xml", mem.XPATH_POST_SECURITY_RULES_PAN, "api/post-rules.xml")

        # Modify the rules, Pre & Post, then append to output list
        if pre_security_rules["result"]:
            modified_rules_pre = modify_rules(pre_security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules_pre,"modified-pre-rules.xml", mem.XPATH_PRE_SECURITY_RULES_PAN])
        if post_security_rules["result"]:
            modified_rules_post = modify_rules(post_security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules_post,"modified-post-rules.xml", mem.XPATH_POST_SECURITY_RULES_PAN])
            
    elif mem.pa_or_pan == "pa":
        # Grab 'start' time
        start = time.perf_counter()
        # Grab Rules
        security_rules = mem.fwconn.grab_api_output("xml", mem.XPATH_SECURITYRULES, "api/pa-rules.xml")
        if security_rules["result"]:
            # Modify the rules, append to be output
            modified_rules = modify_rules(security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules,"modified-pa-rules.xml", mem.XPATH_SECURITYRULES])

    # Begin creating output and/or pushing rules to PA/PAN
    for ruletype in to_output:
        output_and_push_changes(*ruletype)

    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.\n")


# If run from the command line
if __name__ == "__main__":

    # Guidance on how to use the script
    if len(sys.argv) == 2:
        PUSH_CONFIG_TO_PA = False
        filename = sys.argv[1]
        becu("n/a","n/a","n/a","xml",filename)
        sys.exit(0)
    elif len(sys.argv) != 3:
        print("\nplease provide the following arguments:")
        print(
            "\tpython3 becu.py <PA/Panorama IP> <username>\n\n"
        )
        sys.exit(0)
    else:
        # Correct input, no filename, set to None
        filename = None

    # Gather input
    pa_ip = sys.argv[1]
    username = sys.argv[2]
    password = getpass("Enter Password: ")

    # Create connection with the Palo Alto as 'obj' to test login success
    try:
        paobj = pa.api_lib_pa(pa_ip, username, password)
    except:
        print(f"Error connecting to: {pa_ip}\nCheck username/password and network connectivity.")
        sys.exit(0)

    # PA or Panorama?
    allowed = list("12")  # Allowed user input
    incorrect_input = True
    while incorrect_input:
        pa_or_pan = input(
            """\nIs this a PA Firewall or Panorama?

        1) PA (Firewall)
        2) Panorama (PAN)

        Enter 1 or 2: """
        )

        for value in pa_or_pan:
            if value not in allowed:
                incorrect_input = True
                break
            else:
                incorrect_input = False

    if pa_or_pan == "1":
        pa_or_pan = "pa"
    else:
        pa_or_pan = "panorama"

    # Run program
    print("\nThank you...connecting..\n")
    becu(pa_ip, username, password, pa_or_pan, filename)