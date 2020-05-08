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
    This script uses 2 global dictionaries found in zone_settings.py (global for easy end-user modification)
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
import api_lib_pa as pa_api
import zone_settings as settings

###############################################################################################

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


def output_and_push_changes(modified_rules, filename=None, xpath=None, pa=None):

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

    if settings.PUSH_CONFIG_TO_PA:
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
            response = pa.import_named_configuration(fin)

        error_check(response, "Importing Configuration")

        print("\nConfig Uploaded.")
        
        load_config = ""
        while load_config.lower() not in ("y", "n"):
            load_config = input("\nLoad config as candidate configuration? [y/n]: ")
        if load_config == "n":
            print("\nThank you, finished.\n")
        else:
            load_url = f"https://{pa.pa_ip}:443/api/?type=op&key={pa.key}&cmd=<load><config><partial><mode>replace</mode><from-xpath>/config/security/rules</from-xpath><to-xpath>{xpath}</to-xpath><from>{filename}</from></partial></config></load>"
            
            response = pa.session[pa.pa_ip].get(load_url, verify=False)

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

        :param srcdst: the xml ZONE tag needed for insertion into the new rule
        :param tofrom: the xml Address-Object tag needed for insertion into the new rule
        :param x_zone: from or to, zone name
        :param x_addr: source or destination, address/group object
        """

        try:
            if isinstance(x_zone, list):
                count = 0
                for zone in x_zone: 
                    if zone in settings.EXISTING_PRIVATE_ZONES:
                        # Zone found, update this zone to the new private intra-zone
                        newrule[tofrom]["member"].remove(zone)
                        if settings.NEW_PRIVATE_INTRAZONE not in newrule[tofrom]["member"]:
                            newrule[tofrom]["member"].append(settings.NEW_PRIVATE_INTRAZONE)

                        # Get the address/group object associated to this zone
                        new_addr_obj = settings.EXISTING_PRIVATE_ZONES[zone]

                        if isinstance(x_addr, list):
                            for x in x_addr:
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

            elif x_zone in settings.EXISTING_PRIVATE_ZONES:
                # Zone found, update this zone to the new private intra-zone
                newrule[tofrom]["member"] = settings.NEW_PRIVATE_INTRAZONE

                # Get the address/group object associated to this zone
                new_addr_obj = settings.EXISTING_PRIVATE_ZONES[x_zone]
                if isinstance(x_addr, list):
                    for x in x_addr:
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
    
        return None # This function modifies the local newrule

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


def becu(pa_ip, username, password, pa_type, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab security rules from pa/pan.
    Modify them for intra-zone migration.
    """
    
    if pa_type != "xml":
        pa = pa_api.api_lib_pa(pa_ip, username, password, pa_type)
    to_output = []

    if pa_type == "xml":
        # Grab 'start' time
        start = time.perf_counter()
        # Grab XML file, modify rules, and create output file.
        security_rules = grab_xml_or_json_file(filename)
        modified_rules = modify_rules(security_rules["result"]["rules"]["entry"])
        output_and_push_changes(modified_rules, "modified-xml-rules.xml")

    elif pa_type == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        device_groups, _ = pa.grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        pa.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")

        # Grab 'start' time
        start = time.perf_counter()
    
        # Set the XPath now that we have the Device Group
        XPATH_PRE = pa_api.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_POST = pa_api.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)

        # Grab Rules
        pre_security_rules = pa.grab_api_output("xml", XPATH_PRE, "api/pre-rules.xml")
        post_security_rules = pa.grab_api_output("xml", XPATH_POST, "api/post-rules.xml")

        # Modify the rules, Pre & Post, then append to output list
        if pre_security_rules["result"]:
            modified_rules_pre = modify_rules(pre_security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules_pre,"modified-pre-rules.xml", XPATH_PRE, pa])
        if post_security_rules["result"]:
            modified_rules_post = modify_rules(post_security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules_post,"modified-post-rules.xml", XPATH_POST, pa])
            
    elif pa_type == "pa":
        # Grab 'start' time
        start = time.perf_counter()
        # Grab Rules
        XPATH = pa_api.XPATH_SECURITYRULES
        security_rules = pa.grab_api_output("xml", XPATH, "api/pa-rules.xml")
        if security_rules["result"]:
            # Modify the rules, append to be output
            modified_rules = modify_rules(security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules,"modified-pa-rules.xml", XPATH, pa])

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
        settings.PUSH_CONFIG_TO_PA = False
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
        paobj = pa_api.api_lib_pa(pa_ip, username, password, None)
    except:
        print(f"Error connecting to: {pa_ip}\nCheck username/password and network connectivity.")
        sys.exit(0)

    # PA or Panorama?
    allowed = list("12")  # Allowed user input
    incorrect_input = True
    while incorrect_input:
        pa_type = input(
            """\nIs this a PA Firewall or Panorama?

        1) PA (Firewall)
        2) Panorama (PAN)

        Enter 1 or 2: """
        )

        for value in pa_type:
            if value not in allowed:
                incorrect_input = True
                break
            else:
                incorrect_input = False

    if pa_type == "1":
        pa_type = "pa"
    else:
        pa_type = "panorama"

    # Run program
    print("\nThank you...connecting..\n")
    becu(pa_ip, username, password, pa_type, filename)