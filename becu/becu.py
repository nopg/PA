"""
Description: 
    PA Gratuitous ARP Script
    Connect to PA or Panorama and convert existing ruleset from standard/on-prem 'interzone'
    to a cloud-based VM 'intrazone' style deployment. This PA deployment has only 2 zones,
    public and private. All East/West security-rules are intrazone using address groups, 
    rather than having a different zone/interface like traditional physical PA's.

Requires:
    requests
    xmltodict
        to install try: pip3 install xmltodict requests 

Author:
    Ryan Gillespie rgillespie@compunet.biz
    Docstring stolen from Devin Callaway

Tested:
    Tested on macos 10.13.6
    Python: 3.6.2
    PA VM100, Panorama

Example usage:
        $ python3 becu.py <PA(N) mgmt IP> <username>
        Password: 

Cautions:
    - Not fully developed yet
    

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
# import concurrent.futures

import xmltodict
import api_lib_pa as pa

# fmt: off
# Global Variables, debug & xpath location for each profile type
# ENTRY = + "/entry[@name='alert-only']"

PUSH_TO_PA_OR_PAN = True

NEW_INTRAZONE_PRIVATE = "NEW-PRIVATE-ZONE-NAME"
EXISTING_PRIVZONES = {
    "dmz":"NEW-DMZ-OBJ", 
    "trusted":"NEW-TRUST-OBJ",
    "untrusted":"NEW-UNTRUST-OBJ",
    "ViptelaTransit":"NEW-VIPTELA-OBJ"
}

class mem: 
    XPATH_SECURITYRULES = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    XPATH_POST_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/post-rulebase/security/rules"
    XPATH_PRE_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/pre-rulebase/security/rules"
    REST_SECURITYRULES = "/restapi/9.0/Policies/SecurityRules?location=vsys&vsys=vsys1&output-format=json"
    
    ip_to_eth_dict = {}
    pa_ip = None
    username = None
    password = None
    fwconn = None
    device_group = None
    filename = ""
    garp_commands = []
    review_nats = []

# fmt: on

# Read PA file, return dict based on xml or json
def grab_xml_or_json_file(filename):

    output = None

    try:
        with open(filename, "r") as fin:
            data = fin.read()
            if filename.endswith(".xml"):
                output = xmltodict.parse(data)
                output = output["response"]
            elif filename.endswith(".json"):
                output = json.loads(data)        
    except FileNotFoundError:
        print("\nFile not found, check filename.\n")
        sys.exit(0)

    return output


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


    # Import xml via Palo Alto API, TO BE UPDATED
    if PUSH_TO_PA_OR_PAN:
        entry_element = data.replace("<rules>", "")
        entry_element = entry_element.replace("</rules>", "")

        for rule in modified_rules:
            entry = rule["@name"]
            xpath1 = xpath + f"/entry[@name='{entry}']"
            rule = {"entry": rule}
            rule = {"root": rule}
            element = xmltodict.unparse(rule)
            element = element.replace('<?xml version="1.0" encoding="utf-8"?>', "")
            element = element.replace("<root>", "")
            element = element.replace("</root>", "")

            print(f"Updating rule: {entry}")
            response = mem.fwconn.get_xml_request_pa(
                call_type="config", action="edit", xpath=xpath1, element=element,
            )


def modify_rules(security_rules):

    modified_rules = []
    for oldrule in security_rules:
        
        newrule = oldrule
        from_zone = oldrule["from"]["member"]
        to_zone = oldrule["to"]["member"]
        src_addr = oldrule["source"]["member"]
        dst_addr = oldrule["destination"]["member"]

        if isinstance(from_zone, list):
            count = 0
            for zone in from_zone:
                if isinstance(zone, dict):
                    print("\nError, candidate config detected. Please commit or revert changes before proceeding.\n")
                    sys.exit(0)                 
                if zone in EXISTING_PRIVZONES:
                    new_addr_obj = EXISTING_PRIVZONES[zone]
                    
                    if isinstance(src_addr, list):
                        for source in src_addr:
                            if source == "any":
                                newrule["source"]["member"].remove("any")
                                newrule["source"]["member"].append(new_addr_obj)
                    else:
                        if src_addr == "any":
                            if count >= 1:  # Corner case, 2 zones but only 1 existing address object, convert to list
                                newrule["source"]["member"] = [new_addr_obj]
                            else:
                                count += 1
                                newrule["source"]["member"] = new_addr_obj

        elif isinstance(from_zone, dict):
            print("\nError, candidate config detected. Please commit or revert changes before proceeding.\n")
            sys.exit(0)
        
        elif from_zone in EXISTING_PRIVZONES:
            new_addr_obj = EXISTING_PRIVZONES[from_zone]

            if isinstance(src_addr, list):
                for source in src_addr:
                    if source == "any":
                        newrule["source"]["member"].remove("any")
                        newrule["source"]["member"].append(new_addr_obj)

            elif src_addr == "any":
                newrule["source"]["member"] = new_addr_obj
        else:
            print(f"zone not in list: {from_zone}")

        if isinstance(to_zone, list):
            for zone in to_zone:
                if zone in EXISTING_PRIVZONES:
                    new_addr_obj = EXISTING_PRIVZONES[zone]

                    if isinstance(dst_addr, list):
                        for dest in dst_addr:
                            if dest == "any":
                                newrule["destination"]["member"].pop("any")
                                newrule["destination"]["member"].append(new_addr_obj)
                    elif dst_addr == "any":
                        newrule["destination"]["member"] = new_addr_obj
        elif to_zone in EXISTING_PRIVZONES:
            new_addr_obj = EXISTING_PRIVZONES[to_zone]

            if dst_addr == "any":
                newrule["destination"]["member"] = new_addr_obj

    # Update zones to new private zone (intrazone rules)
        newrule["from"]["member"] = NEW_INTRAZONE_PRIVATE
        newrule["to"]["member"] = NEW_INTRAZONE_PRIVATE

        modified_rules.append(newrule)

    return modified_rules


def becu(pa_ip, username, password, pa_or_pan, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab security rules from pa/pan.
    Modify them for intrazone migration.
    """
    #thispa = mem(pa_ip, username, password, pa_or_pan, filename)
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
        output_and_push_changes(modified_rules)

    elif mem.pa_or_pan == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        device_groups, _ = mem.fwconn.grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        mem.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")

        # Set the XPath now that we have the Device Group
        mem.XPATH_PRE_SECURITY_RULES_PAN = mem.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)
        mem.XPATH_POST_SECURITY_RULES_PAN = mem.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)

        # Grab 'start' time
        start = time.perf_counter()
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
    for type in to_output:
        output_and_push_changes(*type)

    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.")


# If run from the command line
if __name__ == "__main__":

    # Guidance on how to use the script
    if len(sys.argv) == 2:
        PUSH_TO_PA_OR_PAN = False
        filename = sys.argv[1]
        becu("n/a","n/a","n/a","xml",filename)
        sys.exit(0)
    elif len(sys.argv) != 3:
        print("\nplease provide the following arguments:")
        print(
            "\tpython3 becu.py <PA/Panorama IP> <username> <optional name of output file>\n\n"
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