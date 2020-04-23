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

DEBUG = False

new_intrazone_private = "new-private-zone-name"
existing_privzones = {
    "dmz":"newdmzobj", 
    "trusted":"newtrustobj"
}

class mem: 
    XPATH_DEVICE_GROUPS = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    XPATH_TEMPLATE_NAMES = "/config/devices/entry[@name='localhost.localdomain']/template"

    XPATH_SECURITYRULES = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security"
    XPATH_POST_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/post-rulebase/security"
    XPATH_PRE_SECURITY_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/pre-rulebase/security"
    REST_SECURITYRULES = "/restapi/9.0/Policies/SecurityRules?location=vsys&vsys=vsys1&output-format=json"
    
    ip_to_eth_dict = {}
    pa_ip = None
    username = None
    password = None
    fwconn = None
    device_group = None
    root_folder = '.'
    filename = ""
    garp_commands = []
    review_nats = []

# fmt: on


def grab_panorama_objects():
    temp_device_groups = mem.fwconn.grab_api_output("xml", mem.XPATH_DEVICE_GROUPS)
    temp_template_names = mem.fwconn.grab_api_output("xml", mem.XPATH_TEMPLATE_NAMES)
    device_groups = []
    template_names = []

    # Need to check for no response, must be an IP not address
    if "entry" in temp_device_groups["result"]["device-group"]:
        for entry in temp_device_groups["result"]["device-group"]["entry"]:
            device_groups.append(entry["@name"])
    else:
        print(f"Error, Panorama chosen but no Device Groups found.")
        sys.exit(0)

   # Need to check for no response, must be an IP not address
    if "entry" in temp_template_names["result"]["template"]:
        if isinstance(temp_template_names["result"]["template"]["entry"],list):
            for entry in temp_template_names["result"]["template"]["entry"]:
                template_names.append(entry["@name"])
        else:
            template_names.append(temp_template_names["response"]["result"]["template"]["entry"]["@name"])
    else:
        print(f"Error, Panorama chosen but no Template Names found.")
        sys.exit(0)
    
    return device_groups, template_names


def temp_do_output(modified_rules):
    # print(modified_rules)

    # modified_rules = {"response": modified_rules}
    # modified_rules = {"result": modified_rules}

    # print("\n\n")
    # print(modified_rules)
    # print("\n\n")
    # test = xmltodict.unparse(modified_rules)
    # sys.exit(0)
    with open("modified-rules.xml", "w") as fout:
        modified_rules = {"response": modified_rules}
        modified_rules = {"result": modified_rules}       
        data = xmltodict.unparse(modified_rules)
        data = data.replace('<?xml version="1.0" encoding="utf-8"?>', "")
        prettyxml = xml.dom.minidom.parseString(data).toprettyxml()
        fout.write(prettyxml)



def modify_rules(security_rules):
    # Pseudocode for BECU
    # check if from zone is a list
    #  if so, check each zone against existing_privzones
    #   find new address object for this zone
    # 

    modified_rules = []
    for oldrule in security_rules:
        
        newrule = oldrule
        from_zone = oldrule["from"]["member"]
        to_zone = oldrule["to"]["member"]
        src_addr = oldrule["source"]["member"]
        dst_addr = oldrule["destination"]["member"]

        if isinstance(from_zone, list):
            for zone in from_zone:
                if zone in existing_privzones:
                    new_addr_obj = existing_privzones[zone]
                    
                    if isinstance(src_addr, list):
                        for source in src_addr:
                            if source == "any":
                                newrule["source"]["member"] = new_addr_obj
                    elif src_addr == "any":
                        newrule["source"]["member"] = new_addr_obj

        elif from_zone in existing_privzones:
            new_addr_obj = existing_privzones[from_zone]

            if isinstance(src_addr, list):
                for source in src_addr:
                    if source == "any":
                        newrule["source"]["member"] = new_addr_obj

            elif src_addr == "any":
                newrule["source"]["member"] = new_addr_obj


        if isinstance(to_zone, list):
            for zone in to_zone:
                if zone in existing_privzones:
                    new_addr_obj = existing_privzones[zone]
        elif to_zone in existing_privzones:
            new_addr_obj = existing_privzones[to_zone]

            if dst_addr == "any":
                newrule["destination"]["member"] = new_addr_obj

    # Update zones to new private zone (intrazone rules)
        newrule["from"]["member"] = new_intrazone_private
        newrule["to"]["member"] = new_intrazone_private

        modified_rules.append(newrule)

    # print("\n\n\nModified Rules:")
    # for ace in modified_rules:
    #     print(ace["@name"])
    #     print(f"to: {ace['to']}, from: {ace['from']}")
    #     print(f"source: {ace['source']}, dest: {ace['destination']}")

    return modified_rules

     

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


def becu(pa_ip, username, password, pa_or_pan, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab security rules pa/pan.
    Modify them for intrazone migration.
    """
    #thispa = mem(pa_ip, username, password, pa_or_pan, root_folder)
    mem.pa_ip = pa_ip
    mem.username = username
    mem.password = password
    if not DEBUG:
        mem.fwconn = pa.api_lib_pa(mem.pa_ip, mem.username, mem.password)
    mem.pa_or_pan = pa_or_pan
    mem.root_folder = filename
    mem.filename = filename

    # Set the correct XPATH for what we need (interfaces and nat rules)
    if mem.pa_or_pan == "panorama":

        # Needs Template Name & Device Group
        device_groups, _ = grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        mem.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")

        XPATH_POST = mem.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)
        XPATH_PRE = mem.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", mem.device_group)
        
    # Grab 'start' time
    start = time.perf_counter()

    # Grab Rules
    if DEBUG:
        security_rules = grab_xml_or_json_file(mem.filename)
        modified_rules = modify_rules(security_rules["result"]["security"]["rules"]["entry"])
        temp_do_output(modified_rules)
    else:
        if mem.pa_or_pan == "panorama":
            pre_security_rules = mem.fwconn.grab_api_output("xml", XPATH_PRE, "pre-rules.xml")
            post_security_rules = mem.fwconn.grab_api_output("xml", XPATH_POST, "post-rules.xml")

            if pre_security_rules["result"]:
                modified_rules_pre = modify_rules(pre_security_rules["result"]["security"]["rules"]["entry"])
                temp_do_output(modified_rules_pre)
            if post_security_rules["result"]:
                modified_rules_post = modify_rules(post_security_rules["result"]["security"]["rules"]["entry"])
                temp_do_output(modified_rules_post)
            
        else:
            security_rules = mem.fwconn.grab_api_output("xml", mem.XPATH_SECURITYRULES, mem.filename)
            if security_rules:
                modified_rules = modify_rules(security_rules["result"]["security"]["rules"]["entry"])
                temp_do_output(modified_rules)

    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.")



# If run from the command line
if __name__ == "__main__":

    root_folder = None
    # Guidance on how to use the script
    if len(sys.argv) == 4:
        filename = sys.argv[3]
    elif len(sys.argv) != 3:
        print("\nplease provide the following arguments:")
        print(
            "\tpython3 becu.py <PA/Panorama IP> <username> <optional name of output file>\n\n"
        )
        sys.exit(0)
    else:
        filename = None


    # Gather input
    pa_ip = sys.argv[1]
    username = sys.argv[2]
    password = getpass("Enter Password: ")

    # Create connection with the Palo Alto as 'obj' to test login success
    try:
        if not DEBUG:
            paobj = pa.api_lib_pa(pa_ip, username, password)
    except:
        print(f"Error connecting to: {pa_ip}\nCheck username/password and network connectivity.")
        sys.exit(0)

    if DEBUG:
        if not filename:
            filename = input("DEBUG ON.\nSecurity Rules Filename: ")
        becu(pa_ip,username,password,"xml",filename)
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
    becu(pa_ip, username, password, pa_or_pan, filename)
