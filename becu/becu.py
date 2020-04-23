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
# import concurrent.futures

import xmltodict
import api_lib_pa as pa

# fmt: off
# Global Variables, debug & xpath location for each profile type
# ENTRY = + "/entry[@name='alert-only']"

DEBUG = True

new_intrazone_private = "new-private-zone-name"
existing_privzones = {
    "dmz":"newdmzobj", 
    "trusted":"newtrustobj"
}

class mem: 
    XPATH_DEVICE_GROUPS = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    XPATH_TEMPLATE_NAMES = "/config/devices/entry[@name='localhost.localdomain']/template"

    XPATH_SECURITYRULES = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security"
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

# PAN_XML_NATRULES =      "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/post-rulebase/nat/rules"

# fmt: on


# def iterdict(d, searchfor):
#     """
#     Traverse through the dictionary (d) and find the key: (searchfor).
#     Return the value of that key.
#     """
#     for k, v in d.items():
#         if searchfor in k:
#             return v
#         elif isinstance(v, dict):
#             if not v:
#                 print(f"system error..\nk={k}\nv={v}")
#                 sys.exit(0)
#             return iterdict(v, searchfor)
#         else:
#             pass


def grab_panorama_objects():
    temp_device_groups = mem.fwconn.grab_api_output("xml", mem.XPATH_DEVICE_GROUPS)
    temp_template_names = mem.fwconn.grab_api_output("xml", mem.XPATH_TEMPLATE_NAMES)
    device_groups = []
    template_names = []

    # Need to check for no response, must be an IP not address
    if "entry" in temp_device_groups["response"]["result"]["device-group"]:
        for entry in temp_device_groups["response"]["result"]["device-group"]["entry"]:
            device_groups.append(entry["@name"])
    else:
        print(f"Error, Panorama chosen but no Device Groups found.")
        sys.exit(0)

   # Need to check for no response, must be an IP not address
    if "entry" in temp_template_names["response"]["result"]["template"]:
        if isinstance(temp_template_names["response"]["result"]["template"]["entry"],list):
            for entry in temp_template_names["response"]["result"]["template"]["entry"]:
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
    with open("output.xml", "w") as fout:
        modified_rules = {"response": modified_rules}
        modified_rules = {"result": modified_rules}       
        data = xmltodict.unparse(modified_rules)
        data = data.replace('<?xml version="1.0" encoding="utf-8"?>', "")
        fout.write(data)


def temp_becu_testing(security_rules):
    # print("\nETHAUTOEU\n\n\n\n\n")
    # print(security_rules)
    # sys.exit(0)

    # for ace in security_rules:
    #     thisrule = ace
    #     print(ace["@name"])
    #     print(f"to: {ace['to']}, from: {ace['from']}")
    #     print(f"source: {ace['source']}, dest: {ace['destination']}")
        
    #     thisrule["to"]["member"] = "MYMYMY"
    #     modified_rules.append(thisrule)
    

    # Pseudocode for BECU
    # if fromzone is in list of existing privzones
    #  and source[member] is any
    #   DOWHAT-FROM
    # if tozone is in list of existing privzones
    #  and dest[member] is any
    #   DOWHAT-TO

    modified_rules = []
    for e in security_rules:
        newrule = e
        if e["from"]["member"] in existing_privzones:
            new_addr_obj = existing_privzones[e["from"]["member"]]
            if e["source"]["member"] == "any":
                newrule["source"]["member"] = new_addr_obj
        if e["to"]["member"] in existing_privzones:
            new_addr_obj = existing_privzones[e["to"]["member"]]
            if e["destination"]["member"] == "any":
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

    temp_do_output(modified_rules)
        


# Read PA file, return dict based on xml or json
def grab_xml_or_json_file(filename):

    output = None

    with open(filename, "r") as fin:
        data = fin.read()
        if filename.endswith(".xml"):
            output = xmltodict.parse(data)
            output = output["response"]
        elif filename.endswith(".json"):
            output = json.loads(data)        

    return output


def becu(pa_ip, username, password, pa_or_pan, root_folder=None):
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
    mem.root_folder = root_folder
    mem.filename = root_folder

    # Set the correct XPATH for what we need (interfaces and nat rules)
    if mem.pa_or_pan == "panorama":

        # Needs Template Name & Device Group
        device_groups, template_names = grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        mem.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")

        XPATH_INTERFACES = mem.XPATH_INTERFACES_PAN
        XPATH_INTERFACES = XPATH_INTERFACES.replace("TEMPLATE_NAME", template_name)
        XPATH_INTERFACES = XPATH_INTERFACES.replace("DEVICE_GROUP", mem.device_group)
        REST_NATRULES = mem.REST_NATRULES_PAN
        REST_NATRULES = REST_NATRULES.replace("TEMPLATE_NAME", template_name)
        REST_NATRULES = REST_NATRULES.replace("DEVICE_GROUP", mem.device_group)
    else:
        pass

    start = time.perf_counter()
    
    # Grab Rules
    if DEBUG:
        security_rules = grab_xml_or_json_file(mem.filename)
    else:
        if mem.filename.endswith(".xml"):
            security_rules = mem.fwconn.grab_api_output("xml", mem.XPATH_SECURITYRULES, mem.filename)
        elif mem.filename.endswith(".json"):
            security_rules = mem.fwconn.grab_api_output("rest", mem.REST_SECURITYRULES, mem.filename)

    if not security_rules:
        print("\nError loading file, check filename.")
        sys.exit(0)

    if security_rules["result"]["@count"] == "0":
        print("\nNo security rules found, check a file TBD for more info.\n")
        sys.exit(0)

    #print(security_rules)

    if mem.filename.endswith(".json"):
        temp_becu_testing(security_rules["result"]["entry"])
    else:
        temp_becu_testing(security_rules["result"]["security"]["rules"]["entry"])

    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.")



# If run from the command line
if __name__ == "__main__":

    root_folder = None
    # Guidance on how to use the script
    if len(sys.argv) == 4:
        root_folder = sys.argv[3]
    elif len(sys.argv) != 3:
        print("\nplease provide the following arguments:")
        print(
            "\tpython3 becu.py <PA/Panorama IP> <username> <optional output folder>\n\n"
        )
        sys.exit(0)

    if not root_folder:
        root_folder = "~temp/"

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
        filename = input("Security Rules Filename: ")
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
    becu(pa_ip, username, password, pa_or_pan, root_folder)
