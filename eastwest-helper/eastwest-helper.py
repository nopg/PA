"""
Description: 
    East/West Segmentation Security-Policy Migration Helper

    This script can be used to migrate 

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
        $ python eastwest-helper.py -i <PA(N) mgmt IP> -u <username>
        Password: 

Cautions:
    This script is still under development

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
import concurrent.futures
import json
import time
import xml.dom.minidom
import copy
import argparse

import ipcalc
import xmltodict
import api_lib_pa as pa_api
import zone_settings as settings

###############################################################################################

class mem:
    address_object_entries = None
    address_group_entries = None

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


def address_group_lookup(entry):

    found = False

    if not isinstance(mem.address_group_entries,list):
        mem.address_group_entries = [mem.address_group_entries]

    for addr_group in mem.address_group_entries:
        if entry in addr_group.get("@name"):
            if "member" in addr_group.get("static"):
                found = True
                member_objects = addr_group["static"]["member"]
            else:
                print("Not supported, hi.")
    
    if not found:
        return None
    else:
        ips = []
        for member in member_objects:
            ips += address_lookup(member)
        
        return ips


def address_lookup(entry):
    """
    Used to find the translated addresses objects on the PA/Panorama.
    Runs another api call to grab the object and return it's value (the actual ip address)
    If the NAT rule isn't using an object, we can assume this value is the IP address.
    Returns a LIST
    """

    if not isinstance(mem.address_object_entries, list):
        mem.address_object_entries = [mem.address_object_entries]

    found = False
    for addr_object in mem.address_object_entries:
        if entry in addr_object.get("@name"):
            if "ip-netmask" in addr_object:
                found = True
                ips = addr_object["ip-netmask"]
            else:
                found = True
                ips = ['1.1.1.1']
                #add_review_entry(addr_object, "not-ip-netmask")
    if not found:
        ips = entry + "/32"

    if isinstance(ips,list):
        pass # Good (for now)
    else:
        ips = [ips]

    return ips # Always returns a list (currently)


def output_and_push_changes(modified_rules, filename=None, xpath=None, pa=None):

    # Always create an output file with the modified-rules.
    if not filename:
        filename = "output/modified-pa-rules.xml"
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
        print("\n\t(Include 'foldername/' if modifying)")
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

        if load_config == "y":
            if pa.pa_type == "panorama":
                same_dg = ""
                while same_dg.lower() not in ("y", "n"):
                    same_dg = input(f"Push to existing Device Group ({pa.device_group})? [y/n]: ")

                # Update xpath to new device-group
                if same_dg == "n":
                    new_device_group = get_device_group(pa)
                    xpath = xpath.replace(pa.device_group, new_device_group)

            fname = filename.rsplit('/', 1)[1]  # Get filename, strip any folders before the filename.
            load_url = f"https://{pa.pa_ip}:443/api/?type=op&key={pa.key}&cmd=<load><config><partial><mode>replace</mode><from-xpath>/config/security/rules</from-xpath><to-xpath>{xpath}</to-xpath><from>{fname}</from></partial></config></load>"
            
            response = pa.session[pa.pa_ip].get(load_url, verify=False)
            error_check(response, "Loading Configuration")

            print("\nCandidate configuration successfully loaded...enjoy the new ruleset!")
            print("Review configuration and Commit manually via the GUI.\n")
        else:
            print("\nThank you, finished.\n")
    
    return None


def addr_obj_check(addrobj):

    ips = address_group_lookup(addrobj)
    if not ips:
        ips = address_lookup(addrobj)

    found = False
    for ip in ips:
        iprange = ipcalc.Network(ip)
        for subnet in settings.EXISTING_TRUST_SUBNET:
            if subnet in iprange:
                found = True

        if found:
            return True
        else:
            pass
    
    return False


def should_be_cloned(sec_rule):
    """
    inner function (possibly to be moved outside later)
    The bulk of the logic for rule modification is done here
    Source & destination behave the same, this allows the same code to be used for both.

    :param srcdst: the xml ZONE tag needed for insertion into the new rule
    :param tofrom: the xml Address-Object tag needed for insertion into the new rule
    :param x_zone: from or to, zone name
    :param x_addr: source or destination, address/group object
    """
    def add_tag(tag):
        if "tag" in new_rule:
            if isinstance(new_rule["tag"]["member"], list):
                new_rule["tag"]["member"].append(tag)
            else:
                temp = new_rule["tag"]["member"]
                new_rule["tag"]["member"] = [temp, tag]
        else:
            new_rule["tag"] = {"member":tag}


    def check_and_modify(srcdst, tofrom, x_zone, x_addr):
        """
        inner function (possibly to be moved outside later)
        The bulk of the logic for zone modification is done here
        Source & destination behave the same, this allows the same code to be used for both.

        :param srcdst: the xml ZONE tag needed for insertion into the new rule
        :param tofrom: the xml Address-Object tag needed for insertion into the new rule
        :param x_zone: from or to, zone name
        :param x_addr: source or destination, address/group object
        """
        clone = False
        singleip = False
        for subnet in settings.EXISTING_TRUST_SUBNET:
            if subnet.endswith("/32"):
                singleip = True

        try:
            if not isinstance(x_zone, list):
                x_zone = [x_zone]
                new_rule[tofrom]["member"] = [new_rule[tofrom]["member"]]
            if not isinstance(x_addr, list):
                x_addr = [x_addr]
                new_rule[srcdst]["member"] = [new_rule[srcdst]["member"]]

            for zone in x_zone: 
                if zone == settings.EXISTING_TRUST_ZONE:
                    for addrobj in x_addr:
                        if addrobj == "any":
                            if not singleip:
                                # Clone/Modify this
                                clone = True
                                new_rule[tofrom]["member"].remove(zone) if zone in new_rule[tofrom]["member"] else clone
                                if settings.NEW_EASTWEST_ZONE not in new_rule[tofrom]["member"]:
                                    new_rule[tofrom]["member"].append(settings.NEW_EASTWEST_ZONE)
                            else:
                                # Single-IP, only clone/tag for review the rules relevant to the single IP
                                pass
                        else:
                            # Check address object against EXISTING_TRUST_SUBNET
                            tag = addr_obj_check(addrobj)
                            if tag:
                                clone = True
                                add_tag(settings.REVIEW_TAG)
                                new_rule[tofrom]["member"].remove(zone) if zone in new_rule[tofrom]["member"] else clone
                                if settings.NEW_EASTWEST_ZONE not in new_rule[tofrom]["member"]:
                                    new_rule[tofrom]["member"].append(settings.NEW_EASTWEST_ZONE)
                            else:
                                # Don't need this address object even if we end up cloning the rule.
                                new_rule[srcdst]["member"].remove(addrobj)

                else:
                    # ZONE NOT RELEVANT TO THIS DISCUSSION
                    pass

        except TypeError:
            print("\nError, candidate config detected. Please commit or revert changes before proceeding.\n")
            sys.exit(0)              

        # If I only made it a list to make it easier on myself, change it back.
        if len(new_rule[tofrom]["member"]) == 1:
            new_rule[tofrom]["member"] = new_rule[tofrom]["member"][0]
        if len(new_rule[srcdst]["member"]) == 1:
            new_rule[srcdst]["member"] = new_rule[srcdst]["member"][0]
        
        # Return True/False
        if clone:
            add_tag(settings.CLONED_TAG)
            new_rule["@name"] = new_rule["@name"] + "-cloned"
        return clone
    
    new_rule = copy.deepcopy(sec_rule)

    from_zone = sec_rule["from"]["member"]
    to_zone = sec_rule["to"]["member"]
    src_addr = sec_rule["source"]["member"]
    dst_addr = sec_rule["destination"]["member"]

    # Check and modify to intra-zone based rules
    clone = check_and_modify("source", "from", from_zone,src_addr)

    if clone:
        check_and_modify("destination", "to", to_zone,dst_addr)
    else:
        clone = check_and_modify("destination", "to", to_zone,dst_addr)

    # Return new_rule or False
    if clone:
        return new_rule
    else:
        return False


def eastwest_addnew_zone(security_rules):
    """
    MODIFY SECURITY RULES
    This accepts a dictionary of rules and 

    :param security_rules: existing security rules
    :return: modified_rules, new/modified security rule-set
    """

    def eastwest_add(sec_rule):
        new_ruleset.append(sec_rule)
        return None

    def eastwest_clone(sec_rule):
        new_ruleset.append(sec_rule)
        return None
    
    new_ruleset = []
    if not isinstance(security_rules, list):
        security_rules = [security_rules]
    print("\nModifying...\n")

    for oldrule in security_rules:

        # Check if rule should be cloned
        new_rule = should_be_cloned(oldrule)
        if new_rule:
            eastwest_clone(new_rule)
            eastwest_add(oldrule)
        else:
            eastwest_add(oldrule)

    print("..Done.")
    return new_ruleset


def get_device_group(pa):

    incorrect_input = True
    while incorrect_input:
        device_groups, _ = pa.grab_panorama_objects()
        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
        device_group = input("\nEnter the Device Group Name: ")

        if device_group in device_groups:
            incorrect_input = False
        else:
            print("\n\nERROR: Template or Device Group not found.\n")
    
    return device_group



def eastwesthelper(pa_ip, username, password, pa_type, filename=None):
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
        modified_rules = eastwest_addnew_zone(security_rules["result"]["rules"]["entry"])
        output_and_push_changes(modified_rules, "output/modified-xml-rules.xml")

    elif pa_type == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        pa.device_group = get_device_group(pa)

        # Grab 'start' time
        start = time.perf_counter()
    
        # Set the XPath now that we have the Device Group
        XPATH_ADDR_OBJ = pa_api.XPATH_ADDRESS_OBJ_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_ADDR_GRP = pa_api.XPATH_ADDRESS_GRP_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_PRE = pa_api.XPATH_SECURITY_RULES_PRE_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_POST = pa_api.XPATH_SECURITY_RULES_POST_PAN.replace("DEVICE_GROUP", pa.device_group)

        # Grab Rules
        mem.address_object_entries = pa.grab_address_objects("xml", XPATH_ADDR_OBJ, "output/api/address-objects.xml")
        mem.address_group_entries = pa.grab_address_groups("xml", XPATH_ADDR_GRP, "output/api/address-groups.xml")

        temp = pa.grab_address_objects("xml", pa_api.XPATH_ADDRESS_OBJ_SHARED, "output/api/shared-address-objects.xml")
        if temp:
            if "entry" in temp:
                    mem.address_object_entries.append(temp)
        
        temp = pa.grab_address_groups("xml", pa_api.XPATH_ADDRESS_GRP_SHARED, "output/api/shared-address-groups.xml")
        if temp:
            if "entry" in temp:
                mem.address_group_entries.append(temp)

        pre_security_rules = pa.grab_api_output("xml", XPATH_PRE, "output/api/pre-rules.xml")
        post_security_rules = pa.grab_api_output("xml", XPATH_POST, "output/api/post-rules.xml")

        # Modify the rules, Pre & Post, then append to output list
        if pre_security_rules["result"]["rules"]:
            if "entry" in pre_security_rules["result"]["rules"]:
                modified_rules_pre = eastwest_addnew_zone(pre_security_rules["result"]["rules"]["entry"])
                to_output.append([modified_rules_pre,"output/modified-pre-rules.xml", XPATH_PRE, pa])
        if post_security_rules["result"]["rules"]:
            if "entry" in post_security_rules["result"]["rules"]:
                modified_rules_post = eastwest_addnew_zone(post_security_rules["result"]["rules"]["entry"])
                to_output.append([modified_rules_post,"output/modified-post-rules.xml", XPATH_POST, pa])
            
    elif pa_type == "pa":
        # Grab 'start' time
        start = time.perf_counter()
        # Grab Rules
        XPATH = pa_api.XPATH_SECURITYRULES
        XPATH_ADDR_OBJ = pa_api.XPATH_ADDRESS_OBJ
        XPATH_ADDR_GRP = pa_api.XPATH_ADDRESS_GRP
        mem.address_object_entries = pa.grab_address_objects("xml", XPATH_ADDR_OBJ, "output/api/address-objects.xml")
        mem.address_group_entries = pa.grab_address_groups("xml", XPATH_ADDR_GRP, "output/api/address-groups.xml")
        security_rules = pa.grab_api_output("xml", XPATH, "output/api/pa-rules.xml")
        if security_rules["result"]:
            # Modify the rules, append to be output
            modified_rules = eastwest_addnew_zone(security_rules["result"]["rules"]["entry"])
            to_output.append([modified_rules,"output/modified-pa-rules.xml", XPATH, pa])

    # Begin creating output and/or pushing rules to PA/PAN
    for ruletype in to_output:
        output_and_push_changes(*ruletype)

    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.\n")


# If run from the command line
if __name__ == "__main__":

    # Check arguments, if 'xml' then don't need the rest of the input
    argrequired = '--xml' not in sys.argv and '-x' not in sys.argv
    parser = argparse.ArgumentParser(description="Please use this syntax:")
    parser.add_argument("-x", "--xml", help="Optional XML Filename", type=str)
    parser.add_argument("-u", "--username", help="Username", type=str, required=argrequired)
    parser.add_argument("-i", "--ipaddress", help="IP or FQDN of PA/Panorama", type=str, required=argrequired)
    args = parser.parse_args()

    # IF XML, do not connect to PA/Pan
    if args.xml:
        settings.PUSH_CONFIG_TO_PA = False
        filename = args.xml
        becu("n/a","n/a","n/a","xml",filename)
        sys.exit(0)

    # Gather input
    pa_ip = args.ipaddress
    username = args.username
    password = getpass("Enter Password: ")    

    # Create connection with the Palo Alto as 'obj' to test login success
    try:
        paobj = pa_api.api_lib_pa(pa_ip, username, password, "test")
        del(paobj)
    except:
        print(f"Error connecting to: {pa_ip}\nCheck username/password and network connectivity.")
        sys.exit(0)

    # PA or Panorama?
    pa_type = pa_api.get_pa_type()

    # Run program
    print("\nThank you...connecting..\n")
    eastwesthelper(pa_ip, username, password, pa_type)