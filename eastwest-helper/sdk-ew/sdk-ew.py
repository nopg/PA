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

from panos import base
from panos import firewall
from panos import panorama
from panos import policies
from panos import objects
from panos import network
from panos import device

###############################################################################################

class mem:
    address_object_entries = None
    address_group_entries = None
    rulebase = None
    prerulebase = None
    postrulebase = None

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


def address_group_lookup(entry):

    found = False

    for addr_group in mem.address_group_entries:
        if entry == addr_group.name:
            if addr_group.static_value:
                found = True
                member_objects = addr_group.static_value
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

    found = False
    for addr_object in mem.address_object_entries:
        if entry == addr_object.name:
            if addr_object.type == "ip-netmask":
                found = True
                ips = addr_object.value
            else:
                found = True
                ips = ['1.1.1.1']
                #add_review_entry(addr_object, "not-ip-netmask")
    if not found:
        ips = entry

    if isinstance(ips,list):
        pass # Good (for now)
    else:
        ips = [ips]

    return ips # Always returns a list (currently)


def addr_obj_check(addrobj):

    ips = address_group_lookup(addrobj)
    if not ips:
        ips = address_lookup(addrobj)

    for ip in ips:
        print(ip)

    found = False
    for ip in ips:
        try:
            tip = address_group_lookup(ip) # One level of nested address groups, just in case..
            if not tip:
                tip = ip
            iprange = ipcalc.Network(tip)

            for subnet in settings.EXISTING_TRUST_SUBNET:
                if subnet in iprange:
                    found = True

            if found:
                return True
            else:
                pass

        except:
            print("Not supported, call me.")
    
    return False


def eastwest_addnew_zone(security_rules, panfw):
    """
    MODIFY SECURITY RULES
    This accepts a dictionary of rules and 

    :param security_rules: existing security rules
    :return: modified_rules, new/modified security rule-set
    """

    def should_be_cloned(sec_rule, new_rule, srcdst):

        if srcdst == "src":
            x_zone = sec_rule.fromzone
            x_addr = sec_rule.source
            new_x_zone = new_rule.fromzone
            new_x_addr = new_rule.source
        else: # == "dst"
            x_zone = sec_rule.tozone
            x_addr = sec_rule.destination
            new_x_zone = new_rule.tozone
            new_x_addr = new_rule.destination

        clone = False
        singleip = False
        for subnet in settings.EXISTING_TRUST_SUBNET:
            if subnet.endswith("/32"):
                singleip = True

        # x = src or dest
        for zone in x_zone: 
            if zone == settings.EXISTING_TRUST_ZONE:
                for addrobj in x_addr:
                    if addrobj == "any":
                        if not singleip:
                            # Clone/Modify this
                            clone = True
                            if zone in new_x_zone:
                                new_x_zone.remove(zone)
                            if settings.NEW_EASTWEST_ZONE not in new_x_zone:
                                new_x_zone.append(settings.NEW_EASTWEST_ZONE)
                        else:
                            # If searching for only Single-IP, only clone/tag for review 
                            # the rules relevant to the single IP, ignore 'any' rules
                            # Idea being you are being very specific here, and probably don't need to close the
                            # 'any' rules again.
                            pass
                    else:
                        #Check address object against EXISTING_TRUST_SUBNET
                        tag = addr_obj_check(addrobj)
                        if tag:
                            clone = True
                            #add_tag(settings.REVIEW_TAG)
                            if zone in new_x_zone:
                                new_x_zone.remove(zone)
                            if settings.NEW_EASTWEST_ZONE not in new_x_zone:
                                new_x_zone.append(settings.NEW_EASTWEST_ZONE)
                        else:
                            # Don't need this address object even if we end up cloning the rule.
                            new_x_addr.remove(addrobj)
            else:
                # ZONE NOT RELEVANT TO THIS DISCUSSION
                pass

        # Return True/False
        if clone:
            #add_tag(settings.CLONED_TAG)
            new_rule.name += "-cloned"
            return new_rule
        return False


    print("\nModifying...\n")

    for oldrule in security_rules:

        newrule = copy.deepcopy(oldrule)
        new_rule = should_be_cloned(oldrule, newrule, "src")
        if new_rule:
            should_be_cloned(oldrule, newrule, "dst")
        else:
            new_rule = should_be_cloned(oldrule, newrule, "dst")
           
        #if to be cloned
        if new_rule:
            if isinstance(panfw, firewall.Firewall):
                mem.rulebase.add(new_rule)
                new_rule.move('before', ref=oldrule.name, update=False)
            else:
                mem.postrulebase.add(new_rule)
                new_rule.move('before', ref=oldrule.name, update=False)


    print("..Done.")

    if isinstance(panfw, firewall.Firewall):
        #panfw.findall(class_type=policies.Rulebase)[0].children[0].apply_similar()
        mem.rulebase.children[0].apply_similar()
    else:
        #panfw.findall(class_type=policies.PreRulebase)[0].children[0].apply_similar()
        mem.postrulebase.children[0].apply_similar()

    sys.exit(0)
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

        # Grab 'start' time
        start = time.perf_counter()

        panfw = panorama.Panorama(pa_ip, username, password)
        # Grab the Device Groups and Template Names, we don't need Template names.
        device_group = get_device_group(pa)
        pre_rulebase = policies.PreRulebase()
        post_rulebase = policies.PostRulebase()
        mem.prerulebase = pre_rulebase
        mem.postrulebase = post_rulebase
        dg = panorama.DeviceGroup(device_group)
        dg.add(pre_rulebase)
        dg.add(post_rulebase)
        panfw.add(dg)

        # Grab Objects and Rules
        mem.address_object_entries = objects.AddressObject.refreshall(panfw)#,add=False)
        mem.address_group_entries = objects.AddressGroup.refreshall(panfw)#,add=False)

        # shared_objs = pa.grab_address_objects("xml", pa_api.XPATH_ADDRESS_OBJ_SHARED, "output/api/shared-address-objects.xml")
        # if shared_objs:
        #     if not isinstance(shared_objs, list):
        #         shared_objs = [shared_objs]
        #     mem.address_object_entries += shared_objs
        
        # print("Grabbing the Shared address objects and groups..")
        # shared_grps = pa.grab_address_groups("xml", pa_api.XPATH_ADDRESS_GRP_SHARED, "output/api/shared-address-groups.xml")
        # if shared_grps:
        #     if not isinstance(shared_grps, list):
        #         shared_grps = [shared_grps]
        #     mem.address_group_entries += shared_grps

        # if settings.OBJ_PARENT_DEVICE_GROUP:
        #     XPATH_ADDR = pa_api.XPATH_ADDRESS_OBJ_PAN.replace("DEVICE_GROUP", settings.OBJ_PARENT_DEVICE_GROUP)
        #     XPATH_GRP = pa_api.XPATH_ADDRESS_GRP_PAN.replace("DEVICE_GROUP", settings.OBJ_PARENT_DEVICE_GROUP)

        #     print(f"Grabbing the {settings.OBJ_PARENT_DEVICE_GROUP} address objects and groups..")
        #     shared_objs = pa.grab_address_objects("xml", XPATH_ADDR, f"output/api/{settings.OBJ_PARENT_DEVICE_GROUP}-address-objects.xml")
        #     if shared_objs:
        #         if not isinstance(shared_objs, list):
        #             shared_objs = [shared_objs]
        #         mem.address_object_entries += shared_objs
            
        #     shared_grps = pa.grab_address_groups("xml", XPATH_GRP, f"output/api/{settings.OBJ_PARENT_DEVICE_GROUP}-address-groups.xml")
        #     if shared_grps:
        #         if not isinstance(shared_grps, list):
        #             shared_grps = [shared_grps]
        #         mem.address_group_entries += shared_grps

        pre_security_rules = policies.SecurityRule.refreshall(pre_rulebase, add=False)
        post_security_rules = policies.SecurityRule.refreshall(post_rulebase)#, add=False)


        # Modify the rules, Pre & Post, then append to output list
        if pre_security_rules:
            modified_rules_pre = eastwest_addnew_zone(pre_security_rules, panfw)
            #to_output.append([modified_rules_pre,"output/modified-pre-rules.xml", XPATH_PRE, pa])
        if post_security_rules:
            modified_rules_post = eastwest_addnew_zone(post_security_rules, panfw)
            #to_output.append([modified_rules_post,"output/modified-post-rules.xml", XPATH_POST, pa])
            
    elif pa_type == "pa":
        # Grab 'start' time
        start = time.perf_counter()

        panfw = firewall.Firewall(pa_ip, username, password)

        # Grab Rules
        # XPATH = pa_api.XPATH_SECURITYRULES
        # XPATH_ADDR_OBJ = pa_api.XPATH_ADDRESS_OBJ
        # XPATH_ADDR_GRP = pa_api.XPATH_ADDRESS_GRP
        #mem.address_object_entries = pa.grab_address_objects("xml", XPATH_ADDR_OBJ, "output/api/address-objects.xml")
        #mem.address_group_entries = pa.grab_address_groups("xml", XPATH_ADDR_GRP, "output/api/address-groups.xml")
        #security_rules = pa.grab_api_output("xml", XPATH, "output/api/pa-rules.xml")

        mem.address_object_entries = objects.AddressObject.refreshall(panfw,add=False)
        mem.address_group_entries = objects.AddressGroup.refreshall(panfw,add=False)

        rulebase = policies.Rulebase()
        mem.rulebase = rulebase
        panfw.add(rulebase)
        security_rules = policies.SecurityRule.refreshall(rulebase)

        if security_rules:
            # Modify the rules, append to be output
            modified_rules = eastwest_addnew_zone(security_rules, panfw)
            to_output.append([modified_rules,"output/modified-pa-rules.xml", pa_api.XPATH_SECURITYRULES, pa])

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
        panfw = firewall.Firewall(pa_ip, username, password)
        del(panfw)
    except Exception as e:
        print(f"Error connecting to: {pa_ip}\nCheck username/password and network connectivity.")
        print()
        print(e)
        sys.exit(0)

    # PA or Panorama?
    pa_type = pa_api.get_pa_type()

    # Run program
    print("\nThank you...connecting..\n")
    eastwesthelper(pa_ip, username, password, pa_type)