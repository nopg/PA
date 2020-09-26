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
from xml.etree.ElementTree import fromstring, ElementTree
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
    singleip = False


def addr_obj_check(entry):
    def address_lookup(address_object, found):
        for obj in mem.address_object_entries:
            if address_object in obj.name:
                if obj.type == "ip-netmask":
                    found = True
                    return [obj.value]
                else:
                    print("non ip-netmask, add support plz")
                    return ["1.1.1.1"]
        if not found:   # IP as Name
            return [address_object]
        
        return None


    found = False
    ips = []
    # Check Objects
    for grp in mem.address_group_entries:
        if entry == grp.name:
            if grp.static_value:
                found = True
                address_objects = grp.static_value
                for obj in address_objects:
                    ips += address_lookup(obj, found)
            else:
                print("Not supported, hi.")
    if not found:
        ips += address_lookup(entry, found)
    
    for ip in ips:
        iprange = ipcalc.Network(ip)
        for subnet in settings.EXISTING_TRUST_SUBNET:
            if subnet in iprange:
                return True 

    return False


def should_be_cloned(old_rule, srcdst, new_rule=None):

    def add_tag(tag):
        if new_rule.tag:
            if tag not in new_rule.tag:
                new_rule.tag.append(tag)

    # Set variables
    clone = False
    removed_addrs = []
    if srcdst == "src":
        x_zone_attr = 'fromzone'
        x_addr_attr = 'source'
    else:   # == "dst"
        x_zone_attr = 'tozone'
        x_addr_attr = 'destination'

    # x_ = src or dest
    # Begin search
    for zone in getattr(old_rule, x_zone_attr): 
        if zone == settings.EXISTING_TRUST_ZONE:
            old_zones = getattr(old_rule, x_addr_attr)
            if new_rule:
                new_zones = getattr(new_rule, x_zone_attr)

            if "any" in old_zones:
                # If searching for only Single-IP, assume the 'any' rules are already cloned.
                if mem.singleip: # SingleIP: Idea being you are being very specific here, 
                    # and probably don't need to clone the 'any' rules again.
                    pass
                else:
                    # Clone/Modify this
                    clone = True
                    if not new_rule:
                        new_rule = copy.deepcopy(old_rule)
                        new_zones = getattr(new_rule, x_zone_attr)
                        
                    # Remove 'any', add new Zone
                    if "any" in new_zones:
                        new_zones.remove("any")
                    new_zones.append(settings.NEW_EASTWEST_ZONE)

            else:
                for addrobj in old_zones:
                    # Is the address object/IP within the EXISTING_TRUST_SUBNET? If so, tag.
                    tag = addr_obj_check(addrobj)
                    if tag:
                        clone = True
                        if not new_rule:
                            new_rule = copy.deepcopy(old_rule)
                            new_zones = getattr(new_rule, x_zone_attr)

                        #add_tag(settings.REVIEW_TAG)

                        if zone in new_zones:
                            new_zones.remove(zone)
                        if settings.NEW_EASTWEST_ZONE not in new_zones:
                            new_zones.append(settings.NEW_EASTWEST_ZONE)
                        
                    else:
                        # Don't need this address object even if we end up cloning the rule.
                        removed_addrs.append(addrobj)
                        if new_rule:
                            if addrobj in getattr(new_rule, x_addr_attr):
                                getattr(new_rule, x_addr_attr).remove(addrobj)
        else:
            # ZONE NOT RELEVANT TO THIS DISCUSSION
            pass

    # Return True/False
    if clone:
        # Cleanup / Prep for clone
        add_tag(settings.CLONED_TAG)
        for addr in removed_addrs:
            if addr in getattr(new_rule, x_addr_attr):
                getattr(new_rule, x_addr_attr).remove(addrobj)
        new_rule.name += "-cloned"
        return new_rule
    else:
        return False


def eastwest_addnew_zone(security_rules, panfw, rulebase):
    """
    MODIFY SECURITY RULES
    This accepts a dictionary of rules and 

    :param security_rules: existing security rules
    :return: modified_rules, new/modified security rule-set
    """

    print("\nModifying...\n")

    for oldrule in security_rules:
        # CHECK SRC, then DST
        new_rule = should_be_cloned(oldrule, "src")
        if new_rule:
            temp = should_be_cloned(oldrule, "dst", new_rule)
            if temp:
                new_rule = temp
        else:
            new_rule = should_be_cloned(oldrule, "dst")

        if new_rule:
            rulebase.add(new_rule)
            new_rule.move('before', ref=oldrule.name, update=False)

              
    print("..Done.")

    rulebase.children[0].apply_similar()

    return None


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

    for subnet in settings.EXISTING_TRUST_SUBNET:
        if subnet.endswith("/32"):
            mem.singleip = True

    if pa_type == "panorama":

        # Grab 'start' time
        start = time.perf_counter()

        panfw = panorama.Panorama(pa_ip, username, password)
        # Grab the Device Groups and Template Names, we don't need Template names.
        pa = pa_api.api_lib_pa(pa_ip, username, password, pa_type)
        device_group = get_device_group(pa)
        pre_rulebase = policies.PreRulebase()
        post_rulebase = policies.PostRulebase()
        dg = panorama.DeviceGroup(device_group)
        dg.add(pre_rulebase)
        dg.add(post_rulebase)
        panfw.add(dg)

        # Grab Objects and Rules
        mem.address_object_entries = objects.AddressObject.refreshall(dg, add=False)#,add=False)
        mem.address_group_entries = objects.AddressGroup.refreshall(dg, add=False)#,add=False)

        #Grabbing the Shared address objects and groups..
        shared = panorama.DeviceGroup('shared')
        panfw.add(shared)

        shared_objects = objects.AddressObject.refreshall(shared, add=False)
        mem.address_object_entries += shared_objects
        shared_groups = objects.AddressGroup.refreshall(shared, add=False)
        mem.address_group_entries += shared_groups

        # Add parent DG (like Shared), if used. Ask Chris Evans or me for details.
        if settings.OBJ_PARENT_DEVICE_GROUP:
            parent_dg = panorama.DeviceGroup(settings.OBJ_PARENT_DEVICE_GROUP)
            panfw.add(parent_dg)

            parent_objects = objects.AddressObject.refreshall(parent_dg, add=False)
            mem.address_object_entries += parent_objects
            parent_groups = objects.AddressGroup.refreshall(parent_dg, add=False)
            mem.address_group_entries += parent_groups

        # GRAB PRE/POST RULES
        pre_security_rules = policies.SecurityRule.refreshall(pre_rulebase)#, add=False)
        post_security_rules = policies.SecurityRule.refreshall(post_rulebase)#, add=False)

        # Modify the rules, Pre & Post
        if pre_security_rules:
            eastwest_addnew_zone(pre_security_rules, panfw, pre_rulebase)
        if post_security_rules:
            eastwest_addnew_zone(post_security_rules, panfw, post_rulebase)
            
    elif pa_type == "pa":
        # Grab 'start' time
        start = time.perf_counter()

        panfw = firewall.Firewall(pa_ip, username, password)

        # Grab Rules
        mem.address_object_entries = objects.AddressObject.refreshall(panfw,add=False)
        mem.address_group_entries = objects.AddressGroup.refreshall(panfw,add=False)

        rulebase = policies.Rulebase()
        panfw.add(rulebase)
        security_rules = policies.SecurityRule.refreshall(rulebase)

        # Modify the rules
        if security_rules:
            modified_rules = eastwest_addnew_zone(security_rules, panfw, rulebase)

    # Finished
    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.\n")


# If run from the command line
if __name__ == "__main__":

    # Check arguments, if 'xml' then don't need the rest of the input
    #argrequired = '--xml' not in sys.argv and '-x' not in sys.argv
    parser = argparse.ArgumentParser(description="Please use this syntax:")
    #parser.add_argument("-x", "--xml", help="Optional XML Filename", type=str)
    parser.add_argument("-u", "--username", help="Username", type=str)#, required=argrequired)
    parser.add_argument("-i", "--ipaddress", help="IP or FQDN of PA/Panorama", type=str)#, required=argrequired)
    args = parser.parse_args()

    # IF XML, do not connect to PA/Pan
    # if args.xml:
    #     print("NO LONGER IMPLEMENTED")
    #     sys.exit(0)

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