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
    rulebase = None
    prerulebase = None
    postrulebase = None


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

        except Exception as e:
            print("Not supported, call me.")
            print(e)
    
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

        print(f"x_zone = {x_zone}")
        print(f"x_addr = {x_addr}")
        print(f"new_x_zone = {new_x_zone}")
        print(f"new_x_addr = {new_x_addr}")
        new_x_zone = ["hi"]
        print(f"x_zone = {x_zone}")
        print(f"x_addr = {x_addr}")
        print(f"new_x_zone = {new_x_zone}")
        print(f"new_x_addr = {new_x_addr}")
        #sys.exit(0)
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
                                print(f"newzone-remove={zone}")
                            if settings.NEW_EASTWEST_ZONE not in new_x_zone:
                                new_x_zone.append(settings.NEW_EASTWEST_ZONE)
                                print(f"newzone-add={settings.NEW_EASTWEST_ZONE}")
                                print(f"oldzone={zone}")
                                print(f"oldzone-still={x_zone}")
                                print(f"newzone={new_x_zone}")
                        else:
                            # If searching for only Single-IP, only clone/tag for review 
                            # the rules relevant to the single IP, ignore 'any' rules
                            # Idea being you are being very specific here, and probably don't need to close the
                            # 'any' rules again.
                            pass
                    else:
                        #Check address object against EXISTING_TRUST_SUBNET
                        tag = addr_obj_check(addrobj)
                        print(repr(tag))
                        if tag:
                            clone = True
                            #add_tag(settings.REVIEW_TAG)
                            print("changing...")
                            print(f"x_zone = {x_zone}")
                            print(f"x_addr = {x_addr}")
                            print(f"new_x_zone = {new_x_zone}")
                            print(f"new_x_addr = {new_x_addr}")
                            if zone in new_x_zone:
                                new_x_zone.remove(zone)
                            if settings.NEW_EASTWEST_ZONE not in new_x_zone:
                                new_x_zone.append(settings.NEW_EASTWEST_ZONE)
                            
                            print(f"x_zone = {x_zone}")
                            print(f"x_addr = {x_addr}")
                            print(f"new_x_zone = {new_x_zone}")
                            print(f"new_x_addr = {new_x_addr}")
                        else:
                            # Don't need this address object even if we end up cloning the rule.
                            if addrobj in new_x_addr:
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

    def etree_to_dict(t):
        d = {t.tag : map(etree_to_dict, t.iterchildren())}
        d.update(('@' + k, v) for k, v in t.attrib.iteritems())
        d['text'] = t.text
        return d
    def elementtree_to_dict(element):
        node = dict()

        text = getattr(element, 'text', None)
        if text is not None:
            node['text'] = text

        node.update(element.items()) # element's attributes

        child_nodes = {}
        for child in element: # element's children
            child_nodes.setdefault(child, []).append( elementtree_to_dict(child) )

        # convert all single-element lists into non-lists
        for key, value in child_nodes.items():
            if len(value) == 1:
                child_nodes[key] = value[0]

        node.update(child_nodes.items())

        return node
    def elem2dict(node):
        """
        Convert an lxml.etree node tree into a dict.
        """
        result = {}

        for element in node.iterchildren():
            # Remove namespace prefix
            key = element.tag.split('}')[1] if '}' in element.tag else element.tag

            # Process element as tree element if the inner XML contains non-whitespace content
            if element.text and element.text.strip():
                value = element.text
            else:
                value = elem2dict(element)
            if key in result:

                
                if type(result[key]) is list:
                    result[key].append(value)
                else:
                    tempvalue = result[key].copy()
                    result[key] = [tempvalue, value]
            else:
                result[key] = value
        return result

    for oldrule in security_rules:

        # test = oldrule.element()
        # #print(repr(test))
        # #str_rule = test.decode('utf-8')
        # print(type(test))
        # #test2 = xmltodict.parse(test)
        # #test3 = test2["entry"]
        # #print(**test2)
        # #sys.exit(0)
        # #test5 = elem2dict(test)
        # #print(test5)
        # #test3 = etree_to_dict(test.getroot())
        # #print(repr(test3))
        # #test2 = json.loads(str_rule)

        # newrule = policies.SecurityRule(oldrule)
        # #newrule = policies.SecurityRule(**test5)
        # print(newrule)
        # print(type(newrule))
        # print(newrule.name)

        # sys.exit(0)

        bs = ['name','fromzone','tozone','source','source_user','hip_profiles','destination','application','service','category','action','log_setting','log_start','log_end','description','type','tag','negate_source','negate_destination','disabled','schedule','icmp_unreachable','disable_server_response_inspection','group','virus','spyware','vulnerability','url_filtering','file_blocking','wildfire_analysis','data_filtering','negate_target','target']#,'uuid']

        ruledict = {}
        for f in bs:
            ruledict[f] = getattr(oldrule, f)

        #newrule1 = copy.deepcopy(oldrule.__dict__)
        # newrule1.pop('parent')
        # newrule1.pop('children')
        # newrule1.pop('_xpaths')
        # newrule1.pop('_stubs')
        # newrule1.pop('_params')
        #newrule = policies.SecurityRule(**newrule1)
        #newrule = policies.SecurityRule(oldrule)
        newrule = policies.SecurityRule(**ruledict)
        # newrule = newrule.name
        # print(oldrule)
        # print(newrule)
        # print(type(oldrule))
        # print(type(newrule))
        # print(newrule.name == oldrule.name)
        # print(newrule.fromzone == oldrule.fromzone)
        # print(oldrule == newrule)
        # print(f"oldrule-name-{oldrule.name}")
        # print(f"newrule-name-{newrule.name}")
        # print(f"oldrule-source-{oldrule.source}")
        # print(f"newrule-source-{newrule.source}")
        # newrule.source = ["hi"]
        # print(f"oldrule-source-{oldrule.source}")
        # print(f"newrule-source-{newrule.source}")
        #sys.exit(0)
        # print(dir(newrule))
        # print()
        # print(newrule._params)
        # print()
        # print(newrule.__dict__)
        # # print(newrule.__dict__)
        # sys.exit(0)

        new_rule = should_be_cloned(oldrule, newrule, "src")
        if new_rule:
            print("\nback out")
            print(f"x_zone = {oldrule.fromzone}")
            print(f"x_addr = {oldrule.source}")
            print(f"new_x_zone = {new_rule.fromzone}")
            print(f"new_x_addr = {new_rule.source}")
            should_be_cloned(oldrule, newrule, "dst")
            print("\nback out again")
            print(f"x_zone = {oldrule.fromzone}")
            print(f"x_addr = {oldrule.source}")
            print(f"new_x_zone = {new_rule.fromzone}")
            print(f"new_x_addr = {new_rule.source}")
            sys.exit(0)
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

    if pa_type == "panorama":

        # Grab 'start' time
        start = time.perf_counter()

        panfw = panorama.Panorama(pa_ip, username, password)
        # Grab the Device Groups and Template Names, we don't need Template names.
        pa = pa_api.api_lib_pa(pa_ip, username, password, pa_type)
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
            eastwest_addnew_zone(pre_security_rules, panfw)
        if post_security_rules:
            eastwest_addnew_zone(post_security_rules, panfw)
            
    elif pa_type == "pa":
        # Grab 'start' time
        start = time.perf_counter()

        panfw = firewall.Firewall(pa_ip, username, password)

        # Grab Rules
        mem.address_object_entries = objects.AddressObject.refreshall(panfw,add=False)
        mem.address_group_entries = objects.AddressGroup.refreshall(panfw,add=False)

        rulebase = policies.Rulebase()
        mem.rulebase = rulebase
        panfw.add(rulebase)
        security_rules = policies.SecurityRule.refreshall(rulebase)

        # Modify the rules
        if security_rules:
            modified_rules = eastwest_addnew_zone(security_rules, panfw)

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