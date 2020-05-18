"""
Description: 
    PA Gratuitous ARP Script
    Connect to PA or Panorama and determine which IP Addresses and Interfaces should
    Send Gratuitous ARP out, typically during the cutover of a new FW.

Requires:
    ipcalc
    requests
    xmltodict
    lxml
        to install try: pip3 install xmltodict requests lxml ipcalc

Author:
    Ryan Gillespie rgillespie@compunet.biz
    Docstring stolen from Devin Callaway

Tested:
    Tested on macos 10.13.6
    Python: 3.6.2
    PA VM100, Panorama, PA 5250

Example usage:
        $ python3 garp.py <destination folder> <PA(N) mgmt IP> <username>
        Password: 

Cautions:
    - Source-NAT only (discovers and outputs others)
    - Panorama Post-NAT rules only (for now)
    

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
import ipcalc
import time
import argparse
#import concurrent.futures

import xmltodict
import api_lib_pa as pa_api

DEBUG = False

class mem: 
    ip_to_eth_dict = {}
    garp_commands = []
    review_nats = []
    address_object_entries = None

# class mem: 

#     XPATH_ADDRESS_OBJ =  "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='ENTRY_NAME']"
#     XPATH_ADDRESS_OBJ_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/address/entry[@name='ENTRY_NAME']"

#     XPATH_INTERFACES =    "/config/devices/entry[@name='localhost.localdomain']/network/interface"
#     XPATH_INTERFACES_PAN =    "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TEMPLATE_NAME']/config/devices/entry[@name='localhost.localdomain']/network/interface"

#     XPATH_DEVICE_GROUPS = "/config/devices/entry[@name='localhost.localdomain']/device-group"
#     XPATH_TEMPLATE_NAMES = "/config/devices/entry[@name='localhost.localdomain']/template"

#     XPATH_POST_NAT_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/post-rulebase/nat/rules"
#     XPATH_PRE_NAT_RULES_PAN = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP']/pre-rulebase/nat/rules"
#     XPATH_NAT_RULES = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"

#     ip_to_eth_dict = {}
#     pa_ip = None
#     username = None
#     password = None
#     fwconn = None
#     device_group = None
#     root_folder = '.'
#     garp_commands = []
#     review_nats = []

def iterdict(d, searchfor):
    """
    Traverse through the dictionary (d) and find the key: (searchfor).
    Return the value of that key.
    """
    for k, v in d.items():
        if searchfor in k:
            return v
        elif isinstance(v, dict):
            if not v:
                print(f"system error..\nk={k}\nv={v}")
                sys.exit(0)
            return iterdict(v, searchfor)
        else:
            pass


def interface_lookup(ip):
    """
    Used to find which physical interface is associated with this IP (NAT entry).
    Uses existing dictionary mapping ip/mask to physical interface.
    Searches based on the subnet mask in use on the physical interface.
    """
    for key, v in mem.ip_to_eth_dict.items():
        iprange = ipcalc.Network(key)
        if ip in iprange:
            return v


def address_lookup(entry):
    """
    Used to find the translated addresses objects on the PA/Panorama.
    Runs another api call to grab the object and return it's value (the actual ip address)
    If the NAT rule isn't using an object, we can assume this value is the IP address.
    Returns a LIST
    """
    if pa.pa_type == "panorama":
        XPATH = pa_api.XPATH_ADDRESS_OBJ_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH = XPATH.replace("ENTRY_NAME", entry)
    else:
        XPATH = pa.XPATH_ADDRESS_OBJ.replace("ENTRY_NAME", entry)

    filename = entry.split("/", 1)[0]
    output = pa.grab_api_output("xml", XPATH, f"api/address-obj--{filename}.xml")

    # Need to check for no response, must be an IP not address
    if output["result"]:
        if "entry" in output["result"]:
            if "ip-netmask" in output["result"]["entry"]:
                ips = output["result"]["entry"]["ip-netmask"]
            else:
                add_review_entry(output["result"]["entry"], "not-ip-netmask")
        else:
            # It must be an IP/Mask already
            ips = entry
    else:
        # It must be an IP/Mask already
        ips = entry    

    if ips is list:
        for ip in ips:
            ips.append(ip)
    else:
        ips = [ips]

    return ips


def add_review_entry(entry, type):
    if type == "disabled":
        mem.review_nats.append(f"Disabled Rule: Check {entry['@name']}")
    elif type == "dnat":
        mem.review_nats.append(f"DNAT, - Check NAT rule named: '{entry['@name']}' for details.")
    elif type == "not-ip-netmask":
        mem.review_nats.append(f"non IP-NETMASK used for translated address: '{entry['@name']}' for details.")

        print("Not implemented yet. I can add it easily if you need it. Send me the natrules.xml")
        print("Most likely an address-object using 'IP Range', 'IP Wildcard Mask', or 'FQDN'.")
        print("For NAT? I know a couple use cases, but maybe manually add this gARP after reviewing.")
        print("May be redundant or otherwise unnecessary.")

    pa_api.create_xml_files(entry, f"review-{entry['@name']}.xml")


def add_garp_command(ip, ifname):
    """
    Update global garp_commands list.
    First remove the subnet mask from the 'ip' received.
    example: 'test arp gratuitous ip 5.5.5.4 interface ethernet1/1'
    """
    ip = ip.split("/", 1)[0]  # removes anything in IP after /, ie /24
    garp_command = f"test arp gratuitous ip {ip} interface {ifname}"
    return garp_command



def process_interface_entries(entry):
    # Set interface name
    ifname = entry["@name"]
    commands = []

    # Should have an IP
    if "layer3" in entry:
        found = False
        errors = []
        # Normal IP Address on interface
        if "ip" in entry["layer3"]:
            # Secondary IP Addresses
            if type(entry["layer3"]["ip"]["entry"]) is list:
                for xip in entry["layer3"]["ip"]["entry"]:
                    ip = xip["@name"]
                    found = True
                    mem.ip_to_eth_dict.update({ip: ifname})
                    commands.append(add_garp_command(ip, ifname))
            else:  # Normal 1 IP on 1 interface
                found = True
                ip = entry["layer3"]["ip"]["entry"]["@name"]
                mem.ip_to_eth_dict.update({ip: ifname})
                commands.append(add_garp_command(ip, ifname))

        # Sub Interfaces
        if "units" in entry["layer3"]:
            # Sub Interfaces

            if isinstance(entry["layer3"]["units"]["entry"], list):

                for subif in entry["layer3"]["units"]["entry"]:
                    # Set new (sub)interface name
                    subifname = subif["@name"]
                    # Secondary IP Addresses
                    if "ip" in subif:
                        if type(subif["ip"]["entry"]) is list:
                            for subif_xip in subif["ip"]["entry"]:
                                found = True
                                ip = subif_xip["@name"]
                                mem.ip_to_eth_dict.update({ip: subifname})
                                commands.append(add_garp_command(ip, subifname))
                        else:  # Normal 1 IP on Subinterface
                            found = True
                            ip = subif["ip"]["entry"]["@name"]
                            mem.ip_to_eth_dict.update({ip: subifname})
                            commands.append(add_garp_command(ip, subifname))
                    else:
                        err = (
                            f"No IP address found (e4)-(DHCP?), {subifname}"
                        )
                        errors.append(err)
            else:  
                # Only one Sub Interface
                subifname = entry["layer3"]["units"]["entry"]["@name"]

                if "ip" in entry["layer3"]["units"]["entry"]:

                    ip = entry["layer3"]["units"]["entry"]["ip"]

                    if isinstance(ip, list):
                        for subif_xip in ip:
                            found = True
                            ip = subif_xip["@name"]
                            mem.ip_to_eth_dict.update({ip: subifname})
                            commands.append(add_garp_command(ip, subifname))
                    else:
                        found = True
                        ip = ip["entry"]["@name"]
                        mem.ip_to_eth_dict.update({ip: subifname})
                        commands.append(add_garp_command(ip, subifname))
                else:
                    err = (
                        f"No IP address found (e3)-(DHCP?), {subifname}"
                    )
                    errors.append(err)                 

        if not found:  # Probably DHCP, should be added
            err = (
                f"No IP address found (e1)-(DHCP?), {ifname}"
            )
            errors.append(err)
            return errors
        else:
            return commands

    else:  # No 'layer3', no IP Address here.
        error = f"No IP address found (e2), {ifname}"
        return error


def build_garp_interfaces(entries, iftype):
    """
    Search through ethernet and aggregate-ethernet interfaces.
    Build a list of 'test arp' commands based on what is found.
    Return this list.
    """
    results = None
    if entries:
        print(f"\nSearching through {iftype} interfaces")
        
        entries_ = entries["entry"]
        if isinstance(entries_, list):
            pass
        else:
            results = process_interface_entries(entries_)
            return [results]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = executor.map(process_interface_entries, entries["entry"])
        
        return results
        
    else:  # No interfaces
        print(f"\nNo interfaces found for '{iftype}' type interfaces\n")


def process_nat_entries(entry):
    ip = None
    
    if "disabled" in entry:
        if entry["disabled"] == "yes":
            add_review_entry(entry, "disabled")
            return None
    if "destination-translation" in entry:
        add_review_entry(entry, "dnat")
    if "source-translation" in entry:
        snat = entry["source-translation"]

        # Returns Address Object typically, could also be an IP
        # Usually 'translated-address' but also check for 'interface-address'
        addr_obj = iterdict(snat, "translated-address")
        if addr_obj:
            # If it's a dictionary, we have multiple IP's
            if isinstance(addr_obj, dict):
                ipobjs = []
                if isinstance(addr_obj["member"], list):
                    [ipobjs.append(o) for o in addr_obj["member"]]
                else:
                    ipobjs.append(addr_obj["member"])
                # Find the real-ip from the address object
                for ipobj in ipobjs:
                    ips = address_lookup(ipobj)
                    commands = []
                    for ip in ips:
                        ifname = interface_lookup(ip)
                        if not ifname:
                            ifname = "INTERFACE NOT FOUND"
                        commands.append(add_garp_command(ip, ifname))
                    return commands
            else:
                # Find the real-ip from the address object
                ips = address_lookup(addr_obj)
                commands = []
                for ip in ips:
                    ifname = interface_lookup(ip)
                    if not ifname:
                        ifname = "INTERFACE NOT FOUND"
                    commands.append(add_garp_command(ip, ifname))
                return commands
        else:
            # Checking for interface-address?
            addr_obj = iterdict(snat, "interface-address")
            if addr_obj:
                ifname = snat["dynamic-ip-and-port"]["interface-address"][
                    "interface"
                ]
                if "ip" in snat["dynamic-ip-and-port"]["interface-address"]:
                    ipobj = snat["dynamic-ip-and-port"]["interface-address"][
                        "ip"
                    ]
                    ips = address_lookup(ipobj)
                    for ip in ips:
                        return add_garp_command(ip, ifname)
                else:  # No IP found(DHCP?), since we have interface should already have a 'test' command for it
                    ip = "IP NOT FOUND, ARP taken care of via: "
                    return add_garp_command(ip, ifname)
            else:  # SNAT Misconfigured
                error =  (
                    f"Error, SNAT configured without a translated IP, {snat}"
                )
                return error
    
    return None


def build_garp_natrules(entries):
    """
    Search through PA/Panorama NAT Rules.
    Build a list of 'test arp' commands based on what is found.
    Currently only supports source-nat, dest-nat's are noted at the end of the output.
    Return this list.
    """
    results = None
    if entries:
        print(f"\nSearching through natrules")
        print("\nPlease wait..\n")

        entries_ = entries["entry"]
        if isinstance(entries_, list):
            pass
        else:
            results = process_nat_entries(entries_)
            return [results]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = executor.map(process_nat_entries, entries["entry"])
        
        return results

    else:  # No Natrules
        print(f"No nat rules found for 'natrules")
        return []


def build_garp_output(command_list):
    for command in command_list:
        if isinstance(command,list):
            for ip in command:
                mem.garp_commands.append(ip)
        else:
            mem.garp_commands.append(command)


def validate_output(output_types):
    for output_type, output in output_types.items():
        found = False
        if output:
            if output.get("result"):
                found = True
        if not found:
            output = None
            print(f"\nNo {output_type} found, check interfaces.xml for API Reply\n")
            if output_type != "pre-nat-rules":
                print("Unable to load required information, see above and correct the issue.\n")
                sys.exit(0)


def garp_logic(pa_ip, username, password, pa_type, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab 'test arp' output from interfaces and NAT rules.
    Print out the commands.
    """

    if pa_type != "xml":
        pa = pa_api.api_lib_pa(pa_ip, username, password, pa_type)

    # Set the correct XPATH for what we need (interfaces and nat rules)
    if pa_type == "panorama":

        incorrect_input = True
        while incorrect_input:
            # Needs Template Name & Device Group
            device_groups, template_names = pa.grab_panorama_objects()
            print("\nTemplate Names:")
            print("---------------------")
            for template in template_names:
                print(template)
            print("--------------\n")
            print("Device Groups:")
            print("--------------")
            for dg in device_groups:
                print(dg)
                
            pa.template_name = input("\nEnter the Template Name: ")
            pa.device_group = input("\nEnter the Device Group Name: ")

            incorrect_input = (
                pa.device_group not in device_groups or
                pa.template_name not in template_names
            )
            if incorrect_input:
                print("\n\nERROR: Template or Device Group not found.\n")

        # Found Device Group / Template Name, Proceed
        XPATH_INTERFACES = pa_api.XPATH_INTERFACES_PAN.replace("TEMPLATE_NAME", pa.template_name)
        XPATH_PRE = pa_api.XPATH_NAT_RULES_PRE_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_POST = pa_api.XPATH_NAT_RULES_POST_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_ADDR = pa_api.XPATH_ADDRESS_OBJ_PAN.replace("DEVICE_GROUP", pa.device_group)
        
        # Grab NAT Rules
        pre_nat_output = pa.grab_api_output(
            "xml", XPATH_PRE, f"api/pre-natrules.xml"
        )
        post_nat_output = pa.grab_api_output(
            "xml", XPATH_POST, f"api/post-natrules.xml"
        )
    
    elif pa_type == "pa":
        XPATH_INTERFACES = pa_api.XPATH_INTERFACES
        XPATH_NATRULES = pa_api.XPATH_NAT_RULES
        XPATH_ADDR = pa_api.XPATH_ADDRESS_OBJ

        # Grab NAT Rules 
        pre_nat_output = None
        post_nat_output = pa.grab_api_output(
            "xml", XPATH_NATRULES, f"api/pa-natrules.xml"
        )

    elif pa_type == "xml":
        pre_nat_output = None
        post_nat_output = None
        fin = open(filename, 'r')
        temp = fin.read()
        fin.close()
        int_output = xmltodict.parse(temp)
        int_output = int_output["response"]
        # print(int_output["response"])
        sys.exit(0)
    
    # We have what we need, begin the work.
    start = time.perf_counter()

    # Grab Interfaces
    int_output = pa.grab_api_output(
        "xml", XPATH_INTERFACES, f"api/interfaces.xml"
    )
    address_objects = pa.grab_api_output(
        "xml", XPATH_ADDR, f"api/address-objects.xml"
    )

    output_types = {
        "interfaces": int_output,
        "address-objects": address_objects,
        "pre-nat-rules": pre_nat_output,
        "post-nat-rules": post_nat_output
    }

    validate_output(output_types)

    # Parse XML to get to what we need closer to a dictionary
    eth_entries = int_output["result"]["interface"].get("ethernet")
    ae_entries = int_output["result"]["interface"].get("aggregate-ethernet")
    if pre_nat_output:
        pre_nat_entries = pre_nat_output["result"]["rules"]
    post_nat_entries = post_nat_output["result"]["rules"]
    mem.address_object_entries = address_objects["result"]["address"]


    # Start the real work finally...
    eth_commands = build_garp_interfaces(eth_entries, "ethernet")
    ae_commands = build_garp_interfaces(ae_entries, "aggregate-ethernet")

    if pre_nat_output:
        garp_pre_nat_commands = build_garp_natrules(pre_nat_entries)
    else:
        garp_pre_nat_commands = None

    garp_post_nat_commands = build_garp_natrules(post_nat_entries)

    mem.garp_commands.append(
        "--------------------ARP FOR Interfaces---------------------"
    )
    build_garp_output(eth_commands)
    build_garp_output(ae_commands)
    mem.garp_commands.append(
        "-------------------------ARP FOR NAT-----------------------"
    )
    build_garp_output(garp_pre_nat_commands)
    build_garp_output(garp_post_nat_commands)


    # Print out all the commands/output!
    print(f"\ngARP Test Commands:")
    print("-----------------------------------------------------------")
    for line in mem.garp_commands:
        print(line)
    print("-----------------------------------------------------------")

    print("--------------------REVIEW THESE NATS----------------------")
    for nat in mem.review_nats:
        print(nat)
    print("-----------------------------------------------------------\n")
    end = time.perf_counter()
    runtime = end - start
    print(f"Took {runtime} Seconds.")



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
        DEBUG = True
        filename = args.xml
        garp_logic("n/a", "n/a", "n/a", "xml", filename)
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
    garp_logic(pa_ip, username, password, pa_type)
