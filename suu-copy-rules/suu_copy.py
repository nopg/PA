"""
Description: 
    Copy Security Rules from one Device Group to another, if ZONENAME is in that rule (src or dst)

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
        $ python suu_copy.py -i <PA(N) mgmt IP> -u <username>
        Password: 

Cautions:

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
import argparse

import xmltodict
import api_lib_pa as pa_api

###############################################################################################

class settings: 
    PUSH_CONFIG_TO_PA = True


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


def output_and_push_changes(new_rules, filename=None, xpath=None, pa=None):

    # Always create an output file with the new-rules.
    if not filename:
        filename = "output/new-pa-rules.xml"
    # Prepare output
    add_entry_tag = {"entry": new_rules}   # Adds the <entry> tag to each rule
    new_rules_xml = {"config": {"security": {"rules": add_entry_tag} } } # Provides an xpath for importing
    data = xmltodict.unparse(new_rules_xml)    # Turn XML into a string
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
                    same_dg = input(f"Push to destination Device Group ({pa.dst_device_group})? [y/n]: ")

                # Update xpath to new device-group
                if same_dg == "n":
                    print("\nWell then why'd you say so last time I asked? Try again!\n")
                    sys.exit(0)
                
                xpath = xpath.replace(pa.device_group, pa.dst_device_group)

            fname = filename.rsplit('/', 1)[1]  # Get filename, strip any folders before the filename.
            load_url = f"https://{pa.pa_ip}:443/api/?type=op&key={pa.key}&cmd=<load><config><partial><mode>replace</mode><from-xpath>/config/security/rules</from-xpath><to-xpath>{xpath}</to-xpath><from>{fname}</from></partial></config></load>"
            
            response = pa.session[pa.pa_ip].get(load_url, verify=False)
            error_check(response, "Loading Configuration")

            print("\nCandidate configuration successfully loaded...enjoy the new ruleset!")
            print("Review configuration and Commit manually via the GUI.\n")
        else:
            print("\nThank you, finished.\n")
    
    return None


def get_device_groups(pa):

    incorrect_input = True
    while incorrect_input:
        device_groups, _ = pa.grab_panorama_objects()
        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
        src_device_group = input("\nEnter the Source Device Group Name: ")
        dst_device_group = input("\nEnter the Destination Device Group Name: ")

        if src_device_group in device_groups and dst_device_group in device_groups:
            incorrect_input = False
        else:
            print("\n\nERROR: Template or Device Group not found.\n")
    
    return src_device_group, dst_device_group


def copy_rules(security_rules, zone_to_check):
    """
    COPY/CLONE SECURITY RULES
    This accepts a dictionary of rules and copies them to a new Device Group if ZONENAME matches
    ZONENAME currently taken in via user input.

    :param security_rules: existing security rules
    :return: new_rules, new/cloned security rule-set
    """
    def copy1(tofrom, x_zone):
        """
        inner function (possibly to be moved outside later)
        The bulk of the logic is done here
        Source & destination behave the same, this allows the same code to be used for both.

        :param tofrom: the xml Address-Object tag needed for insertion into the new rule
        :param x_zone: from or to, zone name
        :return: True or False
        """

        tocopy = False

        try:
            if not isinstance(x_zone, list):
                x_zone = [x_zone]
                newrule[tofrom]["member"] = [newrule[tofrom]["member"]]

            for zone in x_zone:
                if zone_to_check == zone:   # Found relevant rule
                    tocopy = True
                else:
                    pass

        except TypeError:
            print("\nError, candidate config detected. Please commit or revert changes before proceeding.\n")
            sys.exit(0)              

        # If I only made it a list to make it easier on myself, change it back.
        if len(newrule[tofrom]["member"]) == 1:
            newrule[tofrom]["member"] = newrule[tofrom]["member"][0]
    
        return tocopy 

    # copy_rules()
    copied_rules = []
    if not isinstance(security_rules, list):
        security_rules = [security_rules]

    print("\nEvaluating...\n")
    for oldrule in security_rules:
        newrule = copy.deepcopy(oldrule)
        from_zone = oldrule["from"]["member"]
        to_zone = oldrule["to"]["member"]

        # Check and copy if Zone is found
        tocopy = copy1("from", from_zone)
        if not tocopy:
            tocopy = copy1("to", to_zone)

        if tocopy:
            copied_rules.append(newrule)

    print("..Done.")
    return copied_rules


def suu_copy(pa_ip, username, password, pa_type, filename=None):
    """
    Main point of entry.
    Connect to PA/Panorama.
    Grab security rules from pa/pan.
    Clone if ZONENAME is found
    """

    # Grab 'start' time
    start = time.perf_counter()
    
    if pa_type != "xml":
        pa = pa_api.api_lib_pa(pa_ip, username, password, pa_type)
    to_output = []

    if pa_type == "xml":
        # Grab XML file, clone rules, and create output file.
        security_rules = grab_xml_or_json_file(filename)
        new_rules = new_rules(security_rules["result"]["rules"]["entry"])
        output_and_push_changes(new_rules, "output/new-xml-rules.xml")

    elif pa_type == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        pa.device_group, pa.dst_device_group = get_device_groups(pa)
        zone_to_check = input("\nEnter the Zone name to be migrated: ")
    
        # Set the XPath now that we have the Device Group
        XPATH_PRE = pa_api.XPATH_SECURITY_RULES_PRE_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_POST = pa_api.XPATH_SECURITY_RULES_POST_PAN.replace("DEVICE_GROUP", pa.device_group)

        # Grab Rules
        pre_security_rules = pa.grab_api_output("xml", XPATH_PRE, "output/api/pre-rules.xml")
        post_security_rules = pa.grab_api_output("xml", XPATH_POST, "output/api/post-rules.xml")

        # Clone the rules, Pre & Post, then append to output list

        if pre_security_rules["result"]:
            if "entry" in pre_security_rules["result"]["rules"]:
                new_rules_pre = copy_rules(pre_security_rules["result"]["rules"]["entry"], zone_to_check)
                to_output.append([new_rules_pre,"output/new-pre-rules.xml", XPATH_PRE, pa])

        if post_security_rules["result"]:
            if "entry" in post_security_rules["result"]["rules"]:
                new_rules_post = copy_rules(post_security_rules["result"]["rules"]["entry"], zone_to_check)
                to_output.append([new_rules_post,"output/new-post-rules.xml", XPATH_POST, pa])
            
    else:
        print("Error, Device Groups don't exist on a PA, whatchu talking 'bout?")
        sys.exit(0)

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
        suu_copy("n/a","n/a","n/a","xml",filename)
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
    suu_copy(pa_ip, username, password, pa_type)