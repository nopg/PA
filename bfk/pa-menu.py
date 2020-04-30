"""
Description: 
    Generic PA Menu

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
        $ python bfk.py -c <PA(N) mgmt IP> -u <username> (optional: -x <xml_filename>)
        Password: 

Cautions:
    Not fully developed

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

import xmltodict
import api_lib_pa as pa_api

# Import Bob
import bfk as bob

PUSH_CONFIG_TO_PA = False

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

    if PUSH_CONFIG_TO_PA:
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


def grab_security_rules(pa_type, pa=None, filename=None):

    if pa_type == "xml":
        # Grab XML file, modify rules, and create output file.
        security_rules = grab_xml_or_json_file(filename)
        return security_rules["result"]["rules"]["entry"]

    elif pa_type == "panorama":

        # Grab the Device Groups and Template Names, we don't need Template names.
        device_groups, _ = pa.grab_panorama_objects()

        print("--------------\n")
        print("Device Groups:")
        print("--------------")
        for dg in device_groups:
            print(dg)
            
        pa.device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")
    
        # Set the XPath now that we have the Device Group
        XPATH_PRE = pa_api.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)
        XPATH_POST= pa_api.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)

        # Grab Rules
        pre_security_rules = pa.grab_api_output("xml", XPATH_PRE, "api/pre-rules.xml")
        post_security_rules = pa.grab_api_output("xml", XPATH_POST, "api/post-rules.xml")

        # Modify the rules, Pre & Post, then append to output list
        if not pre_security_rules["result"]:
            pre_security_rules = None
        else:
            pre_security_rules = pre_security_rules["result"]["rules"]["entry"]

        if not post_security_rules["result"]:
            post_security_rules = None
        else:
            post_security_rules = post_security_rules["result"]["rules"]["entry"]

        return pre_security_rules, post_security_rules


    elif pa_type == "pa":
        # Grab Rules
        security_rules = pa.grab_api_output("xml", pa_api.XPATH_SECURITYRULES, "api/pa-rules.xml")
        if security_rules["result"]:
            # Modify the rules, append to be output
            return security_rules["result"]["rules"]["entry"]

    return None


def main_menu(pa_ip, username, password, pa_type, filename=None):

    pa = pa_api.api_lib_pa(pa_ip, username, password)

    if pa_type == "xml" or filename:
        output_list = "4"
    else:
        allowed = list("1234,-")  # Allowed user input
        incorrect_input = True

        while incorrect_input:
            selection = input(
                """\nWhat would you like to do?

                1) List Interfaces
                2) List NAT
                3) List Security Rules
                4) Better Call Bob

                For multiple enter: ('1' or 2-4' or '2,5,7')

                Enter Selection: """
            )

            for value in selection:
                if value not in allowed:
                    incorrect_input = True
                    break
                else:
                    incorrect_input = False

            temp = "".join(selection)
            if temp.endswith("-") or temp.startswith("-"):
                incorrect_input = True

        # Turn input into list, remove commas
        output_list = list(selection.replace(",", ""))

        # Organize user input
        # Expand '2-5,8-9' to '2,3,4,5,8,9'
        if "-" in output_list:
            dashes = [index for index, value in enumerate(output_list) if value == "-"]
            remaining = output_list
            final = []

            for dash in dashes:
                predash = remaining.index("-") - 1
                postdash = remaining.index("-") + 1

                up_to_predash = [x for x in remaining[:predash]]
                final = final + up_to_predash

                expanded = range(int(remaining[predash]), int(remaining[postdash]) + 1)
                final = final + [str(num) for num in expanded]

                remaining = remaining[postdash + 1 :]

            if remaining:
                output_list = final + remaining
            else:
                output_list = final

    ######
    ### Begin the real work.
    ######
    # Loop through user provided input, import each profile
    for output in output_list:

        if output == "1": 
            # SET PROPER VARIABLES, GRAB EXTRA VALUES IF NEEDED
            XPATH = "/config/devices/entry[@name='localhost.localdomain']/network/interface"
            filename = f"api/interfaces.xml"

            if pa_type == "panorama":
                # Needs Template Name 
                _, template_names = pa.grab_panorama_objects()
                print("\nTemplate Names:")
                print("---------------------")
                for template in template_names:
                    print(template)
                template_name = input("\nEnter the Template Name (CORRECTLY!): ")
                XPATH = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{TEMPLATE_NAME}']/config/devices/entry[@name='localhost.localdomain']/network/interface"

            # Grab Output (XML or REST, convert to dict.)
            api_output = pa.grab_api_output("xml", XPATH, filename)
            print(api_output)

        elif output == "2": 
            # SET PROPER VARIABLES, GRAB EXTRA VALUES IF NEEDED
            XPATH_OR_RESTCALL = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"
            filename = f"api/natrules.json"
            xml_or_rest = "xml"

            if pa_type == "panorama":
                # Need Device Group
                device_groups, _ = pa.grab_panorama_objects()
                print("\nDevice Groups:")
                print("--------------")
                for dg in device_groups:
                    print(dg)
                    
                device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")
                XPATH_OR_RESTCALL = f"/restapi/9.0/Policies/NATPostRules?location=device-group&device-group={device_group}"
                xml_or_rest = "rest"

            # Grab Output (XML or REST, convert to dict.)
            api_output = pa.grab_api_output(xml_or_rest, XPATH_OR_RESTCALL, filename)
            print(api_output)

        elif output == "3": 

            # SET PROPER VARIABLES, GRAB EXTRA VALUES IF NEEDED
            filename = f"api/pa-security-rules.xml"

            if pa_type == "panorama":
                # Need Device Group
                device_groups, _ = pa.grab_panorama_objects()
                print("\nDevice Groups:")
                print("--------------")
                for dg in device_groups:
                    print(dg)
                    
                device_group = input("\nEnter the Device Group Name (CORRECTLY!): ")
                PRE_XPATH = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group}']/pre-rulebase/security/rules"
                POST_XPATH = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group}']/post-rulebase/security/rules"
                pre_api_output = pa.grab_api_output("xml", PRE_XPATH, filename)
                post_api_output = pa.grab_api_output("xml", POST_XPATH, filename)

                print("\nPRE:\n")
                print(pre_api_output)
                print("\nPOST:\n")
                print(post_api_output)
            else:
                # Grab Output (XML or REST, convert to dict.)
                XPATH = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
                api_output = pa.grab_api_output("xml", XPATH, filename)
                print(api_output)

        elif output == "4": 
            modified_rules = None
            modified_pre_rules = None
            modified_post_rules = None
            to_output = []

            if pa_type == "xml":
                security_rules = grab_security_rules("xml", None, filename)
                modified_rules = bob.modify(security_rules)
            elif pa_type == "pa":
                security_rules = grab_security_rules(pa_type, pa)
                modified_rules = bob.modify(security_rules)
            elif pa_type == "panorama":
                pre_rules, post_rules = grab_security_rules(pa_type, pa)
                if pre_rules:
                    modified_pre_rules = bob.modify(pre_rules)
                if post_rules:
                    modified_post_rules = bob.modify(post_rules)

            if modified_rules:      
                to_output.append( [modified_rules, "bobs-new-rules.xml", pa_api.XPATH_SECURITYRULES, pa] )
            if modified_pre_rules:    
                XPATH_PRE = pa_api.XPATH_PRE_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)  
                to_output.append( [modified_pre_rules, "bobs-new-pre-rules.xml", XPATH_PRE, pa] )
            if modified_post_rules:      
                XPATH_POST= pa_api.XPATH_POST_SECURITY_RULES_PAN.replace("DEVICE_GROUP", pa.device_group)
                to_output.append( [modified_post_rules, "bobs-new-post-rules.xml", XPATH_POST, pa] )
            
            # Begin creating output and/or pushing rules to PA/PAN
            for ruletype in to_output:
                output_and_push_changes(*ruletype)

    print("\nExiting Main Menu.\n")
    sys.exit(0)


# If run from the command line
if __name__ == "__main__":

    # Guidance on how to use the script
    if len(sys.argv) == 2:
        PUSH_CONFIG_TO_PA = False
        filename = sys.argv[1]
        main_menu(None,None,None,"xml",filename)
        sys.exit(0)
    elif len(sys.argv) != 3:
        print("\nplease provide the following arguments:")
        print(
            "\tpython pa-menu.py <PA/Panorama IP> <username>\n\n"
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
        paobj = pa_api.api_lib_pa(pa_ip, username, password)
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
    main_menu(pa_ip, username, password, pa_type, filename)