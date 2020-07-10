import argparse
import os
import xml.dom.minidom

import xmltodict
from jinja2 import Template


def create_xml_files(temp, filename):

    # Because XML: remove <response/><result/> and <?xml> tags
    # Using get().get() won't cause exception on KeyError
    # Check for various response type and ensure xml is written consistently

    #Set data
    blah = {'root':temp}
    data = xmltodict.unparse(blah)
    data = data.replace('<?xml version="1.0" encoding="utf-8"?>', "")
    prettyxml = xml.dom.minidom.parseString(data).toprettyxml()

    with open(filename, "w") as fout:
        fout.write(temp)



def update_bootstrap(filename):
    with open(filename) as fin:
        template = Template(fin.read())

    hostname = "pavm2"
    private_ip = "10.2.248.5"
    public_ip = "10.2.1.5"
    private_nexthop = "10.2.248.1"
    public_nexthop = "10.2.1.1"

    bootstrap = template.render(hostname=hostname,
                                private_ip=private_ip, 
                                public_ip=public_ip,
                                private_nexthop=private_nexthop,
                                public_nexthop=public_nexthop)

    create_xml_files(bootstrap, 'bs.xml')


# If run from the command line
if __name__ == "__main__":

    # Check arguments, if 'xml' then don't need the rest of the input
    #argrequired = '--xml' not in sys.argv and '-x' not in sys.argv
    parser = argparse.ArgumentParser(description="Please use this syntax:")
    parser.add_argument("-x", "--xml", help="Optional XML Filename", type=str, required=True)
    # parser.add_argument("-u", "--username", help="Username", type=str, required=argrequired)
    # parser.add_argument("-i", "--ipaddress", help="IP or FQDN of PA/Panorama", type=str, required=argrequired)
    args = parser.parse_args()

    filename = args.xml

    # Run program
    print("\nThank you...\n")
    update_bootstrap(filename)
    print("\nGood bye.\n")