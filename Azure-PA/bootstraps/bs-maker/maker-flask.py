import argparse
import os
import sys
import xml.dom.minidom

from azure.storage.fileshare import ShareClient
from flask import Flask, render_template, url_for, flash, redirect, Markup
import forms
import xmltodict
from jinja2 import Template

app = Flask(__name__)
app.config['SECRET_KEY'] = 'abcd'


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
    
    return None


def update_bootstrap(templatefile1, templatefile2, **kwargs):

    # Create Bootstrap File
    with open(templatefile1) as fin:
        template1 = Template(fin.read())
    with open(templatefile2) as fin:
        template2 = Template(fin.read())

    bootstrap1 = template1.render(**kwargs)
    create_xml_files(bootstrap1, 'auto-bootstrap1.xml')

    bootstrap2 = template2.render(**kwargs)
    create_xml_files(bootstrap2, 'auto-bootstrap2.xml')

    # Begin Azure 
    AZURE_STORAGE_CONNECTION_STRING = kwargs['connection_string']
    fullpath = kwargs['folder_name']

    share = ShareClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING, "bootstrap")
    az_bootstrap_str1 = f"{fullpath}/fw1/config/bootstrap.xml"
    az_bootstrap_str2 = f"{fullpath}/fw2/config/bootstrap.xml"
    az_initcfg_str1 = f"{fullpath}/fw1/config/init-cfg.txt"
    az_initcfg_str2 = f"{fullpath}/fw2/config/init-cfg.txt"
    
    index = fullpath.rfind("/")
    parentfolder = ""
    if index == -1:
        index = fullpath.rfind("\\")
        if index == -1:
            folder = fullpath
    else:
        parentfolder = fullpath[:index]
        folder = fullpath[index:].strip("/\\") # Remove leading / or \
        try:
            temp = share.get_directory_client(parentfolder)
            temp.get_directory_properties()
        except:
            share.create_directory(parentfolder)

    try:
        temp = share.get_directory_client(parentfolder +'/'+ folder)
        temp.get_directory_properties()
    except:
        share.create_directory(parentfolder +'/'+ folder)

    try:
        share.create_directory(f"{fullpath}/fw1")
        share.create_directory(f"{fullpath}/fw2")

        share.create_directory(f"{fullpath}/fw1/config")
        share.create_directory(f"{fullpath}/fw1/content")
        share.create_directory(f"{fullpath}/fw1/license")
        share.create_directory(f"{fullpath}/fw1/software")

        share.create_directory(f"{fullpath}/fw2/config")
        share.create_directory(f"{fullpath}/fw2/content")
        share.create_directory(f"{fullpath}/fw2/license")
        share.create_directory(f"{fullpath}/fw2/software")

    except Exception as e:
        return f"Error: {e}", "danger"

    # [START upload_files]
    az_bootstrap1 = share.get_file_client(az_bootstrap_str1)
    az_bootstrap2 = share.get_file_client(az_bootstrap_str2)
    az_init_cfg1 = share.get_file_client(az_initcfg_str1)
    az_init_cfg2 = share.get_file_client(az_initcfg_str2)

    with open('auto-bootstrap1.xml', "rb") as source:
        az_bootstrap1.upload_file(source)
    with open('auto-bootstrap2.xml', "rb") as source:
        az_bootstrap2.upload_file(source)

    with open('static/init-cfg.txt', "rb") as source:
        az_init_cfg1.upload_file(source)
    with open('static/init-cfg.txt', "rb") as source:
        az_init_cfg1.upload_file(source)

    # [END upload_file]

    return f"Bootstrap created. File uploaded to '{kwargs['folder_name']}/config/bootstrap.xml'", "success"


@app.route("/", methods=["GET"])
def index():
    # Create Form
    return render_template("index.html", title="gMenu")


@app.route("/bs_maker", methods=["GET", "POST"])
def bs_maker():
    # Create Form
    form = forms.HomePage()

    # Submit:
    if form.validate_on_submit():
        # Gather Args
        kwargs = {
                    'hostname1':form.pahostname1.data,
                    'private_ip1':form.paprivateip1.data,
                    'public_ip1':form.papublicip1.data,
                    'private_nexthop1':form.paprivatenexthop1.data,
                    'public_nexthop1':form.papublicnexthop1.data,
                    'hostname2':form.pahostname2.data,
                    'private_ip2':form.paprivateip2.data,
                    'public_ip2':form.papublicip2.data,
                    'private_nexthop2':form.paprivatenexthop2.data,
                    'public_nexthop2':form.papublicnexthop2.data,
                    'connection_string':form.connection_string.data,
                    'folder_name':form.folder_name.data
        }
        # Update bootstrap, alert user.
        msg, successOrFail = update_bootstrap('static/bs-template1.xml', 'static/bs-template2.xml', **kwargs)

        if successOrFail == "success":
            msg += """

                To begin Azure deployment, <a href='https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fcnetpalopublic.blob.core.windows.net%2Farm-public%2Fgenlb.json'>click here.</a>
                    
                """
            msg = Markup(msg)
        flash(msg, successOrFail)

    return render_template("bs-maker.html", title="PA Bootstrap Maker", form=form)

@app.route("/az_arms", methods=["GET"])
def az_arms():
    return render_template("az_arms.html", title="Azure ARM Templates")


@app.route("/about")
def about():
    return render_template("temp.html", title="gAbout")


@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("temp.html", title="gMenu")


# If run from the command line
if __name__ == "__main__":
    app.run(debug=True)