import argparse
import os
import xml.dom.minidom
from flask import Flask, render_template, url_for, flash, redirect
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



def update_bootstrap(filename, **kwargs):
    with open(filename) as fin:
        template = Template(fin.read())

    bootstrap = template.render(**kwargs)
    create_xml_files(bootstrap, 'auto-bootstrap.xml')

@app.route("/", methods=["GET", "POST"])
def index():
    # Create Form
    form = forms.HomePage()

    # Submit:
    if form.validate_on_submit():
        # Gather Args
        kwargs = {
                    'hostname':form.pahostname.data,
                    'private_ip':form.paprivateip.data,
                    'public_ip':form.papublicip.data,
                    'private_nexthop':form.paprivatenexthop.data,
                    'public_nexthop':form.papublicnexthop.data,
        }
        # Update bootstrap, alert user.
        update_bootstrap('templates/bs-template1.xml', **kwargs)
        flash(f"Bootstrap created. File name is 'auto-bootstrap.xml'", "success")

    return render_template("index.html", title="gMenu", form=form)

@app.route("/basic", methods=["GET", "POST"])
def basic():
    form = forms.HomePage()
    if form.validate_on_submit():
        update_bootstrap('bs-template1.xml')
    return render_template("temp.html", title="gMenu", form=form)


@app.route("/about")
def about():
    return render_template("temp.html", title="gAbout")


@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("temp.html", title="gMenu")


# If run from the command line
if __name__ == "__main__":
    app.run(debug=True)