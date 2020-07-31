from flask import Flask, render_template, url_for, flash, redirect, Markup
import forms

import bs_maker

app = Flask(__name__)
app.config['SECRET_KEY'] = 'abcd'


@app.route("/", methods=["GET"])
def index():
    # Create Form
    return render_template("index.html", title="gMenu")


@app.route("/bs_maker", methods=["GET", "POST"])
def bs_create():
    # Create Form
    form = forms.BS_CreatePage()

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
        msg, successOrFail = bs_maker.create_lb_bootstrap('static/bs-template1.xml', 'static/bs-template2.xml', **kwargs)

        if successOrFail == "success":
            msg += """

                To begin Azure deployment, <a href='https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fcnetpalopublic.blob.core.windows.net%2Farm-public%2Fgenlb.json'>click here.</a>
                    
                """
            msg = Markup(msg)
        flash(msg, successOrFail)

    return render_template("bs_create.html", title="PA Bootstrap Maker", form=form)

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