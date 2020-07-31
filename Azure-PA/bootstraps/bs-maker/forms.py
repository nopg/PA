from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo

class HomePage(FlaskForm):
    pahostname1 = StringField('PA1 Hostname', validators=[DataRequired()])
    paprivateip1 = StringField('PA1 Private IP', validators=[DataRequired()])
    paprivatenexthop1 = StringField('PA1 Private Next Hop Gateway IP', validators=[DataRequired()])
    papublicip1 = StringField('PA1 Public IP', validators=[DataRequired()])
    papublicnexthop1 = StringField('PA1 Public Next Hop Gateway IP', validators=[DataRequired()])

    pahostname2 = StringField('PA2 Hostname', validators=[DataRequired()])
    paprivateip2 = StringField('PA2 Private IP', validators=[DataRequired()])
    paprivatenexthop2 = StringField('PA2 Private Next Hop Gateway IP', validators=[DataRequired()])
    papublicip2 = StringField('PA2 Public IP', validators=[DataRequired()])
    papublicnexthop2 = StringField('PA2 Public Next Hop Gateway IP', validators=[DataRequired()])

    folder_name = StringField('Azure Storage Folder Name', validators=[DataRequired()])
    connection_string = StringField('Azure Storage Connection String', validators=[DataRequired()])
    submit = SubmitField('Build Bootstrap File')

# class LoginForm(FlaskForm):
#     pa_ip = StringField('IP Address', validators=[DataRequired(), Length(min=2,max=32)])
#     username = StringField('Username', validators=[DataRequired(), Length(min=2,max=32)])
#     password = PasswordField('Password', validators=[DataRequired(), Length(min=2,max=32)])

#     submit = SubmitField('Login')
#     remember = BooleanField('Remember Me')

# class PaPAN(FlaskForm):
#     pa = BooleanField('PA or PAN?')