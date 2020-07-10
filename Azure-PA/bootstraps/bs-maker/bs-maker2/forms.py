from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo

class HomePage(FlaskForm):
    pahostname = StringField('PA Hostname', validators=[DataRequired()])
    paprivateip = StringField('PA Private IP', validators=[DataRequired()])
    paprivatenexthop = StringField('PA Private Next Hop Gateway IP', validators=[DataRequired()])
    papublicip = StringField('PA Public IP', validators=[DataRequired()])
    papublicnexthop = StringField('PA Public Next Hop Gateway IP', validators=[DataRequired()])
    submit = SubmitField('Build Bootstrap File')

# class LoginForm(FlaskForm):
#     pa_ip = StringField('IP Address', validators=[DataRequired(), Length(min=2,max=32)])
#     username = StringField('Username', validators=[DataRequired(), Length(min=2,max=32)])
#     password = PasswordField('Password', validators=[DataRequired(), Length(min=2,max=32)])

#     submit = SubmitField('Login')
#     remember = BooleanField('Remember Me')

# class PaPAN(FlaskForm):
#     pa = BooleanField('PA or PAN?')