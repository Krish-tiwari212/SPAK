from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, EmailField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Signupform(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Subform(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    name = StringField('First Name', validators=[DataRequired()])

class AddForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired()])
    image_url = StringField('Product Image Link', validators=[DataRequired()])
    price = StringField('Price of product', validators=[DataRequired()])
    size = StringField('Size of Product', validators=[DataRequired()])
    description = StringField("A Short Description About Product", validators=[DataRequired()])

