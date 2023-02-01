from flask import Flask, render_template, redirect, url_for,flash,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField,IntegerField,FloatField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'nithinskey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class carts(db.Model):
   id = db.Column(db.Integer, primary_key = True)
   name = db.Column(db.String(100))
   price = db.Column(db.Float(100))  
   quantity = db.Column(db.Float(100))
   total = db.Column(db.Float(100))



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class AdditemForm(FlaskForm):
   
    name = StringField('name', validators=[InputRequired(), Length(min=4, max=15)])
    price = FloatField('Price', validators=[InputRequired()])
    quantity = IntegerField('quantity', validators=[InputRequired()])
    total = FloatField('total', validators=[InputRequired()])



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('add_item'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/add_item', methods = ['GET', 'POST'])
@login_required
def add_item():
   form = AdditemForm()
   if form.validate_on_submit():
        items = carts(name=form.name.data, price=form.price.data,quantity=form.quantity.data, total=form.total.data)
        db.session.add(items)
        db.session.commit()
        return redirect('show_all')

   return render_template('get_items.html',form=form)


@app.route('/show_all')
def show_all():
   return render_template('show_all.html', items = carts.query.all() )




@app.route("/delete/<int:id>",methods=['GET'])
def delete(id):
    item = carts.query.filter_by(id=id).first()
    #item = carts.query.get_or_404(id)

    db.session.delete(item)
    db.session.commit()
    return redirect(url_for("show_all"))
        
 
   

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.secret_key='admin123'
    with app.app_context():
        db.create_all()
    app.run(debug = True)