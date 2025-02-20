from flask import Flask,render_template,redirect,url_for, request,session,flash
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

basedir=os.path.abspath(os.path.dirname(__file__))
app=Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "your_secret_key")
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+os.path.join(basedir,"app.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db=SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Products(db.Model):
    __tablename__="Products"

    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(100), nullable=False)
    desc=db.Column(db.String(200), nullable=False)
    price=db.Column(db.Integer, nullable=False)
    image=db.Column(db.String(200),nullable=False)

    def __init__(self, name, desc, price, image):
        self.name = name
        self.desc = desc
        self.price = price
        self.image = image

    def __repr__(self):
        return f" Name: {self.name} \n Desc: {self.desc} \n Price: $ {self.price} \n Image:{self.image}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def wrapper(fn):
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role != role:
                flash("Unauthorized access!", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/')
def home():
    users_list = User.query.all()
    return render_template('index.html', user=current_user, users_list=users_list)

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return render_template("admin_dashboard.html", user=current_user)
    return render_template("user_dashboard.html", user=current_user)

@app.route('/men')
def men():
    products = Products.query.all()
    return render_template('men.html', products=products, total_price=total_price)
def total_price():
    cart = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart)
    return total

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = Products.query.get_or_404(product_id)
    
    if 'cart' not in session:
        session['cart'] = []

    cart = session['cart']
    
    for item in cart:
        if item['id'] == product.id:
            item['quantity'] += 1
            break
    else:
        
        cart.append({
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'image': product.image,
            'quantity': 1
        })

    session.modified = True  

    return redirect(url_for('men')) 

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item['id'] != product_id]
        session.modified = True
    return redirect(url_for('men'))
@app.route('/purchase')
def purchase():
    return render_template('purchase.html')

@app.route("/role", methods=["GET", "POST"])
def role():
    if request.method == "POST":
        role = request.form.get("role")
        if role and current_user.email.endswith('@threadinn.com'):
            current_user.role = role
            db.session.commit()
            flash(f"Role updated to {role}!", "success")
            return redirect(url_for('home'))  # Go to the home page after role update
        
        flash("Error in updating role. Please try again.", "danger")
    
    return render_template('role.html')  # Render role.html for role assignment

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash("Login successful!", "success")
            if "@threadinn.com" in email:
                return redirect(url_for('role'))
            else:
                return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("register.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email, role="user")
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        if "@threadinn.com" in email:
            return redirect(url_for("role"))
        else:
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    session.pop('_flashes', None)  # Clear flash messages
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("register"))  # Redirect to sign-up page

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/admin")
@role_required("admin")
def admin():
    return render_template("admin.html", user=current_user)

if __name__ == '__main__':
    with app.app_context():
        db.drop_all() 
        db.create_all()
        admin_email = "krishna123@gmail.com"
        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            admin_user = User(name="Krishna", email=admin_email, role="admin")
            admin_user.set_password("123456")
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        if not Products.query.first():
            prod1 = Products("Captain America: Sam Soldier", "Oversized T-Shirts", 149, 'prod1_1.webp')
            prod2 = Products("Cotton Linen Stripes: Sienna", "Cotton Linen Shirts", 199, 'prod2_1.webp')
            prod3 = Products("Solids: Deep Sea Blue", "Oversized T-Shirts", 99, 'prod3.webp')
            prod4 = Products("Solids: Off White", "Oversized T-Shirts", 49, 'prod4.webp')
            prod5 = Products("Bloom: Ticket To Nowhere", "Holiday Shirts", 199, 'prod5.webp')
            prod6 = Products("Colourblock T-shirt: Varsity League", "Oversized T-Shirts", 99, 'prod6.webp')
            prod7 = Products("Black Panther: Wakanda Tribe", "Oversized T-Shirts", 89, 'prod7.webp')
            prod8 = Products("Peanuts: Keepin It Cool", "Oversized T-Shirts", 149, 'prod8.webp')
            db.session.add_all([prod1, prod2, prod3, prod4, prod5, prod6, prod7, prod8])
            db.session.commit()
    app.run(debug=True, port=7000)