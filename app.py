import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    image_file = db.Column(db.String(150), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='posts', lazy=True)



# User Model (The Intelligence)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_pic = db.Column(db.String(150), default='default.png')

@app.route('/profile', methods=['GET', 'POST']) # This is the URL
@login_required
def profile():
    if request.method == 'POST':
        file = request.files.get('pic')
        if file:
            filename = f"user_{current_user.id}_{file.filename}"
            file.save(os.path.join('static/profile_pics', filename))
            current_user.profile_pic = filename
            db.session.commit()
            flash('Personnel File Updated!')
    return render_template('profile.html', user=current_user)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        content = request.form.get('content')
        file = request.files.get('post_image')
        filename = None
        
        if file:
            filename = f"post_{datetime.utcnow().timestamp()}_{file.filename}"
            file.save(os.path.join('static/post_pics', filename))
            
        new_post = Post(content=content, image_file=filename, author=current_user)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))

    # Get all posts, newest first
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    tf2_classes = ['scout', 'soldier', 'pyro', 'demoman', 'heavy', 'engineer', 'medic', 'sniper', 'spy']
    return render_template('index.html', posts=posts, classes=tf2_classes)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')  
        password = request.form.get('password')
        
        #Checks if username OR email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash('That name is already taken, maggot!')
            return redirect(url_for('signup'))
        
        if existing_email:
            flash('This email is already registered to another mercenary!')
            return redirect(url_for('signup'))
        
        #Create the user with the email included
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        user_to_add = User(username=username, email=email, password=hashed_pw)
        
        #Save to database
        try:
            db.session.add(user_to_add)
            db.session.commit()
            flash('Account created! Now log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Database error. The Engineer is working on it!')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            print(f"DEBUG: Login successful for {username}")
            return redirect(url_for('index'))
        else:
            print("DEBUG: Login failed - password or username mismatch")
            flash('Invalid credentials, Maggot!')
            # No redirect needed here, it will fall through to render_template below
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Mission Abandoned. You have been logged out.')
    return redirect(url_for('login'))



@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Security Check: Only the author can delete their own Intel
    if post.author != current_user:
        flash("You are not authorized to redact this Intel!")
        return redirect(url_for('index'))
    
    # If there is an image, you might want to delete the file too
    if post.image_file:
        image_path = os.path.join(app.root_path, 'static/post_pics', post.image_file)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(post)
    db.session.commit()
    flash('Intel has been successfully redacted.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # This builds the database file
    app.run(debug=True)