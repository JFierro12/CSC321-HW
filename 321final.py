import os
import logging
from datetime import datetime
from flask import Flask, render_template_string, redirect, url_for, flash, request, jsonify, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

logging.basicConfig(filename='mingle.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mingle.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

project_members = db.Table('project_members',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role', db.String(50))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    bio = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.String(120), nullable=True)

    threads = db.relationship('Thread', backref='author', lazy='dynamic')
    replies = db.relationship('Reply', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(140), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tags = db.Column(db.String(100))

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UpdateProfileForm(FlaskForm):
    bio = TextAreaField('Bio')
    picture = FileField('Profile Picture')
    submit = SubmitField('Update Profile')

class ThreadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags')
    submit = SubmitField('Post Thread')

class ReplyForm(FlaskForm):
    body = TextAreaField('Reply', validators=[DataRequired()])
    submit = SubmitField('Post Reply')

class ProjectUpdateForm(FlaskForm):
    update_text = TextAreaField('Update', validators=[DataRequired()])
    project_file = FileField('File')
    submit = SubmitField('Update')

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MingleAI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-color: #ffffff;
            --text-color: #212529;
            --card-bg: #f8f9fa;
            --nav-bg: #212529;
        }
        [data-theme="dark"] {
            --bg-color: #121212;
            --text-color: #e0e0e0;
            --card-bg: #1e1e1e;
            --nav-bg: #000000;
        }
        body { background-color: var(--bg-color); color: var(--text-color); transition: 0.3s; }
        .card { background-color: var(--card-bg); color: var(--text-color); border-color: #444; }
        .navbar { background-color: var(--nav-bg) !important; }
        .profile-img { width: 150px; height: 150px; object-fit: cover; border-radius: 50%; border: 3px solid #0d6efd; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">MingleAI</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="#" onclick="toggleTheme()">🌓 Theme</a></li>
                    
                    {% if current_user.is_authenticated %}
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('profile') }}">Profile</a></li>
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('new_thread') }}">New Thread</a></li>
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
                    {% else %}
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {{ content|safe }}
        
    </div>
    <script>
        function toggleTheme() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }
        if(localStorage.getItem('theme') === 'dark') {
            document.body.setAttribute('data-theme', 'dark');
        }
    </script>
</body>
</html>
"""

PROFILE_CONTENT = """
    <div class="row">
        <div class="col-md-4 text-center">
            <div class="card mb-4">
                <div class="card-body">
                    {% if current_user.profile_pic %}
                        <img src="{{ url_for('uploaded_file', filename=current_user.profile_pic) }}" class="profile-img mb-3" alt="Profile">
                    {% else %}
                        <div style="width: 150px; height: 150px; background-color: #ccc; border-radius: 50%; margin: 0 auto; display: flex; align-items: center; justify-content: center; font-size: 50px; color: #fff;">?</div>
                    {% endif %}
                    
                    <h4>{{ current_user.username }}</h4>
                    <p class="text-muted">{{ current_user.email }}</p>
                    {% if current_user.is_admin %}
                        <span class="badge bg-danger mb-2">ADMINISTRATOR</span>
                    {% endif %}
                    <p>{{ current_user.bio if current_user.bio else "No bio yet." }}</p>
                    <a href="{{ url_for('edit_profile') }}" class="btn btn-outline-primary btn-sm">Edit Profile</a>
                </div>
            </div>
        </div>
        
        <div class="col-md-8">
            <h3>My Threads</h3>
            {% for thread in threads %}
                <div class="card mb-2">
                    <div class="card-body d-flex justify-content-between align-items-center">
                        <a href="{{ url_for('thread_detail', thread_id=thread.id) }}" style="color: var(--text-color);">{{ thread.title }}</a>
                        <form action="{{ url_for('delete_thread', thread_id=thread.id) }}" method="POST" style="display:inline;">
                            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this thread?')">Delete</button>
                        </form>
                    </div>
                </div>
            {% else %}
                <p>You haven't posted any threads yet.</p>
            {% endfor %}

            <hr class="mt-5">
            <div class="alert alert-warning">
                <h4>Danger Zone</h4>
                <p>Deleting your account will remove all your data permanently.</p>
                <form action="{{ url_for('delete_account') }}" method="POST" onsubmit="return confirm('Are you sure? This cannot be undone.');">
                    <button type="submit" class="btn btn-danger">Delete Account</button>
                </form>
            </div>
        </div>
    </div>
"""

EDIT_PROFILE_CONTENT = """
    <div class="col-md-8 offset-md-2">
        <h3>Edit Profile</h3>
        <form method="POST" enctype="multipart/form-data">
            {{ form.hidden_tag() }}
            <div class="mb-3">
                {{ form.bio.label(class="form-label") }}
                {{ form.bio(class="form-control", rows="3") }}
            </div>
            <div class="mb-3">
                {{ form.picture.label(class="form-label") }}
                {{ form.picture(class="form-control") }}
            </div>
            {{ form.submit(class="btn btn-primary") }}
            <a href="{{ url_for('profile') }}" class="btn btn-secondary">Cancel</a>
        </form>
    </div>
"""

THREAD_CONTENT = """
    <div class="card mb-4">
        <div class="card-body">
            <div class="d-flex align-items-center mb-3">
                {% if thread.author.profile_pic %}
                    <img src="{{ url_for('uploaded_file', filename=thread.author.profile_pic) }}" style="width: 40px; height: 40px; border-radius: 50%; margin-right: 10px; object-fit: cover;">
                {% endif %}
                <div>
                    <h2 class="card-title m-0">{{ thread.title }}</h2>
                    <h6 class="text-muted m-0">By {{ thread.author.username }}</h6>
                </div>
            </div>
            
            <p class="card-text" style="white-space: pre-wrap;">{{ thread.body }}</p>
            
            {% if current_user.is_authenticated and (current_user.id == thread.author_id or current_user.is_admin) %}
                <form action="{{ url_for('delete_thread', thread_id=thread.id) }}" method="POST" class="mt-3">
                    <button type="submit" class="btn btn-danger btn-sm">Delete Thread</button>
                </form>
            {% endif %}
        </div>
    </div>
    
    <h4>Replies</h4>
    {% for reply in replies %}
        <div class="card mb-2"><div class="card-body">
            <div class="d-flex align-items-center mb-2">
                 {% if reply.author.profile_pic %}
                    <img src="{{ url_for('uploaded_file', filename=reply.author.profile_pic) }}" style="width: 30px; height: 30px; border-radius: 50%; margin-right: 10px; object-fit: cover;">
                {% endif %}
                <strong>{{ reply.author.username }}</strong>
            </div>
            <p>{{ reply.body }}</p>
        </div></div>
    {% else %}
        <p class="text-muted">No replies yet.</p>
    {% endfor %}

    {% if current_user.is_authenticated %}
        <hr>
        <h4>Leave a Reply</h4>
        <form method="POST">
            {{ form.hidden_tag() }}
            <div class="mb-3">{{ form.body(class="form-control", rows="3") }}</div>
            {{ form.submit(class="btn btn-primary") }}
        </form>
    {% endif %}
"""

INDEX_CONTENT = """
    <form action="{{ url_for('index') }}" method="GET" class="mb-4">
        <div class="input-group">
            <input type="text" name="q" class="form-control" placeholder="Search threads...">
            <button class="btn btn-secondary" type="submit">Search</button>
        </div>
    </form>
    <h2>Latest Discussions</h2>
    {% for thread in threads %}
        <div class="card mb-3">
            <div class="card-body">
                <div class="d-flex align-items-center mb-2">
                    {% if thread.author.profile_pic %}
                        <img src="{{ url_for('uploaded_file', filename=thread.author.profile_pic) }}" style="width: 30px; height: 30px; border-radius: 50%; margin-right: 10px; object-fit: cover;">
                    {% endif %}
                    <h5 class="card-title m-0"><a href="{{ url_for('thread_detail', thread_id=thread.id) }}" style="color: var(--text-color);">{{ thread.title }}</a></h5>
                </div>
                
                <h6 class="card-subtitle mb-2 text-muted">by {{ thread.author.username }}</h6>
                <p class="card-text">{{ thread.body[:100] }}...</p>
                {% if thread.tags %}
                    <span class="badge bg-info text-dark">{{ thread.tags }}</span>
                {% endif %}
            </div>
        </div>
    {% else %}
        <p>No threads found. Be the first to post!</p>
    {% endfor %}
"""

LOGIN_CONTENT = """
<div class="col-md-6 offset-md-3">
    <h3>Login</h3>
    <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">{{ form.email(class="form-control", placeholder="Email") }}</div>
        <div class="mb-3">{{ form.password(class="form-control", placeholder="Password") }}</div>
        {{ form.submit(class="btn btn-primary w-100") }}
    </form>
</div>
"""

REGISTER_CONTENT = """
<div class="col-md-6 offset-md-3">
    <h3>Register</h3>
    <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">{{ form.username(class="form-control", placeholder="Username") }}</div>
        <div class="mb-3">{{ form.email(class="form-control", placeholder="Email") }}</div>
        <div class="mb-3">{{ form.password(class="form-control", placeholder="Password") }}</div>
        <div class="mb-3">{{ form.confirm_password(class="form-control", placeholder="Confirm Password") }}</div>
        {{ form.submit(class="btn btn-primary w-100") }}
    </form>
</div>
"""

NEW_THREAD_CONTENT = """
<h3>New Thread</h3>
<form method="POST">
    {{ form.hidden_tag() }}
    <div class="mb-3">{{ form.title(class="form-control", placeholder="Thread Title") }}</div>
    <div class="mb-3">{{ form.body(class="form-control", rows="5", placeholder="Write your content here...") }}</div>
    <div class="mb-3">{{ form.tags(class="form-control", placeholder="Tags (comma separated)") }}</div>
    {{ form.submit(class="btn btn-primary") }}
</form>
"""

@app.errorhandler(404)
def not_found_error(error):
    return render_template_string(BASE_TEMPLATE, content="<h1>404 - Page Not Found</h1>"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template_string(BASE_TEMPLATE, content="<h1>500 - Server Error</h1>"), 500

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/")
def index():
    query = request.args.get('q')
    if query:
        threads = Thread.query.filter(Thread.title.ilike(f'%{query}%')).all()
    else:
        threads = Thread.query.order_by(Thread.created_at.desc()).all()
    inner = render_template_string(INDEX_CONTENT, threads=threads)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        if User.query.count() == 0:
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        logging.info(f"New user registered: {user.username}")
        flash('Account created! Login now.', 'success')
        return redirect(url_for('login'))
    inner = render_template_string(REGISTER_CONTENT, form=form)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login failed. Check details.', 'danger')
    inner = render_template_string(LOGIN_CONTENT, form=form)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    my_threads = Thread.query.filter_by(author_id=current_user.id).all()
    inner = render_template_string(PROFILE_CONTENT, threads=my_threads)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/profile/edit", methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.picture.data:
            f = form.picture.data
            filename = secure_filename(f"{current_user.id}_{f.filename}")
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_pic = filename
        
        current_user.bio = form.bio.data
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))
    
    elif request.method == 'GET':
        form.bio.data = current_user.bio

    inner = render_template_string(EDIT_PROFILE_CONTENT, form=form)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/account/delete", methods=['POST'])
@login_required
def delete_account():
    Thread.query.filter_by(author_id=current_user.id).delete()
    Reply.query.filter_by(author_id=current_user.id).delete()
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Account deleted.', 'info')
    return redirect(url_for('index'))

@app.route("/thread/new", methods=['GET', 'POST'])
@login_required
def new_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data, body=form.body.data, tags=form.tags.data, author=current_user)
        db.session.add(thread)
        db.session.commit()
        flash('Thread created!', 'success')
        return redirect(url_for('index'))
    inner = render_template_string(NEW_THREAD_CONTENT, form=form)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/thread/<int:thread_id>", methods=['GET', 'POST'])
def thread_detail(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    form = ReplyForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        reply = Reply(body=form.body.data, author=current_user, thread_id=thread.id)
        db.session.add(reply)
        db.session.commit()
        flash('Reply posted!', 'success')
        return redirect(url_for('thread_detail', thread_id=thread.id))
    replies = Reply.query.filter_by(thread_id=thread_id).all()
    inner = render_template_string(THREAD_CONTENT, thread=thread, replies=replies, form=form)
    return render_template_string(BASE_TEMPLATE, content=inner)

@app.route("/thread/<int:thread_id>/delete", methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if thread.author != current_user and not current_user.is_admin:
        abort(403)
    db.session.delete(thread)
    db.session.commit()
    flash('Thread deleted!', 'success')
    return redirect(url_for('profile'))

@app.route("/ai/query", methods=['POST'])
def ai_query():
    data = request.get_json()
    return jsonify({'response': f"AI suggestion for: {data.get('prompt')}"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)