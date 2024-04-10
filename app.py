import os
from flask import Flask, render_template, url_for, redirect, flash, request, send_from_directory
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from forms import RegistrationForm, LoginForm, PostForm
from models import User,Like, Post, db, Follow
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from wtforms.validators import InputRequired, EqualTo
from flask_wtf import FlaskForm

from models import db, add_admin_user
from flask_admin import Admin, AdminIndexView, expose

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_media.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not (current_user.is_authenticated and current_user.username == 'admin'):
            flash("You need to be an admin to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        return super(MyAdminIndexView, self).index()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

class UserCreateForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match.')])
    
class UserAdmin(ModelView):
    form_excluded_columns = ['password_hash']
    create_form = UserCreateForm
    def on_model_change(self, form, model, is_created):
        if is_created:
            model.password_hash = generate_password_hash(form.password.data)
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

admin = Admin(app, name='Bobcat Buzz Admin Page', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(UserAdmin(User, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()

    if request.method == 'POST':
        user_exists = User.query.filter_by(username=form.username.data).first()
        if user_exists:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', title='Register', form=form)

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, 
                    password_hash=hashed_password,
                    first_name=form.first_name.data,
                    last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user and check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        except Exception as e:
            flash('An error occurred during login. Please try again.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/home')
@login_required
def home():
    form = PostForm()
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('home.html', posts=posts, form=form)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_post')
@login_required
def create_post():
    form = PostForm()
    return render_template('create_post.html', form=form)

@app.route('/view_feed')
@login_required
def view_feed():
    show_followed = request.args.get('followed', 'false').lower() == 'true'
    
    if show_followed:
        # Assuming you have a method to get posts from followed users
        posts = current_user.get_followed_posts()
    else:
        posts = Post.query.order_by(Post.timestamp.desc()).all()
    
    return render_template('view_feed.html', posts=posts, show_followed=show_followed)


@app.route('/follow_users', methods=['GET', 'POST'])
@login_required
def follow_users():
    if request.method == 'POST':
        username = request.form.get('username')
        user_to_follow = User.query.filter_by(username=username).first()
        if user_to_follow and user_to_follow != current_user:
            current_user.follow(user_to_follow)
            db.session.commit()
            flash(f'You are now following {username}!', 'success')
        else:
            flash('User not found or cannot follow yourself.', 'danger')
    
    followed_users = current_user.followed.all()
    return render_template('follow_users.html', followed_users=followed_users)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(content=form.content.data, user_id=current_user.id)
        if form.image.data:
            filename = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            post.image = filename
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
    return redirect(request.referrer)

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user_to_unfollow = User.query.filter_by(username=username).first()
    if user_to_unfollow:
        current_user.unfollow(user_to_unfollow)
        db.session.commit()
        flash('You are no longer following {}.'.format(username))
    else:
        flash('User not found.')
    return redirect(url_for('follow_users'))

@app.route('/like/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post is None:
        flash('Post not found.')
        return redirect(url_for('index'))
    current_user.like_post(post)
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/unlike/<int:post_id>')
@login_required
def unlike_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post is None:
        flash('Post not found.')
        return redirect(url_for('index'))
    current_user.unlike_post(post)
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author.id != current_user.id:
        flash('You cannot delete this post.', 'danger')
        return redirect(url_for('home'))
    Like.query.filter_by(post_id=post_id).delete()
    db.session.delete(post)
    db.session.commit()
    return redirect(request.referrer or url_for('home'))

@app.route('/admin')
def admin_dashboard():
    return redirect(url_for('admin.index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_admin_user() 
    app.run(debug=True)
