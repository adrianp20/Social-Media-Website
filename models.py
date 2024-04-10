from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileRequired, FileAllowed

from flask_admin import AdminIndexView, expose
from flask import redirect, url_for, flash, request
from flask_login import current_user


db = SQLAlchemy()


class Follow(db.Model):
    __tablename__ = 'follow'
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key = True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key = True)
    followed_username = db.Column(db.String(80), nullable = False)
    
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    likes = db.relationship('Like', backref='user', lazy='dynamic')
    followed = db.relationship(
        'Follow', secondary='follow',
        primaryjoin=(Follow.follower_id == id),
        secondaryjoin=(Follow.followed_id == id),
        backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def follow(self, user):
        if not self.is_following(user):
            follow = Follow(follower_id=self.id, followed_id=user.id, followed_username = user.username)
            db.session.add(follow)

    def unfollow(self, user):
        follow = self.followed.filter(
            Follow.follower_id == self.id,
            Follow.followed_username == user.username
        ).first()
        if follow:
           db.session.delete(follow)

    def is_following(self, user):
        return self.followed.filter(
            Follow.followed_username == user.username,
            Follow.follower_id == self.id
        ).count() > 0

    def like_post(self, post):
        if not self.has_liked_post(post):
            like = Like(user_id=self.id, post_id=post.id)
            db.session.add(like)

    def unlike_post(self, post):
        like = self.likes.filter_by(post_id=post.id).first()
        if like:
            db.session.delete(like)

    def has_liked_post(self, post):
        return Like.query.filter(Like.user_id == self.id, Like.post_id == post.id).count() > 0
    
    def get_followed_posts(self):
        followed_users_ids = [follow.followed_id for follow in self.followed]
        followed_users_ids.append(self.id)
        return Post.query.filter(Post.user_id.in_(followed_users_ids)).order_by(Post.timestamp.desc()).all()
    
    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    likes = db.relationship('Like', backref='post', lazy='dynamic')
    image = db.Column(db.String(255))
    def like_count(self):
        return self.likes.count()

class Like(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)

# Function to add an admin user
def add_admin_user():
    if User.query.filter_by(username='admin').first() is None:
        admin_user = User(username='admin', first_name='Admin', last_name='User')
        admin_user.set_password('adminPassword')  # Replace with a strong password
        db.session.add(admin_user)
        db.session.commit()
        print('Admin user created successfully.')
    else:
        print('Admin user already exists.')