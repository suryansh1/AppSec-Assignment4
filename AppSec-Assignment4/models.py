from databases import db
from datetime import datetime

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	# password = db.Column(db.String(20))
	pswd_hash = db.Column(db.String(128), nullable=False)
	# two_fa = db.Column(db.String(10), nullable=False)
	two_fa_hash = db.Column(db.String(128), nullable=False)

	spell_queries = db.relationship('Spell_Query', backref='author', lazy='dynamic')
	login_events = db.relationship('Login_Event', backref='logger', lazy='dynamic')

	# def __init__(self, username, pswd_hash, two_fa_hash):
	# 	self.username = username
	# 	self.pswd_hash = pswd_hash
	# 	self.two_fa_hash = two_fa_hash


	def __repr__(self):
		return '<User  >'.format( self.username)



class Spell_Query(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	query_text = db.Column(db.String(140))
	query_result = db.Column(db.String(140))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	def __repr__(self):
		return '<Spell_Query {}>'.format(self.query_text)


class Login_Event(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	login_timestamp = db.Column(db.DateTime, default=datetime.now())
	logout_timestamp = db.Column(db.DateTime)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	def __repr__(self):
	    return '<Login_Event {}>'.format(self.login_timestamp)