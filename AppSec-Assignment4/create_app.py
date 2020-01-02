from flask import Flask
import os
from databases import db
from flask_bcrypt import Bcrypt
from models import User

basedir = os.path.abspath(os.path.dirname(__file__))
bcrypt = Bcrypt()

def app_creator():
	app = Flask(__name__)

	app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
	
	app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
	
	secret_key = open("secret_key", "r").read().strip()

	csrf_secret_key = open("csrf_secret_key", "r").read().strip()
	
	app.config.update(dict(
	    SECRET_KEY=secret_key,
	    WTF_CSRF_SECRET_KEY=csrf_secret_key
	))

	db.init_app(app)

	with app.app_context():
		db.create_all()

		# admin_pswd = open("admin_pswd", "r").read().strip()
		# admin_2fa = open("admin_2fa", "r").read().strip()

		# pw_hash = bcrypt.generate_password_hash(admin_pswd, 12)
		
		# two_fa_hash = bcrypt.generate_password_hash(admin_2fa, 12)

		# admin = User(username = "admin", pswd_hash = pw_hash, 
		# 					two_fa_hash = two_fa_hash)

		# db.session.add(admin)
		# db.session.commit()	

	return app