from flask import Flask, redirect, render_template, request, session, abort, url_for
import os, subprocess, re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired
from flask_bcrypt import Bcrypt
from databases import db
from create_app import app_creator
from models import User, Spell_Query, Login_Event
from datetime import datetime


app = app_creator()

bcrypt = Bcrypt()

# users_dict = {}
# session['logged_in'] = False


class RegistrationForm(FlaskForm):
	uname = StringField("username")
	pword = PasswordField("password")
	two_fa = PasswordField("two_factor_authentication", id='2fa')

class LoginForm(FlaskForm):
	uname = StringField("username")
	pword = PasswordField("password")
	two_fa = PasswordField("two_factor_authentication", id='2fa')

class SpellCheckForm(FlaskForm):
	inputtext = TextAreaField("inputtext")

class LoginHistoryForm(FlaskForm):
	userid = StringField("userid", id = "userid")

class HistoryAdminForm(FlaskForm):
	uname = StringField('username', id='userquery')

@app.route("/")
def home():
	return redirect(url_for('spell_check'))

@app.route("/spell_check", methods=['POST', 'GET'])
def spell_check():
	
	if 'username' not in session:
	# if not session.get('logged_in'):

		return redirect(url_for('login'))

	else:
		# print(session.get('username') + " is logged in.")

		form = SpellCheckForm()

		if request.method == 'POST':
			inputtext = request.form['inputtext']

			# print(inputtext)

			with open("test.txt",'w', encoding = 'utf-8') as f:
				f.write(inputtext)

			out = subprocess.check_output(["./a.out", "test.txt", "wordlist.txt"])
			
			# processed_output = ",".join(out.decode().split('\n'))
			processed_output = out.decode().replace('\n', ',')

			print(processed_output)

			os.remove("test.txt")

			user = User.query.filter_by(username = session['username']).first()

			newSpellQuery = Spell_Query(query_text = inputtext, query_result = processed_output,
											user_id = user.id)
			db.session.add(newSpellQuery)
			db.session.commit()

			return "<p id=textout>" + inputtext + "</p> </br> <p id=misspelled>" + processed_output\
					+"</p>"

		return render_template('spell_check.html', form = form)

@app.route('/register', methods=['POST', 'GET'])
def register():
	form = RegistrationForm()

	# print (form.errors)
	# print(	session['logged_in'] )

	if request.method == 'POST':
		uname = request.form['uname']
		pword = request.form['pword']
		two_fa = request.form['two_fa']

		if (len(uname) > 0 and  len(pword) > 0 and len(two_fa) > 0 and 
		len(uname) < 20 and  len(pword)<20 and len(two_fa) < 20):

			# Encrypt password and 2fa, store in dict
			pw_hash = bcrypt.generate_password_hash(pword, 12)
			two_fa_hash = bcrypt.generate_password_hash(two_fa, 12)

			newUser = User(username = uname, pswd_hash = pw_hash, 
						two_fa_hash = two_fa_hash)

			db.session.add(newUser)
			db.session.commit()


			# users_dict[uname] = [pw_hash, two_fa_hash]

			return " <a href=\"/login\" id=success >Registration Success, Please Login </a> <br> \
			 <a href = \"/register\" > Register another user </a>"

		else :
			return "<a href id=success >Registration Failure, Try again </a>"


	return render_template('register.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():

	form = LoginForm()
	# print(	session['logged_in'] )
	if request.method == 'POST':

		uname = request.form['uname']
		pword = request.form['pword']
		two_fa = request.form['two_fa']
	
		# Validate username, password and 2fa
		user = User.query.filter_by(username=uname).first()
		# user = users_dict[uname]
		# if uname in users_dict.keys():
		
		if user is not None:
			# pw_hash = users_dict[uname][0]
			pw_hash = user.pswd_hash

			# two_fa_hash = users_dict[uname][1]
			two_fa_hash = user.two_fa_hash			
			if bcrypt.check_password_hash(pw_hash, pword) and bcrypt.check_password_hash(two_fa_hash, two_fa) :
			
				session['username'] = uname

				# Retrieve time and add to logs DB
				newLoginEvent = Login_Event(user_id = user.id)
				db.session.add(newLoginEvent)
				db.session.commit()

				return " <a href=\"/spell_check\" id=result >Login Success </a>"

			else:
				return " <a href=\"/login\" id=result >Login Failure </a>"
		else:
				return " <a href=\"/login\" id=result >Login Failure </a>"
		
	return render_template('login.html', form=form)


@app.route("/logout", methods=['POST', 'GET'])
def logout():
	# session['logged_in'] = False

	if 'username' not in session:
		return home()

	user = User.query.filter_by(username=session['username']).first()
	
	
	# latestLoginEvent = Login_Event.query.filter_by(user_id = user.id).order_by(Login_Event.id.desc()).first()
	latestLoginEvent = Login_Event.query.filter_by(user_id = user.id).order_by(Login_Event.id.desc()).first()
	

	latestLoginEvent.logout_timestamp = datetime.now()
	print("Logging out " + str(user.username))
	
	# print(str(latestLoginEvent.login_timestamp))
	# print(str(latestLoginEvent.logout_timestamp))

	db.session.commit()
	session.pop('username', None)

	return home()

@app.route("/login_history", methods=['POST', 'GET'])
def login_history():
	if 'username' not in session:
		return redirect(url_for('login'))

	if session['username'] != "admin":
		return redirect(url_for('login'))

	form = LoginHistoryForm()

	if request.method == 'POST':

		user = User.query.filter_by(username=request.form['userid']).first()

		if user is not None:
			extractedLoginEvents = user.login_events.all()
		

			print(extractedLoginEvents)

			return render_template('login_history.html', form=form, user=user,
									login_events=extractedLoginEvents)

	return render_template('login_history.html', form=form)	



@app.route("/history", methods=['POST', 'GET'])
def history():

	if 'username' not in session:
		return redirect(url_for('login'))

	if session['username'] == 'admin':

		form = HistoryAdminForm()
		if request.method == 'POST' :
			user = User.query.filter_by(username=request.form['uname']).first()
			extractedSpellQueries = user.spell_queries.all()
			return render_template('history-admin.html', form=form, user=user,
								numqueries=len(extractedSpellQueries), 
								spell_queries=extractedSpellQueries)
		else:
			return render_template('history-admin.html', form=form)
	else:
		user = User.query.filter_by(username=session['username']).first()
		extractedSpellQueries = user.spell_queries.all()
		return render_template('history.html', user=user,
			 numqueries=len(extractedSpellQueries),
			  spell_queries=extractedSpellQueries)

@app.route('/history/<query>', methods=['GET'])
def history_query(query):

	if 'username' not in session:
		return redirect(url_for('login'))

	loggedin_username = session['username']

	user = User.query.filter_by(username=loggedin_username).first()

	# query_id = re.findall('\d+', query)[0]
	# query_id = [int(s) for s in query.split() if s.isdigit()][0]
	query_id = ''.join([n for n in query if n.isdigit()])

	print("Query ID : " + query_id)
	
	is_allowed = False

	if loggedin_username == "admin":
		is_allowed = True		
		extractedSpellQuery = Spell_Query.query.filter_by(id=query_id).first()

	else : 

		# extractedSpellQueries = user.spell_queries.all()

		# for spell_query in extractedSpellQueries:
		# 	if query_id == spell_query.id:
		# 		is_allowed = True

		# 		extractedSpellQuery = spell_query
		
		extractedSpellQuery = Spell_Query.query.filter_by(id=query_id, user_id=user.id).first()

	# if not is_allowed:
	if extractedSpellQuery is None:
		return " <a href=\"/login\" id=result >You are not allowed to view this query</a>"

	return render_template('history_query.html',
				 spell_query=extractedSpellQuery)


if __name__ == "__main__":

	# app.config['SECRET_KEY'] = "someRandomSecretKeyHahahaha"
	# db.create_all()
	# print("Successfully created DB")
	app.run(debug=True, host='0.0.0.0')
	
	

