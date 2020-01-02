from models import User, Spell_Query, Login_Event, db
from flask_bcrypt import Bcrypt
from datetime import datetime
# import pytest

bcrypt = Bcrypt()

def test_new_user():
	''' Tests instantiation of new user'''

	CONST_USERNAME = "testUsername"
	CONST_PASSWORD = "testPassword@123"
	CONST_2FA = "1111111111"

	PW_HASH = bcrypt.generate_password_hash(CONST_PASSWORD, 12)
	TWO_FA_HASH = bcrypt.generate_password_hash(CONST_2FA, 12)

	newUser = User(username=CONST_USERNAME, pswd_hash=PW_HASH,
				two_fa_hash=TWO_FA_HASH)
	assert newUser.username == CONST_USERNAME
	assert newUser.pswd_hash == PW_HASH
	assert newUser.two_fa_hash == TWO_FA_HASH

def test_new_spell_query():
	''' Tests instantiation of new Spell Query'''
	
	CONST_USER_ID = 999
	CONST_QUERY_TEXT = "take a sad sogn and make it betta"
	CONST_QUERY_RESULT = "sogn, betta"
	
	newSpellQuery = Spell_Query(query_text = CONST_QUERY_TEXT,
								query_result = CONST_QUERY_RESULT,
								user_id = CONST_USER_ID)

	assert newSpellQuery.query_text == CONST_QUERY_TEXT
	assert newSpellQuery.query_result == CONST_QUERY_RESULT
	assert newSpellQuery.user_id == CONST_USER_ID

def test_new_login_event():
	''' Tests instantiation of new login event'''
	CONST_LOGIN_TIMESTAMP = datetime.now()
	CONST_USER_ID = 111
	newLoginEvent = Login_Event(user_id=CONST_USER_ID,
						login_timestamp=CONST_LOGIN_TIMESTAMP)

	assert newLoginEvent.login_timestamp == CONST_LOGIN_TIMESTAMP
	assert newLoginEvent.user_id == CONST_USER_ID

test_new_user()
test_new_spell_query()
test_new_login_event()
