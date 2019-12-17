from flask import Flask, request, render_template, make_response, redirect, session
import random
import string
import subprocess
import os
from flask_wtf.csrf import CSRFProtect
from forms import *
from hashlib import sha256
from webapp_sql import *
mkdir_init_call = subprocess.Popen(["mkdir", "userdata/"]) 
mkdir_init_call.communicate()
app=Flask(__name__)
from datetime import datetime



def hash_func(password, salt):
	pass_hash = sha256()
	salted = password + salt
	pass_hash.update(salted.encode('utf-8', "ignore"))
	hashed = pass_hash.hexdigest()
	return hashed

def randomString(stringLength=20):
	letters = string.ascii_lowercase
	letters += "0123456789"

	return ''.join(random.choice(letters) for i in range(stringLength))


app.config['SECRET_KEY'] = randomString(40)

def checkcookie(auth, userid):
	sql_session = db_session()
	results = sql_session.query(WebSession.username).filter(WebSession.username == userid, WebSession.cookie == auth).all()
	if len(results) > 0:
		sql_session.close()
		return True
	sql_session.close()
	return False



db_session = create_tables()

def admin_init():
	sql_session = db_session()
	if len(sql_session.query(User.username).filter(User.username=="admin").all()) >0:
		sql_session.close()
		return
	else:
		pre_hash = "Administrator@1"
		salt =   randomString(8)
		password= hash_func(pre_hash, salt)
		admin_user = User(username="admin", password=password, twofa="12345678901", salt=salt)
		sql_session.add(admin_user)
		sql_session.commit()
		sql_session.close()
		return
admin_init()
@app.route('/')
def home():
	user=None
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	return render_template('base.html', title="Home", user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
	sql_session = db_session()
	form=LoginForm(request.form)
	user=None
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	if request.method == 'POST':
		# .get returns none if form value not there
		uname = request.form.get("uname")
		pword = request.form.get('pword')
		twofa = request.form.get('2fa')
		if uname is not None:
			user_res = sql_session.query(User.username).filter(User.username == uname).all()
			if len(user_res) > 0:
				sql_session.close()
				return render_template('register.html', title="Register", message="""failure""", form=form, user=user)
			
			else:
				salt =   randomString(8)
				password = hash_func(pword, salt)
				new_user = User(username=uname, password=password, twofa=twofa, salt=salt)
				sql_session.add(new_user)
				sql_session.commit()
				sql_session.close()
				return render_template('register.html', title="Register", message="""success""", form=form, user=user)
				
	if request.method == 'GET':
	#else:
		sql_session.close()
		return render_template('register.html', title="Register", form=form,  user=user)
	
@app.route('/login', methods=['GET', 'POST'])
def login():
	sql_session = db_session()
	uname = request.form.get("uname")
	pword = request.form.get('pword')
	twofa = request.form.get('2fa')
	form=LoginForm(request.form)
	user=None
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	if request.method =='POST' :
		# .get returns none if form value not there
		user_query = sql_session.query(User.username, User.salt).filter(User.username == uname)
		user_res = user_query.first()
		
		if user_res == None:
			sql_session.close()
			return render_template('login.html', title="Login", message="""Incorrect Username or Password""", form=form, user=user)
		else:
			salt = user_res.salt
			hashed = hash_func(pword, salt)
			pass_query = sql_session.query(User.username).filter(User.username == uname, User.password == hashed)
			pass_res = pass_query.all()
			if len(pass_res) == 0:
				sql_session.close()
				return render_template('login.html', title="Login", message="""Incorrect Username or Password""", form=form, user=user)
			else:
				twofa_query = sql_session.query(User.username).filter(User.username == uname, User.password == hashed, User.twofa == twofa)
				twofa_res = twofa_query.all()
				if len(twofa_res) == 0:
					sql_session.close()
					return render_template('login.html', title="Login", message="""Two-factor Authentication Failure, wrong code supplied""", form=form, user=user)
				else:
					resp = make_response(render_template('login.html', title="Login", message="""Success""",form=form, user=uname))
					auth_token = randomString(20)
					login_event = WebSession(username=uname, cookie=auth_token, logintime=datetime.now(), logouttime=None)
					sql_session.add(login_event)
					sql_session.commit()
					session['auth'] = auth_token
					session['username'] = uname
					sql_session.close()
					return resp
			
	elif request.method=='GET':
		"""
		if request.cookies.get('auth') is not None:
			auth = request.cookies.get('auth')
			if auth in cookies.keys():
				if checkcookie(auth, cookies[auth]['username']):
					return redirect("/")
		"""
		sql_session.close()
		return render_template('login.html', title="Login", form=form, user=user)

@app.route('/login_history', methods=["GET", "POST"])
def login_history():
	user=None
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	if user is None:
		return redirect("/")
	admin = False
	if user == "admin":
		admin = True
	else:
		return redirect("/")
	form=LogForm(request.form)
	if request.method == "POST":
		sql_session = db_session()
		uname = request.form.get("userid")
		results = sql_session.query(WebSession.id, WebSession.logintime, WebSession.logouttime).filter(WebSession.username==uname).all()
		list_of_session = []
		for row in results:
			child_dictionary = {}
			child_dictionary['logintime'] = row.logintime
			child_dictionary['event_num'] = row.id
			child_dictionary['logouttime'] = row.logouttime
			if child_dictionary['logouttime'] is None:
				child_dictionary['logouttime'] = "N/A"
			list_of_session.append(child_dictionary)
		return render_template('login_history.html', title="Login Logs", form=form, user=user, results=list_of_session)
	else:
		return render_template('login_history.html', title="Login Logs", form=form, user=user)
	
	

@app.route('/logout', methods=["GET","POST"])
def logout():
	sql_session = db_session()
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				now = datetime.now()
				sql_session.query(WebSession).filter(WebSession.username==session['username'], WebSession.cookie==session['auth']).update({WebSession.cookie:None, WebSession.logouttime:now},synchronize_session=False)
				sql_session.commit()
				session.clear()
				sql_session.close()
				return redirect("/")
	sql_session.close()
	return redirect("/")
@app.route('/spell_check', methods=["GET", "POST"])
def spell_check():	
	form=SpellCheckForm(request.form)
	authorized = False
	user = None
	auth = session.get('auth', None)
	uname = session.get('username', None)
	if auth is None or uname is None:
		return redirect("/")
	else:
		if checkcookie(auth, uname):
			authorized = True
			user = uname
		else:
			return redirect("/")
	
	if authorized:
		
		if request.method == 'GET':
			return render_template('spell_check.html', title="Spell Check", form=form, user=user)
		if request.method == 'POST':
			text = request.form.get('inputtext')
			if text is None:
				text = ""
			#Prevent Resource DOS (max file length is 10,000,000 bytes (10 MB)
			if len(text) > 10000000:
				text = text[:9999999]
			#exepath = os.path.expanduser('~/a.out')
			#Prevents command injection, and DOS for users
			user_hash = sha256()
			user_hash.update(user.encode('utf-8', "ignore"))
			hash_val = user_hash.hexdigest()
			mkdir_call = subprocess.Popen(["mkdir", "userdata/" + hash_val], stdout=subprocess.PIPE)
			mkdir_call.communicate()
			f = open("userdata/" + hash_val + "/test.txt", "w")
			f.write(text)
			f.close()
			MyOut = subprocess.Popen(["./a.out", "userdata/" + hash_val +'/test.txt', 'wordlist.txt'], stdout=subprocess.PIPE)
			
			stdout,stderr = MyOut.communicate()
			miss = stdout.decode('utf-8')
			miss = miss.replace('\n',',')
			if len(miss) >0:
				if miss[len(miss)-1] ==",":
					miss = miss[:len(miss)-1]
			history_row = History(username=user, text=text, results=miss)
			sql_session.add(history_row)
			return render_template('spell_check.html', title="Spell Check", textout=text, misspelled=miss, form=form, user=user)


if __name__=="__main__":
	
	csrf = CSRFProtect()
	csrf.init_app(app)

	#app.run()
