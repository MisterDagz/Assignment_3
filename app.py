from flask import Flask, request, render_template, make_response, redirect, session
import random
import string
import subprocess
import os
from flask_wtf.csrf import CsrfProtect
from forms import *
from hashlib import sha256

mkdir_init_call = subprocess.Popen(["mkdir", "userdata/"]) 
mkdir_init_call.communicate()
app=Flask(__name__)


users = {}
cookies = {}

def randomString(stringLength=20):
	letters = string.ascii_lowercase
	letters += "0123456789"

	return ''.join(random.choice(letters) for i in range(stringLength))


app.config['SECRET_KEY'] = randomString(40)

def checkcookie(auth, userid):
	#enforces an allowed number of failures for cookie auth, if it exceeds 3, the current cookie for the user is invalid.
	if auth in cookies.keys():
		if cookies[auth]['username'] == userid:
			return True
		else:
			cookies[auth]['failurecount'] += 1
		if cookies[auth]['failurecount'] >=3:
			cookies.pop(auth, None)
	
	if userid in users:
		cookie = users[userid].get('cookie', None)
		if cookie is not None:
			cookies[cookie]['failurecount'] +=1 
			if cookies[auth]['failurecount'] >=3:
				cookies.pop(auth, None)
	return False

@app.route('/')
def home():
	user=None
	#Prevents cookie enumeration
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	return render_template('base.html', title="Home", user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
	form=LoginForm(request.form)
	#if request.method == 'POST':
		# .get returns none if form value not there
	uname = request.form.get("uname")
	pword = request.form.get('pword')
	twofa = request.form.get('2fa')
	user=None
	if 'username' in session.keys():
		if 'auth' in session.keys():
			if checkcookie(session['auth'], session['username']):
				user = session['username']
	if uname is not None:
		if uname in users:
			return render_template('register.html', title="Register", message="""failure""", form=form, user=user)
		
		else:
			jblob = {"username": uname, "password": pword, "2fa": twofa}
			users[uname] = jblob
			
			return render_template('register.html', title="Register", message="""success""", form=form, user=user)
			
	#if request.method == 'GET':
	else:
		return render_template('register.html', title="Register", form=form,  user=user)
	
@app.route('/login', methods=['GET', 'POST'])
def login():
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

		if uname not in users:
			return render_template('login.html', title="Login", message="""Incorrect Username or Password""", form=form, user=user)
		else:
			if pword != users[uname]["password"]:
				return render_template('login.html', title="Login", message="""Incorrect Username or Password""", form=form, user=user)
			elif twofa != users[uname]["2fa"]:
				return render_template('login.html', title="Login", message="""Two-factor Authentication Failure, wrong code supplied""", form=form, user=user)
			else:
				resp = make_response(render_template('login.html', title="Login", message="""Success""",form=form, user=uname))
				auth_token = randomString(20)
				# Failure count is to check if someone is trying to enumerate the cookie for a user
				cookies[auth_token] = {'username':uname, 'failurecount':0}
				users[uname]['cookie'] = auth_token
				session['auth'] = auth_token
				session['username'] = uname
				return resp
			
	elif request.method=='GET':
		"""
		if request.cookies.get('auth') is not None:
			auth = request.cookies.get('auth')
			if auth in cookies.keys():
				if checkcookie(auth, cookies[auth]['username']):
					return redirect("/")
		"""
		return render_template('login.html', title="Login", form=form, user=user)
	
@app.route('/spell_check', methods=["GET", "POST"])
def spell_check():	
	form=SpellCheckForm(request.form)
	authorized = False
	user = None
	if 'auth' in session.keys():
		if session['auth'] is not None:
			auth = session['auth']
			if auth in cookies.keys():	
				uname = session['username']
				if uname is not None:
					if checkcookie(auth, uname):
						authorized = True
						user = session['username']
					else:
						return redirect("/")
				else:
					return redirect("/")
			else:
				return redirect("/")
		else:
			return redirect("/")
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
			
			return render_template('spell_check.html', title="Spell Check", textout=text, misspelled=miss, form=form, user=user)


if __name__=="__main__":
	
	csrf = CsrfProtect()
	csrf.init_app(app)

	#app.run()
