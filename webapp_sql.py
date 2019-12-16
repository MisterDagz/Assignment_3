from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, Sequence
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()



class User(Base):
	__tablename__ = 'users'

	id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
	username = Column(String)
	password = Column(String)
	twofa = Column(String)

	salt = Column(String)


class History(Base):
	__tablename__ = 'history'
	id = Column(Integer, Sequence('history_id_seq'), primary_key=True)
	username = Column(String)
	text = Column(String)
	results = Column(String)


class WebSession(Base):
	__tablename__ = 'WebSession'
	id = Column(Integer, Sequence('log_id_seq'), primary_key=True)
	username = Column(String)
	cookie = Column(String)
	logintime = Column(DateTime)
	logouttime = Column(DateTime)


def create_tables():
	engine = create_engine('sqlite:///spellcheck.db', echo = True)
	# meta = MetaData()
	'''
	users = Table(
		'users', meta,
		Column('id', Integer, primary_key=True),
		Column('username', String),
		Column('password', String),
		Column('twofa', String),
		Column('salt', String)
	)

	history = Table(
		'history', meta,
		Column('id', Integer, primary_key=True),
		Column('username', String),
		Column('text', String),
		Column('results', String)
	)
	logs = Table(
		'logs', meta,
		Column('id', Integer, primary_key=True),
		Column('username', String),
		Column('login_time', DateTime),
		Column('logout_time', DateTime),
		Column('cookie', String)
	)
	'''
	
	Base.metadata.create_all(engine)
	Session = sessionmaker(bind=engine)
	return Session


