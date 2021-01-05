from sqlalchemy import create_engine, asc
from database_setup import Base
from sqlalchemy.orm import sessionmaker
import json

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog App"

# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False},
                       echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
