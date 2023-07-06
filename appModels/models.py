from background.config import BaseConfig
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Table,DateTime
from sqlalchemy.ext.automap import automap_base

Bases = automap_base()
Session = scoped_session(sessionmaker(
    autocommit=False, autoflush=False, bind=BaseConfig.engine))
Base = declarative_base()
Base.query = Session.query_property()
session = Session()





user_roles = Table('user_roles', Base.metadata,
                   Column('user_id', Integer, ForeignKey(
                       'users.id'), primary_key=True),
                   Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True), extend_existing=True)


class User(Base):
    """
    Tabela z kontami użytkowników::

        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        username = Column(String(25), unique=True, nullable=False)
        password = Column(String(), nullable=False)
        deleted = Column(Boolean(), default= "False")
        roles = relationship('roles', secondary=user_roles , back_populates='users')

        def __init__(self, username, password,deleted):
            self.username = username
            self.password = password
            self.deleted = deleted
            self.authenticated = True

    """

    __tablename__ = "users"
   # __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True)
    username = Column(String(25), unique=True, nullable=False)
    password = Column(String(), nullable=False)
    deleted = Column(Boolean(), default="False")
    roles = relationship('roles', secondary=user_roles, back_populates='users')

    def __init__(self, id, username, password, deleted):
        self.id = id
        self.username = username
        self.password = password
        self.deleted = deleted


class roles(Base):
    """
    Tabela z rolami::

        __tablename__ = 'roles'
        id = Column(Integer(), primary_key=True)
        role = Column(String(50), unique=True)
        users = relationship('User', secondary=user_roles, back_populates='roles')

        def __init__(self, role):
            self.role = role

    """
    __tablename__ = 'roles'
   # __table_args__ = {'extend_existing': True}
    id = Column(Integer(), primary_key=True)
    role = Column(String(50), unique=True)
    users = relationship('User', secondary=user_roles, back_populates='roles')

    def __init__(self, role):
        self.role = role



class JWTTokenBlocklist(Base):
    """
    Tabela do blokowania tokenów które jeszcze nie straciły ważności::

    """
    __tablename__ = "jwt_token_block_list"
    id = Column(Integer, primary_key=True)
    jwt_token = Column(String, nullable=False)
    created_at = Column(DateTime(), nullable=False)

    def __repr__(self):
        return f"Expired Token: {self.jwt_token}"

 

Bases.prepare()