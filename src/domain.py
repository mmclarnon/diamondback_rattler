import datetime
from json import JSONEncoder
import enum
import uuid
import logging
logger = logging.getLogger( __name__ )

from sqlalchemy import create_engine,inspect,Enum
from sqlalchemy import String, Text, PickleType, Float, Integer, Boolean, ForeignKey, DateTime, JSON, BigInteger
from sqlalchemy_utils import IPAddressType
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import sessionmaker,relationship, backref
from sqlalchemy.sql import func
from ipaddress import IPv4Address

from history_meta import Versioned

class Base(DeclarativeBase):
    pass

metadata = Base.metadata

def object_as_dict( obj ):
    resulting_dict = { c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs }

    if 'created_date' in resulting_dict:
        resulting_dict['created_date'] = None
    
    if 'last_modified_date' in resulting_dict:
        resulting_dict['last_modified_date'] = None

    if 'last_scan_date' in resulting_dict:
        resulting_dict['last_scan_date'] = None

    return resulting_dict

class Victim( Versioned, Base ):
    __tablename__ = 'victim'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    internet_facing_ip = mapped_column( String, default=None, nullable=True )
    has_internet       = mapped_column( Boolean, default=False )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class LaunchEvent( Versioned, Base ):
    __tablename__ = 'launch_event'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class Target( Versioned, Base ):
    __tablename__ = 'target'
    id               = mapped_column( Integer, primary_key=True )
    address          = mapped_column( String, default=None, nullable=True )
    hardware_address = mapped_column( String, default=None, nullable=True )
    cpe              = mapped_column( String, default=None, nullable=True )
    discovery_method = mapped_column( String, default=None, nullable=True )
    is_encoded       = mapped_column( Boolean, default=False )
    note             = mapped_column( Text, nullable=True, default=None )
    data             = mapped_column( JSON, nullable=True )
    created_date     = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated     = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )
    services         = relationship("TargetService", back_populates="victim")

class TargetService( Versioned, Base ):
    __tablename__ = 'target_service'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    banner             = mapped_column( String, default=None, nullable=True )
    port               = mapped_column( Integer, default=0, nullable=True )
    cpe                = mapped_column( String, default=None, nullable=True )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    victim_id          = mapped_column(Integer, ForeignKey('target.id'), default=None, nullable = True)
    victim             = relationship("Target", back_populates="services")
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class Command( Versioned, Base ):
    __tablename__ = 'command'
    id               = mapped_column( Integer, primary_key=True )
    name             = mapped_column( String, default=None, nullable=True )
    value            = mapped_column( String, default=None, nullable=True )    
    service          = mapped_column( String, default=None, nullable=True )
    cpe              = mapped_column( String, default=None, nullable=True )
    created_date     = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated     = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class PlatformAction( Versioned, Base ):
    __tablename__ = 'platform_action'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    input              = mapped_column( String, default=None, nullable=True )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )