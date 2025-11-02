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

class Credential( Base ):
    __tablename__ = 'credential'
    id                = mapped_column( Integer, primary_key=True )
    value             = mapped_column( String, default=None, nullable=True )
    is_encoded        = mapped_column( Boolean, default=False )
    note              = mapped_column( Text, nullable=True, default=None )
    data              = mapped_column( JSON, nullable=True )

    is_valid          = mapped_column( Boolean, default=False )


    length            = mapped_column( Integer, default=0 )
    encoded_length    = mapped_column( Integer, default=0 )

    created_date      = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_scan_date    = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )