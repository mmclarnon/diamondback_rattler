# https://cleverzone.medium.com/understanding-one-to-one-relationships-with-sqlalchemy-4348a307fdae
import datetime
from json import JSONEncoder
import enum
import uuid
import logging
logger = logging.getLogger( __name__ )

from sqlalchemy import create_engine,inspect,Enum
from sqlalchemy import Column, String, Text, PickleType, Float, Integer, Boolean, ForeignKey, DateTime, JSON, BigInteger
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
    location           = relationship( "Location", back_populates="victim", uselist=False )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )
    current_gateway    = mapped_column( String, default=None, nullable=True )
    targets            = relationship('Target', back_populates='victim', cascade='all, delete-orphan')
    launch_events      = relationship('LaunchEvent', back_populates='victim', cascade='all, delete-orphan')

    def __repr__( self ):
        return f"<Victim id=({self.id}) address=({self.name}) ip=({self.internet_facing_ip})>"

class LaunchEvent( Versioned, Base ):
    __tablename__ = 'launch_event'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    current_address    = mapped_column( String, default=None, nullable=True )
    network_interface  = mapped_column( String, default=None, nullable=True )
    network_gateway    = mapped_column( String, default=None, nullable=True )
    current_address    = mapped_column( String, default=None, nullable=True )        
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )
    victim_id          = Column(Integer, ForeignKey('victim.id'))
    victim             = relationship('Victim', back_populates='launch_events')
    location           = relationship('Location', back_populates='launch_events')    
    location_id        = Column(Integer, ForeignKey('location.id'))

class Target( Versioned, Base ):
    __tablename__ = 'target'
    id               = mapped_column( Integer, primary_key=True )
    address          = mapped_column( String, default=None, nullable=True )
    hardware_address = mapped_column( String, default=None, nullable=True )
    cpe              = mapped_column( String, default=None, nullable=True )
    discovery_method = mapped_column( String, default=None, nullable=True )
    connection       = mapped_column( String, default=None, nullable=True )    
    is_encoded       = mapped_column( Boolean, default=False )
    note             = mapped_column( Text, nullable=True, default=None )
    data             = mapped_column( JSON, nullable=True )
    created_date     = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated     = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )
    victim_id        = Column(Integer, ForeignKey('victim.id'))
    victim           = relationship('Victim', back_populates='targets')

    # One-to-Many relationship with TargetService
    # This creates a list of TargetService objects accessible via target.services
    services = relationship(
        "TargetService",
        back_populates="target",  # Bidirectional relationship
        cascade="all, delete-orphan",  # Cascade deletes
        lazy="dynamic",  # Load services dynamically (useful for large collections)
        order_by="TargetService.port"  # Order services by port
    )

    def __str__( self ):
        return self.address

    def __repr__( self ):
        return f"<Target id=({self.id}) address=({self.address}) victim=({self.victim})>"

class TargetService( Versioned, Base ):
    __tablename__ = 'target_service'
    id                 = mapped_column( Integer, primary_key=True )

    # Foreign key to Target (Many-to-One relationship)
    target_id = Column(
        Integer, 
        ForeignKey('target.id', ondelete='CASCADE'),  # Delete services when target is deleted
        nullable=False,
        index=True  # Index for faster joins
    )

    def __str__(self):
        return f"<Target:{self.name}>"

    name               = mapped_column( String, default=None, nullable=True )
    banner             = mapped_column( String, default=None, nullable=True )
    port               = mapped_column( Integer, default=0, nullable=True )
    protocol           = mapped_column( String, default=None, nullable=True )
    cpe                = mapped_column( String, default=None, nullable=True )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    target_id          = Column(Integer, ForeignKey('target.id'))

    # Many-to-One relationship with Target
    # This creates a Target object accessible via service.target
    target = relationship(
        "Target",
        back_populates="services",  # Bidirectional relationship
        lazy="joined"  # Eagerly load target when loading service
    )

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
    location_id        = mapped_column(Integer, ForeignKey('location.id'), default=None, nullable = True)
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class Credential( Versioned, Base ):
    __tablename__ = 'credential'
    id                 = mapped_column( Integer, primary_key=True )
    name               = mapped_column( String, default=None, nullable=True )
    value              = mapped_column( String, default=None, nullable=True )
    service            = mapped_column( String, default=None, nullable=True )
    created_date       = mapped_column( DateTime, default=datetime.datetime.utcnow )
    last_updated       = mapped_column( DateTime, nullable=False, server_default=func.now(), onupdate=datetime.datetime.now() )

class Location(Versioned, Base):
    """SQLAlchemy model for storing IP address information"""
    __tablename__ = 'location'
    
    id = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip = mapped_column(String(45), nullable=False, index=True)  # Supports IPv4 and IPv6
    hostname = mapped_column(String(255))
    city = mapped_column(String(100))
    region = mapped_column(String(100))
    country = mapped_column(String(100))
    country_code = mapped_column(String(10))
    postal_code = mapped_column(String(20))
    latitude = mapped_column(Float)
    longitude = mapped_column(Float)
    timezone = mapped_column(String(100))
    org = mapped_column(String(255))  # Organization/ISP
    asn = mapped_column(String(50))  # Autonomous System Number
    raw_data = mapped_column(JSON)  # Store complete response as JSON
    query_timestamp = mapped_column(DateTime, default=datetime.datetime.utcnow)
    victim_id = Column(Integer, ForeignKey('victim.id'))
    victim = relationship( "Victim", back_populates="location" )
    
    launch_events      = relationship('LaunchEvent', back_populates='location', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Location(ip='{self.ip}', city='{self.city}', country='{self.country}')>"
    
    def to_dict(self):
        """Convert the model instance to a dictionary"""
        return {
            'id': self.id,
            'ip': self.ip,
            'hostname': self.hostname,
            'city': self.city,
            'region': self.region,
            'country': self.country,
            'country_code': self.country_code,
            'postal_code': self.postal_code,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'timezone': self.timezone,
            'org': self.org,
            'asn': self.asn,
            'query_timestamp': self.query_timestamp.isoformat() if self.query_timestamp else None
        }
