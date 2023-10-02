from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from . import ConfigParserCrypt as configparser
import os


# Let's get the configuration file and read it
config = configparser.ConfigParserCrypt()
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
parser = config.config_read(config_path)  # Read the configuration file


# Get the database parameters
db_host = parser.get('Database', 'db_host')
db_port = parser.get('Database', 'db_port')
db_username = parser.get('Database', 'db_username_encrypted')
db_password = parser.get('Database', 'db_password_encrypted')
db_name = parser.get('Database', 'db_name')
db_pool_size = parser.getint('Database', 'db_pool_size')
db_ca_path = parser.get('Database', 'db_ca_path')


#Get the log level from the config file
echo_boolean = parser.getboolean('Database', 'debug', fallback='INFO')
    

# Create a connection string
connection_string = f"postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"

# Create an engine with connection pooling and SSL validation
engine = create_engine(
    connection_string,
    pool_size=db_pool_size,  # Example of a connection pool size
    max_overflow=0,
    # Enable SSL validation
    connect_args={
        'sslmode': 'require',
        'sslrootcert': db_ca_path  # Path to the CA file
    },
    echo=echo_boolean,  # Print SQL queries for debugging (optional)
).execution_options()

# Create a session factory
session_factory = sessionmaker(bind=engine)
DBSession = scoped_session(session_factory)
