'''
Database Manager Module to to handle database oeprations using TinyDB.

'''

from tinydb import TinyDB, Query
from datetime import datetime, timedelta
import uuid
import os
from . import shared_constants
from pathlib import Path



class DatabaseManager:
    def __init__(self):
        '''
        Intialize database connection 
        '''

        # Check if the database file exists, if not create it
        self.db = TinyDB(shared_constants.DATABASE_FILE)
        # Initialize users table
        self.users_table = self.db.table(shared_constants.USERS_TABLE)
        # Initialize files tables
        self.files_table = self.db.table(shared_constants.FILES_TABLE)
        # Initialize sessions table
        self.sessions_table = self.db.table(shared_constants.SESSIONS_TABLE)

        # create a query object for user queries
        self.User = Query()

        # create a query object for file queries
        self.File = Query()

        # create a query object for session queries
        self.Session = Query()


# ---------------- User Management ---------------------------#

    def create_user(self, username, password_hash , salt , public_key, role = "user"):
        '''
        Method to create a new user in the database
        '''

        if self.user_exists(username):
            return None
        
        user_id = str(uuid.uuid4())
        user_record = {
            'user_id': user_id,
            'username': username,
            'password_hash': password_hash,
            'salt': salt,
            'public_key': public_key,
            'created_at': datetime.now().isoformat(),
            'role': role
        }

        # Insert the user record into the users table
        self.users_table.insert(user_record)
        return user_id

    def get_user(self, username):
        '''
        Method to get user details using username
        '''
        return self.users_table.get(self.User.username == username)

    def get_users(self):
        return self.users_table.all()
    
    def find_user_by_id(self, user_id):
        '''
        Method to find user by user id
        '''
        return self.users_table.get(self.User.user_id == user_id)
    
    def user_exists(self, username):
        '''
        Method to check if user already exists
        '''
        return self.users_table.contains(self.User.username == username)
    
    def update_login_time(self, username):
        '''
        Method to update the last login time of a user
        '''
        self.users_table.update({'last_login': datetime.now().isoformat()}, self.User.username == username)

    def delete_user(self, username):
        '''
        Method to delete a user from the database
        '''
        if not self.user_exists(username):
            return False

        # Delete the user session
        self.users_table.remove(self.Session.username == username)

        self.delete_user_sessions(username)

        self.delete_user_files(username)

        return True
    
    # ---------------- Session Management ---------------------------#
    def create_session(self, username, connection):
        '''
        Method to create a new session for - user
        return session_id
        '''

        token = str(uuid.uuid4())

        # Set the session expiration time
        # SESSION_TIMEOUT is taken from shared_constants.py
        expire_time = datetime.now() + timedelta(seconds=shared_constants.SESSION_TIMEOUT)

        # get user information for role
        user = self.get_user(username)

        if not user:
            return None
        
        session_record = {
            'token': token,
            'connection': connection,
            'username': username,
            'user_role': user['role'],
            'created_at': datetime.now().isoformat(),
            'expires_at': expire_time.timestamp()
        }

        # store the session record in the sessions table
        self.sessions_table.insert(session_record)

        return token
    
    def validate_session(self, token):
        '''
        Method to validate a session using the token
        '''
        session_val = self.sessions_table.get(self.Session.token == token)

        if not session_val:
            return None

        # Check if the session has expired
        expires_at = datetime.fromtimestamp(session_val['expires_at'])
        if expires_at < datetime.now():
            # If the session has expired, remove it from the database
            self.delete_session(token)
            # return None @ 2
            return (None,None)
        
        return (session_val['username'], session_val['user_role'])

    def get_session(self, connection):
        return self.sessions_table.get(self.Session.connection == connection)

    def delete_session(self, token):
        '''
        Method to delete a session using the token
        '''

        self.sessions_table.remove(self.Session.token == token)
        return True

    def delete_session_connection(self, connection):
        '''
        Method to delete a session using the token
        '''

        self.sessions_table.remove(self.Session.connection == connection)
        return True
    
    def delete_user_sessions(self, username):
        '''
        Method to delete all sessions of a user
        '''

        self.sessions_table.remove(self.Session.username == username)
        return True
    
    def clean_expired_sessions(self):
        '''
        Method to clean expired sessions from the database
        '''

        # get current time 
        now = datetime.now().timestamp()

        self.sessions_table.remove(self.Session.expires_at < now)

    # ---------------- File Management ---------------------------#

    def create_file(self, username, file_name, file_path, cert_path, encrypted_key, iv, file_hash):
        file_id = str(uuid.uuid4())

        user = self.get_user(username)

        if not user:
            return None

        upload_time = datetime.now().isoformat()

        file_record = {
            'file_id': file_id,
            'owner': username,
            'file_name': file_name,
            'file_path': file_path,
            'cert_path': cert_path,
            'upload_time': upload_time,
            'downloads': 0,
            'encrypted_key': encrypted_key,  # RSA-encrypted AES key (base64 string)
            'iv': iv,                        # AES IV (base64 string)
            'file_hash': file_hash          # SHA-256 hash of original file for integrity check
        }

        self.files_table.insert(file_record)

        return file_id

    def get_file(self, file_id):
        return self.files_table.get(self.File.file_id == file_id)

    def get_file_by_path(self, path):
        return self.files_table.get(self.File.file_path == path)

    def increment_downloads(self, file_id):
        file = self.get_file(file_id)
        self.files_table.update({'downloads': file['downloads'] + 1}, self.File.file_id == file_id)

    def validate_file(self):
        """todo: request validation from wherever handles that"""

    def delete_file(self, file_id):
        self.files_table.remove(self.File.file_id == file_id)

        return True

    def delete_file_by_path(self, path):
        self.files_table.remove(self.File.file_path == path)

        return True

    def delete_user_files(self, username):
        self.files_table.remove(self.File.owner == username)

        return True
