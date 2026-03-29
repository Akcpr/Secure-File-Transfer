import socket
import logging
import os 
import json
from importlib.abc import PathEntryFinder

from tqdm import tqdm
import ssl
import subprocess
from Database.database_manager import DatabaseManager
from pathlib import Path
from config import MASTER_HASH

# configuring logging
# each log message will include
# - timestamp
# - name of the logger
# - log level
# - actual log message
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger('secure_file_transfer_server')

# Constants
# Listening to all interfaces
HOST = '0.0.0.0'
PORT = 9999
# Size of the buffer to read data from the socket
BUFFER_SIZE = 5000
# @ note: 1
CHUNK_SIZE = 4096

database_manager = DatabaseManager()

# Master hash is loaded from config.py, which reads the MASTER_HASH env var.

# Creating directory for storing files 
file_directory = 'server_files'
encrypted_file_dir = Path(file_directory, 'files')
metadata_dir = Path(file_directory, 'metadata')

#check if the directory exists
os.makedirs(file_directory, exist_ok=True)
os.makedirs(encrypted_file_dir, exist_ok=True)
os.makedirs(metadata_dir, exist_ok=True)

def create_ssl_context():
    try:
        # check if the SSL certificates are present
        if not os.path.exists('certificate.pem') or not os.path.exists('private_key.key'):
            logger.info('SSL certificate and key not found')
            logger.info('Please execute generate_ssl_certificates.py to generate the SSL certificate')
            return None

        # create SSL Context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Load the server's certificate and private key
        context.load_cert_chain(certfile='certificate.pem', keyfile='private_key.key')

        logger.info('SSL Context created successfully')
        return context
    
    except ssl.SSLError as e:
        logger.error(f"SSL Error: {e}")
        return None
    except Exception as e:
        logger.error(f'Error creating SSL Context: {e}')
        return None



def verify_ssl_certificates():
    '''
    Function to verify the SSL Certificates
    '''

    try:

        cert_command = ["openssl", "x509", "-in", "certificate.pem", "-pubkey", "-noout"]
        key_command = ["openssl", "rsa", "-in", "private_key.key", "-pubout"]


        cert_result = subprocess.run(cert_command, capture_output=True,  text=True)
        key_result = subprocess.run(key_command, capture_output=True, text=True)

        # Check if if public key of certificate matches the public key of the private key
        
        if cert_result.stdout.strip() == key_result.stdout.strip():
            logger.info('SSL Certificates and key are same public key')
            return True
        else:
            logger.error('SSL Certificates and key do not match')
            return False
        
    except Exception as e:
        logger.error(f'Error verifying SSL Certificates: {e}')
        return False
    

def handle_commands(command, client_socket, client_address):
    ''' Function to handel commands from the client '''
    try:
        # parsing the incoming commnad as json 
        incoming_command = json.loads(command)

        # extracting the actioon key from the incoming command
        # the key action is used to determine the type of command
        action = incoming_command.get('action')

        # if action key is is list_files
        if action == 'login':
            return handle_login(incoming_command, client_socket)
        elif action == 'create_account':
            return handle_create_user(incoming_command, client_socket)
        elif action == 'check_username':
            return handle_check_username(incoming_command, client_socket)
        elif action == 'authorize_admin':
            return handle_authorize_admin(incoming_command)

        session = database_manager.get_session(client_socket.fileno())

        if not database_manager.validate_session(session.get('token')):
            return {'status': 'error', 'message': 'invalid session'}

        user = database_manager.get_user(session.get('username'))

        if action == 'list_files':
            # call the function to handle list files command
            return handle_list_files(client_socket)
        elif action == 'upload_file':
            return handle_file_upload(incoming_command , client_socket, client_address)
        elif action == 'download_file':
            return handle_file_download(incoming_command, client_socket, client_address)
        elif action == 'delete_file':
            return  handle_delete_file(incoming_command, client_socket)
        elif action == 'list_users':
            if user.get('role') != 'admin':
                return {'status': 'error', 'message': 'Unauthorized access'}
            return handle_list_users()
        elif action == 'delete_user':
            if user.get('role') != 'admin':
                return {'status': 'error', 'message': 'Unauthorized access'}
            return handle_delete_user(incoming_command, client_socket)
        elif action == 'list_files_all':
            if user.get('role') != 'admin':
                return {'status': 'error', 'message': 'Unauthorized access'}
            return handle_list_all_files()
        elif action == 'delete_file_any':
            if user.get('role') != 'admin':
                return {'status': 'error', 'message': 'Unauthorized access'}
            return handle_delete_any_file(incoming_command, client_socket)
        else:
            # if the action is not recognized
            # usin key value pair to return the error message
            # status is set to error
            # and the message is set to unknown action
            return {'status': 'error', 'message': f'Unknown action: {action}'}
        
    # if the incoming command is not a valid json
    except json.JSONDecodeError:
        # status is set to error
        # message is set to invalid json format
        return {'status': 'error', 'message': 'Invalid JSON format'}
    
    except Exception as e:
        # status is set to error
        # message is set to the error message
        return {'status': 'error', 'message': str(e)}
    
def handle_list_files(client_socket):
    '''
    Function to handel the list of files 
    '''
    try:
        session = database_manager.get_session(client_socket.fileno())
        user = database_manager.get_user(session.get('username'))
        dir_path = Path(encrypted_file_dir / user.get('user_id'))
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
        file_tree = get_file_tree(Path(encrypted_file_dir / user.get('user_id')))
        print(file_tree)
        # return status success
        # and files set to the list of files
        return {'status': 'success', 'files': file_tree if len(file_tree) > 0 else 'File Directory is empty'}

    except Exception as e:
        logger.error(f"error listing files - {str(e)}")
        # status is set to error
        # message is set to the error message
        # using key value pair to return the error message
        return {'status': 'error', 'message': f'Error listing files: {str(e)}'}

def handle_file_upload(incoming_command,client_socket,client_address):
    '''
    Function to handel file upload functionality
    '''

    try:
        session = database_manager.get_session(client_socket.fileno())
        user = database_manager.get_user(session.get('username'))

        # get the file name and size from the incoming command
        filename = incoming_command.get("filename")
        file_size = incoming_command.get("file_size")

        encrypted_key = incoming_command.get("encrypted_key")  # base64 string of encrypted AES key
        iv = incoming_command.get("iv")                        # base64 string of AES IV
        file_hash = incoming_command.get("file_hash")          # original SHA-256 hash

        if not filename or file_size is None:
        # if the file name is not provided or file size is not valid
           return {'status': 'error', 'message': 'invalid file name or size'}
        
        # create the file path
        dir_path = Path(encrypted_file_dir / user.get('user_id'))
        file_path = Path(dir_path / filename)

        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)

        # send the ready message to the client
        # indicating the server is ready to receive the file

        ack_response = {'status': 'ready', 'message': 'ready to receive file'}

        # send the ack response to the client
        client_socket.sendall(json.dumps(ack_response).encode('utf-8'))

        # Receive the file size from the client
        bytesize_received = 0

        # open the file in binary write mode
        with open (file_path, 'wb') as file:
            while bytesize_received < file_size:
                remaining_bytes = file_size - bytesize_received
                # min fuhnction is used to get the minimum of the two values
                # it ensures that the number of bytes to receive does not exceed the remaining bytes
                # when it happns assigin the value of remaining bytes to bytes to receiv
                bytes_to_receive = min(CHUNK_SIZE, remaining_bytes)

                # recive the data from the client
                chunk = client_socket.recv(bytes_to_receive)
                
                # check if the chunk is not empty
                if not chunk:
                    break

                # write the chunk to file
                file.write(chunk)

                # get the number of bytes received

                bytesize_received += len(chunk)
        
        # verify if the file size is equal to the bytes received
        actual_file_size = os.path.getsize(file_path)


        # if the file size is not equal to the bytes received
        if actual_file_size != file_size:
            # remove the file if it exists
            os.remove(file_path)
            logger.error(f"File size not match for {filename} - expected size {file_size} - got {actual_file_size}")
            return {'status': 'error', 'message': 'file size mismatch - file upload failed'}
        
        else:
            logger.info(f"File {filename} uploaded successfully - size {actual_file_size} bytes")

            user_metadata = Path(metadata_dir / user.get('user_id'))
            metadata_path = Path(user_metadata / f"{filename}.meta.json")

            if not user_metadata.exists():
                user_metadata.mkdir(parents=True, exist_ok=True)

              # Save in same directory
            with open(metadata_path, 'w') as meta_file:
                json.dump({
                    "encrypted_key": encrypted_key,  # store base64-encoded AES key
                    "iv": iv,                        # store AES IV
                    "file_hash": file_hash           # store original file hash
                }, meta_file)

            database_manager.create_file(user.get('username'), filename, str(file_path), str(metadata_path), encrypted_key, iv, file_hash)
            # return the success message
            return {'status': 'success', 'message': f'file {filename} uploaded successfully', 'bytes_received': bytesize_received}
        
    except Exception as e:
        # log the error message
        logger.error(f"Error uploading file - {str(e)}")

        # remove the file if it exists
        try:
            # check if the file path exists
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass

        # return the error message
        return {'status': 'error', 'message': f'Error uploading file: {str(e)}'}

def handle_file_download(incoming_command, client_socket, client_address):
    '''
    Function to to handel the file to download functionality
    '''

    
    try:
        session = database_manager.get_session(client_socket.fileno())
        user = database_manager.get_user(session.get('username'))
        # get the file name and size from the incoming command
        filename = incoming_command.get("filename")

        dir_path = Path(encrypted_file_dir / user.get('user_id'))
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)

        # create the file path
        file_path = Path(dir_path / filename)
        # get the file size from the local file
        file_size = file_path.stat().st_size



        if not filename:
            # if the file name is not provided or file size is not valid
            return {'status': 'error', 'message': 'Missing file name'}


        # check if the file exists
        if not file_path.exists():
            return {'status': 'error', 'message': 'File not found'}
        
        metadata_path = Path(metadata_dir / user.get('user_id') / f"{filename}.meta.json")  # metadata filename is based on original file
        if not metadata_path.exists():
            return {'status': 'error', 'message': 'Missing encryption metadata'}

        with open(metadata_path, 'r') as meta_file:
            metadata = json.load(meta_file)  # load encryption details

        encrypted_key = metadata.get('encrypted_key')  # encrypted AES key (base64)
        iv = metadata.get('iv')                        # AES IV (base64)
        file_hash = metadata.get('file_hash')

        file_metadata = {
            'status': 'ready',
            'message': 'Ready to send file',
            'filename': filename,
            'file_size': file_size,
            'encrypted_key': encrypted_key,  # send encrypted AES key to client
            'iv': iv,                        # send AES IV
            'file_hash': file_hash           # send hash of original file for validation
            } 
    
        # send the file metadata to the client
        client_socket.sendall(json.dumps(file_metadata).encode('utf-8'))


        bytes_sent = 0
        # open the file in binary mode
        # using tqdm to show the progeress bar 
        # Flages used 
        # total = file size is in bytes 
        # unit = B is the unit of measurement in bytes
        # desc is the description of the progress bar whih is set to the uplodead file name 
        # ncols - the width of the progress bar force set to 100 to prevent from cracking into multiple lines
        # leave = True to keep the progress bar on the screen after completion 
        with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Sending {filename}", ncols=100, leave=True) as pbar:
            with open(file_path, 'rb') as file:
                # read the file in chunks
                while bytes_sent < file_size:
                    # read a chunk of data from the file
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    # send the chunk of data to the server
                    client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                    # suppressing the log message for each chunk
                    #logger.info(f"Sent chunk of size {len(chunk)} bytes")
                    # update the progress bar
                    pbar.update(len(chunk))

        logger.info(f'File {filename} sent successfully to {client_address} - {file_size} bytes')


        ######################################
        completion_response = {
            'status': 'success',
            'message': f'File {filename} sent successfully',
            'bytes_sent': bytes_sent
        }

        # send the completion response to the client
        client_socket.sendall(json.dumps(completion_response).encode('utf-8'))

        # signal for file sent
        return {'status': "file_sent_signal"}


    except Exception as e:
        logger.error(f"Error sinding file  - {str(e)}")

        try:
            error_response = {
                'status': 'error',
                'message': f'Error sending file: {str(e)}'
            }
            client_socket.sendall(json.dumps(error_response).encode('utf-8'))
        except:
            pass
        # send the error response to the client
        return {'status': 'error', 'message': f'Error sending file: {str(e)}'}

def handle_delete_file(incoming_command, client_socket):
    session = database_manager.get_session(client_socket.fileno())
    user = database_manager.get_user(session.get('username'))

    file_id = incoming_command.get('file_id')
    file_path = incoming_command.get('file_path')
    file = database_manager.get_file(file_id)

    if file:
        file_path = file.get('file_path')

    if not file_path:
        return {'status': 'File missing', 'message': 'unable to find file with information provided'}

    if user.get('user_id') not in str(file_path):
        return {'status': 'Illegal access', 'message': 'Unpermitted to access this file'}

    if not file:
        file = database_manager.get_file_by_path(file_path)

    if not Path(file_path).exists():
        return {'status': 'error', 'message': f"File at {file_path} does not exist."}

    try:
        if file:
            cert_path = file.get('cert_path')
            database_manager.delete_file(file.get('file_id'))
            if cert_path:
                Path(cert_path).unlink()
        Path(file_path).unlink()
    except Exception as e:
        return {'status': 'error', 'message': f"Error deleting file: {str(e)}"}
    return {'status': 'success', 'message': 'File successfully deleted.'}

def handle_check_username(incoming_command, client_socket):

    try:
        username = incoming_command.get("username")

        if (database_manager.user_exists(username)):
            return {'status': 'duplicate', 'message': f'{username} is already taken'}
        #validate username
        return {'status': 'success', 'message': f'{username} is free'}
    except Exception as e:
        logger.error(f"Error checking username - {str(e)}")
        return {'status': 'error', 'message': f'Error checking username: {str(e)}'}

def handle_create_user(incoming_command, client_socket):
    try:
        user = incoming_command.get('user')
        username = user.get('username')
        password_hash = user.get('password_hash')
        salt = user.get('salt')
        role = user.get('role')

        database_manager.create_user(username, password_hash, salt, "public key", role)

        return {'status': 'success', 'message': f'{role} Account {username} has successfully been created'}
    except Exception as e:
        logger.error(f"Error creating user - {str(e)}")
        return {'status': 'error', 'message': f'Error creating user: {str(e)}'}

def handle_login(incoming_command, client_socket):
    try:
        username = incoming_command.get('username')
        password_hash = incoming_command.get('password_hash')

        user = database_manager.get_user(username)
        if not user:
            return {'status': 'invalid user', 'message': f'Account: {username} does not exist'}
        if not compare_password(user.get('password_hash'), password_hash):
            return {'status': 'wrong password', 'message': 'Wrong password'}
        token = database_manager.create_session(username, client_socket.fileno())
        return {'status': 'success', 'message': 'Successfully logged in',
                'user': {
                    'username': user.get('username'),
                    'role': user.get('role')
                },
                'token': token}
    except Exception as e:
        logger.error(f"Error logging in user - {str(e)}")
        return {'status': 'error', 'message': f'Error logging in user: {str(e)}'}

def handle_authorize_admin(incoming_command):
    try:
        incoming_hash = incoming_command.get('incoming_hash')

        if not compare_password(MASTER_HASH, incoming_hash):
            return {'status': 'wrong password', 'message': 'Wrong password'}

        return {'status': 'success', 'message': 'Correct master password'}
    except Exception as e:
        logger.error(f"Error authorizing admin- {str(e)}")
        return {'status': 'error', 'message': f'Error authorizing admin: {str(e)}'}

def handle_list_users():
    try:
        users = []

        result = database_manager.get_users()

        for user in result:
            users.append({
                'user_id': user.get('user_id'),
                'username': user.get('username'),
                'role': user.get('role')
            })
        return ({
            'status': 'success',
            'message': 'Successfully retrieved all users',
            'users': users
        })
    except Exception as e:
        logger.error(f"error retrieving users - {str(e)}")
        # status is set to error
        # message is set to the error message
        # using key value pair to return the error message
        return {'status': 'error', 'message': f'Error retrieving users: {str(e)}'}

def handle_delete_user(incoming_command, client_socket):
    try:
        username = incoming_command.get('username')

        success = database_manager.delete_user(username)

        if success:
            return ({'status': 'success', 'message': f'Successfully deleted {username}'})
        else:
            return ({'status': 'failure', 'message': f'Acount: {username} could not be found'})
    except Exception as e:
        logger.error(f"error deleting user - {str(e)}")
        # status is set to error
        # message is set to the error message
        # using key value pair to return the error message
        return {'status': 'error', 'message': f'Error deleting user: {str(e)}'}

def handle_list_all_files():
    try:
        file_tree = get_file_tree(Path(encrypted_file_dir))

        # return status success
        # and files set to the list of files
        return {'status': 'success', 'files': file_tree if len(file_tree) > 0 else 'File Directory is empty'}

    except Exception as e:
        logger.error(f"error listing files - {str(e)}")
        # status is set to error
        # message is set to the error message
        # using key value pair to return the error message
        return {'status': 'error', 'message': f'Error listing files: {str(e)}'}

def handle_delete_any_file(incoming_command, client_socket):
    file_id = incoming_command.get('file_id')
    file_path = ""
    file = database_manager.get_file(file_id)

    if file:
        file_path = file.get('file_path')

    if not file_path:
        return {'status': 'File missing', 'message': 'unable to find file with information provided'}

    if not file:
        file = database_manager.get_file_by_path(file_path)

    if not Path(file_path).exists():
        return {'status': 'error', 'message': f"File at {file_path} does not exist."}

    try:
        if file:
            cert_path = file.get('cert_path')
            database_manager.delete_file(file.get('file_id'))
            if cert_path:
                Path(cert_path).unlink()
        Path(file_path).unlink()
    except Exception as e:
        return {'status': 'error', 'message': f"Error deleting file: {str(e)}"}
    return {'status': 'success', 'message': 'File successfully deleted.'}

def compare_password(stored_hash, incoming_hash):
    return stored_hash == incoming_hash

def get_file_tree(path):
    file_tree = {}

    for entry in path.iterdir():
        if entry.is_dir():
            file_tree[entry.name] = get_file_tree(entry)
        else:
            file = database_manager.get_file_by_path(str(entry))
            if file:
                file_tree[entry.name] = file
            else:
                file_tree[entry.name] = "No metadata"

    return file_tree

def start_server():
    ''' Function to start the server and listen for incoming connections '''

    # Create a socket 
    ##server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow the socket to be reused 
    # Set the socket option to allow address reuse
    # Usefull when the server is restated and the port is still in use
    # Thus preving address already in use error
    ##server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Set a timeout for the socket
    ##server_socket.settimeout(1.0)  # 1 second timeout

    ssl_context = create_ssl_context()

    if not ssl_context:
        logger.error('SSL Context could not be created. Exiting server.')
        return False

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow the socket to be reused
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)

    try:
        # bind socket to host and port
        server_socket.bind((HOST, PORT))

        # listen for incoming connections
        # 6 is the max number of queued connections 
        server_socket.listen(6)
        logger.info(f"Server is listening on {HOST}:{PORT}")

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                try:
                    ssl_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)
                    ssl_client_socket.settimeout(240)
                    ssl_client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    logger.info(f"connection from {client_address} has been established.")
                
                except ssl.SSLError as e:
                    logger.error(f"SSL Handeshake failed {e}")
                    client_socket.close()
                    continue
            
            except socket.timeout:
                continue  

            
            try:
                # Settig a welcome message
                server_welcome_message = json.dumps({
                    "status": "Success",
                    "message": "Welcome to secure file transfer server"
                })

                # Send the welcome message to the client
                ssl_client_socket.sendall(server_welcome_message.encode('utf-8'))

                while True:
                    # Recieve data from client
                    client_data = ssl_client_socket.recv(BUFFER_SIZE)
                    if not client_data:
                        logger.info(f"Client {client_address} disconnected.")
                        break
                    
                    decode_client_data = client_data.decode('utf-8')
                    logger.info(f"Recieved data from {client_address}: {decode_client_data}")

                    # Handle the command and get the response
                    
                    server_response = handle_commands(decode_client_data, ssl_client_socket, client_address)

                    if 'ready' not in server_response.get('status', '') and 'file_sent_signal' not in server_response.get('status', ''):
                        ssl_client_socket.sendall(json.dumps(server_response).encode('utf-8'))

                logger.info(f"No data received from {client_address} - Closing connection.")
            
            except ssl.SSLError as e:
                logger.error(f'SSL Error with client {client_address} - {e}')
            except Exception as e:
                logger.error(f"error handling client {client_address} - {e}")

                try:
                    error_response = json.dumps({
                        'status': 'error',
                        'message': f'server error {str(e)}'
                    })

                    # send the error response to the client
                    ssl_client_socket.sendall(error_response.encode('utf-8'))
                except:
                    pass

            finally:
                # Close the client socket
                database_manager.delete_session_connection(ssl_client_socket.fileno())
                ssl_client_socket.close()
                logger.info(f"connection with {client_address} closed successfully")

    except KeyboardInterrupt:
        logger.info("server is shutting down")


    except Exception as e:
        logger.error(f"Server error -  {e}")

    finally:
        # Close the server socket
        server_socket.close()
        logger.info("server socket closed")

if __name__ == "__main__":
    # Start the server
    start_server()

