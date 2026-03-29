

import socket
import logging
import json
import os
from validation import *

import base64
#from PyQt5.QtCore.QUrl import password
# for loading the progress bar
from tqdm import tqdm
import ssl
import hashlib

from User.user import User

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from key_manager import generate_and_save_rsa_keypair  # for generating RSA key pair
from config import PASSWORD_PEPPER

# each log message will include
# - timestamp
# - name of the logger
# - log level
# - actual log message
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('secure_file_transfer_client')

HOST = 'localhost'  # The server's hostname or IP address
PORT = 9999
BUFFER_SIZE = 5000

# @ note: 1
CHUNK_SIZE = 4096

current_user = None


def certificate_exists():
    ''' Chec if the certificate file exists in the current directory '''
    if not os.path.exists('certificate.pem'):
        logger.error("Certificate file 'certificate.pem' not found.")
        print("Certificate file 'certificate.pem' not found.\n")
        print('Go to Web Browser and visit http://localhost:8000/server.html to download the certificate')
        return False
    else:
        return True

def open_ssl_context():
    '''
    Creating SSL Context for the secure connection
    '''
    context = ssl.create_default_context(cafile="certificate.pem") 

    # no verification of the server's certificate as it is a self-signed certificate
    context.check_hostname = False  

    # Automatically verify the server's certificate
    context.verify_mode = ssl.CERT_REQUIRED

    # Try loading the certificate to check for errors immediately


    # set the TLS version to default
    # @ note : 4
    # comment out the line below to get the default TLS version
    # context.minimum_version = ssl.TLSVersion.TLSv1_2

    return context


def send_command(client_socket, command):
    '''Function to send command to the server and get response '''

    try:
        # send the command to the server
        client_socket.sendall(command.encode('utf-8'))
        logger.info(f"Sent command to server: {command}")


        # recive and return the response from the server 
        response_data = client_socket.recv(BUFFER_SIZE)

        if not response_data:
            raise ConnectionError("Server closed the connection")
        
        # decoding the response data
        response = response_data.decode('utf-8')
        logger.info(f"Received response from server: {response}")

        return json.loads(response)

    except (ConnectionError, ConnectionResetError, ConnectionAbortedError) as e:
        logger.error(f"Connection error: {e}")
        print(f"Connection error: {e}")
        return {'status': 'error', 'message': f'Connection error: {str(e)}'}
    
    except Exception as e:
        logger.error(f"Error sending command {e}")
        return {'status': 'error', 'message': str(e)}

def list_files(client_socket):
    ''' Send the command to list the files in the server directory '''

    try:
        command = json.dumps({
            'action': 'list_files'
        })

        response = send_command(client_socket, command)

        if response.get('status') == 'success':
            print(json.dumps(response.get('files'), indent=4))
            return
        print(response.get('message'))
    except Exception as e:
        logger.error(f"Error listing files- {str(e)}")
        print(f"Error listing files: {str(e)}")

def delete_file(client_socket):
    try:
        list_files(client_socket)
        command = {'action': 'delete_file'}
        while True:
            print("would you prefer to enter:\n1.File ID\n2.File path")
            user_input = input("\n> ").strip()
            if user_input == '1':
                print("Enter File ID")
                file_id = input("\n> ")
                command['file_id'] = file_id
                break
            elif user_input == '2':
                print("Enter File Path")
                file_path = input("\n> ")
                command['file_path'] = file_path
                break
            print("Please enter 1 or 2")

        command = json.dumps(command)
        response = send_command(client_socket, command)

        print(response.get('message'))
    except Exception as e:
        logger.error(f"Error deleting file- {str(e)}")
        print(f"Error deleting file: {str(e)}")

def upload_file(client_socket):
    ''' 
    Function to upload a file to the server
    '''

    file_path = input("Enter the path of the file to upload: ")

    if not os.path.isfile(file_path):
        print("File Not Found")
        return

    try:
        # get the file name name and size 
        file_name = os.path.basename(file_path)
        # getsize function returns the size of the file in bytes
        file_size = os.path.getsize(file_path)

        # generate a 256-bit AES key
        aes_key = AESGCM.generate_key(bit_length=256)

        # generate a 12-byte IV for AES-GCM
        aes_iv = os.urandom(12)

        # create an AESGCM cipher object
        aesgcm = AESGCM(aes_key)

        # open and read the original file data
        with open(file_path, 'rb') as f:
            original_data = f.read()

        # encrypt the file using AES-GCM
        encrypted_data = aesgcm.encrypt(aes_iv, original_data, None)

        # compute SHA-256 hash of original file
        file_hash = hashlib.sha256(original_data).hexdigest()

        # load the server's RSA public key from a PEM file
        with open('public_key.pem', 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        # encrypt AES key with RSA-OAEP padding
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # encode encrypted AES key and IV for transmission (Base64)
        encoded_key = base64.b64encode(encrypted_aes_key).decode('utf-8')
        # ensure the IV is exactly 12 bytes
        if len(aes_iv) != 12:
            raise ValueError(f"Generated IV is not 12 bytes: got {len(aes_iv)}")
        encoded_iv = base64.b64encode(aes_iv).decode('utf-8')


        # crafting the upload command to the server in json format
        upload_command = json.dumps({
            'action': 'upload_file',
            'filename': file_name,
            'file_size': len(encrypted_data),  # send encrypted size
            'encrypted_key': encoded_key,      # send encrypted AES key
            'iv': encoded_iv,                  # send IV
            'file_hash': file_hash             # send hash of original file
        })

        # send the comand by calling the send_command function
        response = send_command(client_socket, upload_command)

        # first check server response is in ready state
        if response.get('status') == 'ready':
            print(f"Initiating file upload for {file_name} ({len(encrypted_data)} bytes)")

            bytes_sent = 0
            # open the file in binary mode
            # using tqdm to show the progeress bar 
            # Flages used 
            # total = file size is in bytes 
            # unit = B is the unit of measurement in bytes
            # desc is the description of the progress bar whih is set to the uplodead file name 
            # ncols - the width of the progress bar force set to 100 to prevent from cracking into multiple lines
            # leave = True to keep the progress bar on the screen after completion 
            with tqdm(total=len(encrypted_data), unit='B', unit_scale=True, desc=file_name , ncols=100 , leave=True) as pbar:
                while bytes_sent < len(encrypted_data):
                    chunk = encrypted_data[bytes_sent:bytes_sent + CHUNK_SIZE]  # Slice buffer directly
                    if not chunk:
                        break
                    client_socket.sendall(chunk)  # Send chunk
                    bytes_sent += len(chunk)
                    pbar.update(len(chunk))

            # after the file is uploaded we receive the response from the server
            final_response_data_raw = client_socket.recv(BUFFER_SIZE)

            # decode the response
            final_response_data = json.loads(final_response_data_raw.decode('utf-8'))

            # check if the status of the response is success
            if final_response_data.get('status') == 'success':
                print(f'File {file_name}  Upload Successful')
            else:
                # print the error message 
                # default message is Unknown error
                print(f"Error: {final_response_data.get('message', 'Unknown error')}")
        else:
            # when the sever is not in ready state
            # print the error message
            # default message is server not ready
            print(f"Error :{response.get('message', 'Server not ready')}")

    except Exception as e:
        # log the error message 
        logger.error(f"error uploading file {file_path} {str(e)}")
        print(f"error uploading file {file_path} {str(e)}")



def download_file(client_socket):
    ''' Function to download files from server'''


    try:
        list_files(client_socket)# List files on server before downloading

        # Prompt the user to input the name of the file to download
        filename = input("Enter the file name to download: ").strip()
        if not filename:
            print("No Filename Provided")
            return

        # Ask the user for the download directory (default is current directory)
        download_dir = input("Enter download directory (Press Enter for current directory): ")
        if not download_dir:
            print("No Download Directory Provided")
            download_dir = '.'

        # Validate that the directory exists
        if not os.path.exists(download_dir):
            print(f"Directory {download_dir} Not Found")
            return

        # Prepare and send the download command to the server
        download_command = json.dumps({
            'action': 'download_file',
            'filename': filename
        })

        # Send the command and get the response
        response = send_command(client_socket, download_command)

        # If server is ready to send the file
        if response.get("status") == "ready":
            file_size = response.get('file_size')
            server_file_name = response.get('filename')

            # Get encrypted AES key, IV and original file hash from the response
            encrypted_aes_key_b64 = response.get('encrypted_key')
            aes_iv_b64 = response.get('iv')
            original_file_hash = response.get('file_hash')

            # ========== PATCH: Fix IV base64 padding ==========
            if len(aes_iv_b64) % 4 != 0:
                aes_iv_b64 += '=' * (4 - len(aes_iv_b64) % 4)

            try:
                # Decode the base64 encoded IV and encrypted AES key
                aes_iv = base64.b64decode(aes_iv_b64)
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

                # Check IV length to match AES-GCM spec (12 bytes)
                if len(aes_iv) != 12:
                    print(f"Invalid IV length: {len(aes_iv)} bytes (expected 12)")
                    return

                # Load the RSA private key from local PEM file
                with open("private_key.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

                # Decrypt AES key using RSA OAEP padding
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Initialize AES-GCM cipher with the decrypted AES key
                aesgcm = AESGCM(aes_key)

            except Exception as e:
                # Handle any decryption/preparation error and exit early
                logger.error(f"Error decrypting AES key or IV: {str(e)}")
                print(f"Error decrypting AES key or IV: {str(e)}")
                return

            # ====== Only reach here if key/IV decryption is successful ======
            print(f"Initiating file download for {server_file_name} ({file_size} bytes)")
            download_path = os.path.join(download_dir, server_file_name)

            bytes_received = 0
            encrypted_data = b''  # buffer to hold received encrypted data

            # Show the progress bar while receiving the encrypted file
            with tqdm(total=file_size, unit='B', unit_scale=True, desc=server_file_name, ncols=100, leave=True) as pbar:
                while bytes_received < file_size:
                    bytes_to_read = min(CHUNK_SIZE, file_size - bytes_received)
                    chunk = client_socket.recv(bytes_to_read)
                    if not chunk:
                        break
                    encrypted_data += chunk
                    bytes_received += len(chunk)
                    pbar.update(len(chunk))

            # Double-check received size matches server's expected file size
            if len(encrypted_data) != file_size:
                print(f"Error: file size mismatch - expected {file_size}, got {len(encrypted_data)}")
                return

            try:
                # Decrypt the file content using AES-GCM and the IV
                decrypted_data = aesgcm.decrypt(aes_iv, encrypted_data, None)

                # Compute hash of decrypted file and compare with the original
                actual_file_hash = hashlib.sha256(decrypted_data).hexdigest()
                if actual_file_hash != original_file_hash:
                    print("Error: file hash mismatch - integrity verification failed")
                    return

                # Save decrypted data to disk
                with open(download_path, 'wb') as file:
                    file.write(decrypted_data)

            except Exception as e:
                # Catch AES decryption or hash mismatch failure
                logger.error(f"Error decrypting or validating file: {str(e)}")
                print(f"Error decrypting or validating file: {str(e)}")
                return

            # Final success response confirmation from server
            final_response_data_raw = client_socket.recv(BUFFER_SIZE)
            final_response_data = json.loads(final_response_data_raw.decode('utf-8'))

            if final_response_data.get('status') == 'success':
                print(f'File {server_file_name} downloaded successfully to {download_path}')
            else:
                print(f"Error: {final_response_data.get('message', 'Unknown Server error')}")

        else:
            # Server not ready to send file
            print(f"Error: {response.get('message', 'Server not ready for download')}")

    except Exception as e:
        logger.error(f"Error in downloading file {filename} {str(e)}")
        print(f"Error in downloading file {filename} {str(e)}")



def login(client_socket):
    print("Login")
    print("=========================")
    while True:
        print("Enter your username")
        username = input("\n> ")

        print("Enter your password")
        password_hash = hash_password(input("\n> "), username)

        command = json.dumps({
            'action': 'login',
            'username': username,
            'password_hash': password_hash
        })

        response = send_command(client_socket, command)

        if response.get('status') == 'success':
            print(f"Welcome {username}")
            global current_user
            current_user = User(response.get('user').get('username'), "n/a", response.get('user').get('role'))
            break
        else:
            print("Invalid Username or password, please try again.")
    return True

def register(client_socket):
    print("User Registration")
    print("=========================")
    generate_and_save_rsa_keypair()

    with open("public_key.pem", "rb") as f:
        public_key_pem = f.read().decode('utf-8')

    while True:
        print("Is this to be an admin account? (y/n)")
        user_input = input("\n> ").lower().strip()
        admin = False
        if user_input == "n" or user_input == "no":
            break
        elif user_input == "y" or user_input == "yes":
            print("Enter master Password")
            password = input("\n> ")

            password_hash =hash_password(password, "master")

            command = json.dumps({
                'action': 'authorize_admin',
                'incoming_hash': password_hash
            })

            response = send_command(client_socket, command)

            print(response.get('message'))

            if response.get('status') == "success":
                admin = True
                break
        else:
            print("Please only enter y/n")

    user = User("", "", "admin" if admin else "user")
    while True:
        print("Enter your username")
        username = input("\n> ")

        if validate_username(username):
            command = json.dumps({
                'action': 'check_username',
                'username': username
            })

            response = send_command(client_socket, command)

            if response.get('status') == 'success':
                user.username = username
                break
            if response.get('status') == 'duplicate':
                print(response.get('message'))
    password = ""
    while True:
        print("Enter your Password")
        password_input = input("\n> ")
        if validate_password(password_input):
            if password_input:
                password_hash = hash_password(password_input, user.username)
                user.password_hash = password_hash
                password = password_input
                break
    while True:
        print("Re-enter your Password")
        password_input = input("\n> ")
        if password == password_input:
            break
        print("Password missmatch")

    command = json.dumps({
        'action': 'create_account',
        'user': {
            'username': user.username,
            'password_hash': user.password_hash,
            'salt': generate_salt(username),
            'role': user.role,
            'public_key': public_key_pem
        }
    })

    response = send_command(client_socket, command)

    print(response.get('message'))
    if response.get('status') == 'success':
        return True

def list_users(client_socket):
    try:
        command = json.dumps({
            'action': 'list_users'
        })

        response = send_command(client_socket, command)

        if response.get('status') != 'success':
            print(response.get('message'))
            return
        for user in response.get('users'):
            print(f"{user.get('username')}:")
            print(f"\tID: {user.get('user_id')}")
            print(f"\tRole: {user.get('role')}")
    except Exception as e:
        logger.error(f"Error listing users- {str(e)}")
        print(f"Error listing users: {str(e)}")


def delete_user(client_socket):
    try:
        list_users(client_socket)
        print("enter username of user you wish to delete")
        username = input("\n> ")

        command = json.dumps({
            'action': 'delete_user',
            'username': username
        })

        response = send_command(client_socket, command)

        print(response.get('message'))
    except Exception as e:
        logger.error(f"Error deleting user- {str(e)}")
        print(f"Error deleting user: {str(e)}")


def list_all_files(client_socket):
    try:
        command = json.dumps({
            'action': 'list_files_all'
        })

        response = send_command(client_socket, command)

        if response.get('status') == 'success':
            print(json.dumps(response.get('files'), indent=4))
            return
        print(response.get('message'))
    except Exception as e:
        logger.error(f"Error listing files- {str(e)}")
        print(f"Error listing files: {str(e)}")

def delete_any_file(client_socket):
    try:
        list_all_files(client_socket)
        command = {'action': 'delete_file_any'}
        print("Enter File ID")
        file_id = input("\n> ")
        command['file_id'] = file_id

        command = json.dumps(command)
        response = send_command(client_socket, command)

        print(response.get('message'))
    except Exception as e:
        logger.error(f"Error deleting file- {str(e)}")
        print(f"Error deleting file: {str(e)}")


def generate_salt(username):
    return hashlib.sha256(username.encode()).hexdigest()

def hash_password(password, username):
    salt = generate_salt(username)
    return hashlib.sha256((password + salt + PASSWORD_PEPPER).encode()).hexdigest()

def user_menu(client_socket):
    print("\nSecure File Transfer Client SSL enabled")
    print("=========================")
    print("1. List Files")
    print("2. Upload File")
    print("3. Download File")
    print("4. Delete File")
    print("5. Exit")
    print("=========================")

    input_choice = input("\n enter your choice (1-5) --> ")

    if input_choice == '1':
        # Call the list_files function to send the command to the server
        list_files(client_socket)

    elif input_choice == '2':
        # Call the upload_file function to send the file upload command to the server
        upload_file(client_socket)

    elif input_choice == '3':
        # Call the download_file function to send the file download command to the server
        download_file(client_socket)

    elif input_choice == '4':
        delete_file(client_socket)

    elif input_choice == '5':
        print("Exiting...")
        return False
    else:
        print("Invalid choice.")
    return True

def admin_menu(client_socket):
    print("\nSecure File Transfer Client SSL enabled")
    print("=========================")
    print("1. List Files")
    print("2. Upload File")
    print("3. Download File")
    print("4. Delete File")
    print("5. List Users")
    print("6. Delete User")
    print("7. List all Files")
    print("8. Delete any File")
    print("9. Exit")
    print("=========================")
    input_choice = input("\n enter your choice (1-9) --> ")
    match input_choice:
        case '1':
            # Call the list_files function to send the command to the server
            list_files(client_socket)
        case '2':
            # Call the upload_file function to send the file upload command to the server
            upload_file(client_socket)
        case '3':
            # Call the download_file function to send the file download command to the server
            download_file(client_socket)
        case '4':
            delete_file(client_socket)
        case '5':
            list_users(client_socket)
        case '6':
            delete_user(client_socket)
        case '7':
            list_all_files(client_socket)
        case '8':
            delete_any_file(client_socket)
        case '9':
            print("Exiting...")
            return False
        case _:
            print("Invalid choice.")
    return True

def start_client():
    ''' Function to start the server and listen for incoming connections '''


    #client_address_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #client_address_socket.settimeout(30)
    
    result = certificate_exists()
    if not result:
        return
    

    ssl_context = open_ssl_context()

    try:
        # bind socket to host and port
        client_address_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_address_socket.settimeout(30)
        client_address_socket.connect((HOST, PORT))

        # listen for incoming connection
        logger.info(f"connected to server at {HOST}:{PORT}")

        # Recive the welcome message from server
        #incoming_data = client_address_socket.recv(BUFFER_SIZE)

        # Decode the data
        #welcome_message_decode = json.loads(incoming_data.decode('utf-8'))

        # Log the welcome message
        #logger.info(f"Server says: {welcome_message_decode.get('message', 'No welcome message')}")

        # Wrap the socket with SSL
        ssl_client_socket = ssl_context.wrap_socket(client_address_socket, server_hostname=HOST)
        logger.info(f"SSL Connnection Established wuith the server at {HOST}:{PORT}")

        # Recive the welcome message from server in open_ssl_context function
        incoming_data = ssl_client_socket.recv(BUFFER_SIZE)

        welcome_message_decode = json.loads(incoming_data.decode('utf-8'))


        # Log the welcome message
        logger.info(f"Server says: {welcome_message_decode.get('message', 'No welcome message')}")
        while True:
            print("1. Login")
            print("2. Register")
            print("=========================")
            input_choice = input("\n enter your choice (1-2) --> ").strip()
            if input_choice == "1":
                login(ssl_client_socket)
                break
            elif input_choice == "2":
                register(ssl_client_socket)
            else:
                print("Please only enter 1 or 2")
        global current_user


        # Simple command menu
        continue_work = True
        while continue_work:
            if current_user.role == 'admin':
                continue_work = admin_menu(ssl_client_socket)
            else:
                continue_work = user_menu(ssl_client_socket)

    except ssl.SSLError as e:
        logger.error(f"SSL error occurred: {str(e)}")
        print("SSL error occurred: ", e)
        start_client()
    
    except ConnectionResetError:
        print('Connection reset by server')

    except Exception as e:
        logger.error(f"Server error - {str(e)}")
        print(f"Error: {str(e)}")

    finally:
        # Close the server socket
        ssl_client_socket.close()
        logger.info("server socket closed")

if __name__ == "__main__":
    # Start the server
    start_client()

