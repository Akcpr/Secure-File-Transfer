import subprocess
import os
from cryptography import x509

import shutil

# PS while running subprocess commands in python 
# the return value of the subprocess.run() method can be used to check the success or failure of the command
# two types of return codes are 0 means sucess and nonzero - ( Deafukt is 1 ) means failure



def check_openssl_installed():
    '''
    Check if OpenSSL is installed on the system
    '''
    
    try:
        # using subprocess to run the openssl command 
        # capture output file is set to True to capture the output
        # text is set to True to get the output as a string
        # Now if opensssl is installed then it will return the version of openssl
        # If openssl is not installed then it will raise a FileNotFoundError
        # it will trigger the except block
        result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
        print(f"OpenSSL is installed - {result.stdout.strip()}")
        return True 

    # if openssl is not installed then it will raise a FileNotFoundError
    except FileNotFoundError:
        print("OpenSSL is not installed")
        print('Install Instructions:')
        print("Linux : sudo apt install openssl")
        print("Windows : Download from https://slproweb.com/products/Win32OpenSSL.html")
        return False



def run_openssl_command(command , description):
    '''
    Function to run oppenssl commands
    Arguments:
    Command : takes the command to run as list 
    Description : takes the description of the command to run
    '''

    try:
        # using subprocess to run the openssl command 
        # capture output file is set to True to capture the output
        # text is set to True to get the output as a string
        print(f"{description}\n")

        # Flagss used in the command
        # command - to capture the command to run
        # capture_output - to capture the output of the command
        # shell - to run the command in shell mode
        result = subprocess.run(command, capture_output=True, text=True, shell=False)

        # check if the command was successful
        if result.returncode != 0:
            print(f"❌ Error: {result.stderr}")
            return False
        
        if result.stdout:
            print(f"✅ {description} completed")
        return True

        
#        if result.returncode == 0:
#            print(f"{description} completed")
#            return True
#        else:
#            print(f"Error: {result.stderr}")
#            return False



    except Exception as e:
        # print the error message if the command fails
        print(f"An error occurred while running the command: {e}")
        return False


def generate_private_key():
    '''
    Function to generate a private key using openssl 

    Encryption Algorithm: RSA
    Key Size: 2048 bits
    Exponent: not set as it is set to default value of 65537
    '''

    # command crafted to generate a private key using openssl
    command = ['openssl', 'genrsa', '-out', 'private_key.key', '2048']

    # calling the run_openssl_command function to run the command
    return run_openssl_command(command , 'Generating Private Key')

def generate_certificate():
    '''
    Function to generate a self-signed certificate using OpenSSL
    '''

    # certificate confirguration
    # Subject string 

    #### @ note: 2
    subject_information = (
        '/C=AU',  # Country
        '/ST=Victoria',  # State or Province
        '/L=Clayton',  # Locality
        '/O=Secure_File_Transfer',
        '/CN=localhost'  # Common Name
    )

    # Subject Alternative Name (SAN) extensions
    # @note : 3
    san_extensions = "subjectAltName=DNS:localhost,IP:127.0.0.1"

    
    # command crafter to generate a self-signed certificate using openssl
    command = [
        'openssl', 'req', '-x509', '-new', '-key', 'private_key.key',
        '-out', 'certificate.pem', '-days', '365', 
        '-subj', '/'.join(subject_information),
        '-addext', san_extensions
    ]

    # calling the run_openssl_command function to generate the certificate with the crafted command
    return run_openssl_command(command, 'Generating Self-Signed Certificate')


def display_certificate():
    '''
    Function to display the generated certificate using OpenSSL
    '''

    print("============================================================================")
    print("Displaying the generated certificate:")
    print("============================================================================")
    command = ['openssl', 'x509', '-in', 'certificate.pem', '-text', '-noout']
    subprocess.run(command)





def get_certificate_fingerprint():
    '''
    Function to display the fingerprint of the generated certificate using OpenSSL
    '''

    # why need to display the fingerprint ?
    # to verify the integrity of the certificate
    # In more detail, the fingerprint is a hash of the certificate's contents

    try:
        # using sha 256 algorithm to generate the fingerprint
        command = ['openssl', 'x509', '-in', 'certificate.pem', '-noout', '-fingerprint', '-sha256']
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            # Return the fingerprint as a string
            return result.stdout
        else:
            print(f"Error generating fingerprint: {result.stderr}")
            return False
            #return "Unknown"
        
    except Exception as e:
        print(f"An error occurred when generating fingerprint : {e}")
        return False
        #return "Unknown"

def verify_gen_files():
    '''
    Function to verify the generated files were created successfully or not
    '''

    # List of files to check
    # we are checking for the existence of the private key and certificate files
    files_to_check = ['private_key.key', 'certificate.pem']
    print("============================================================================")
    print("Validating the generated files")
    print("============================================================================")

    #### check - 1 - file existence
    # iterating through the list of files to check if they exist
    for file in files_to_check:
        # using os.path.exists() to check if the file exists
        if os.path.exists(file):
            # if file exists get the files size using os.path.getsize()
            size = os.path.getsize(file)
            # printing the file and its size
            print(f"File found: {file}  Size: {size} bytes")
        else:
            print(f"File not found --> {file}")
            return False
    
    ### check - loading the certificate
    try:
        # Load the certificate to verify its validity
        # using with statement to open the certificate file
        with open('certificate.pem', 'rb') as certificate_file:
            # read the certificate data in a binary mode
            certificate_data = certificate_file.read()
        

        # load_pem_x509_certificate is a method from the cryptography library
        # it is used to load a pem encoded x509 certificate
        # If the certificate is valid, it will return a certificate object
        # if the certificate is invalid, it will raise an exception
        # when it raises an exception it will be caught by the except block
        certificate = x509.load_pem_x509_certificate(certificate_data)

        print("Certificate validation -> successful")
        print(f"Subject: {certificate.subject}")
        print(f"Valid from: {certificate.not_valid_before}")
        print(f"Valid until: {certificate.not_valid_after} ")
        

        return True

    except Exception as e:
        print(f" Certificate validation -> failed: {e}")
        return False

            
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return False



def test_ssl_config():
    '''
    Function to test the SSL Configuration using OpenSSL
    '''

    # command to test the ssl configuration
    # Flags used in the command
    # x509 - type of certificate
    # command to extract the public key from the certificate
    certificate_command = ["openssl", "x509", "-in", "certificate.pem", "-pubkey", "-noout"]

    # use openssl to extract to process the rsa private key
    # read the private key from the file private_key.key"
    # output the corresponding public key in pem format
    key_command = ["openssl", "rsa", "-in", "private_key.key", "-pubout"]


    try:
        # running the certificate command to extract the public key from the certificate
        certificate_result = subprocess.run(certificate_command, capture_output=True, text=True)

        # running the key command to extract the public key from the private key
        key_result = subprocess.run(key_command, capture_output=True, text=True)


        # basically we ar comparing the public key extracted from the certificate
        # with the public key extracted from the private key
        if certificate_result.stdout.strip() == key_result.stdout.strip():
            print("SSL Configuration Test: Successful")
            print("Public Key Matches")
            return True

        else:
            print("Print Error: Public Key Mismatch --> public key of the certificate and private key do not match")
            return False

    except Exception as e:
        print(f"SSL Configuration Test -  Failed - {e}")
        return False

def copy_certificate():
    '''
    Function to copy the .pem file to a specified directory
    '''
    try:
        shutil.copy("certificate.pem", "public_cert_server")
        print("Certificate copied successfully.")
    except Exception as e:
        print(f"Error copying certificate: {e}")

def main():
    '''
    Main function to run the script
    '''
    print("==================================================")
    print("SSL Certificate Generation Script")
    print("==================================================")

    # Check if OpenSSL is installed
    if not check_openssl_installed():
        return False
    
    # Remove existing files if they exist
    for file in ['private_key.key', 'certificate.pem']:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed existing file: {file}")

    # Generate a private key
    # if the private key is not generated successfully then return False
    # we are also calling the generate_private_key function 
    if not generate_private_key():
        print("Failed to generate private key")
        return False
    
    if not generate_certificate():
        print("Failed to generate self-signed certificate")
        return False
    
    if not verify_gen_files():
        print("Generated files verification failed")
        return False
    
    if not test_ssl_config():
        print("SSL Configuration Test failed")
        return False

    display_certificate()

    fingerprint = get_certificate_fingerprint()
    print("============================================================================")
    print(f" \n SHA CERTIFICATE FINGERPRINT:")
    print(f"   {fingerprint}")
    print("============================================================================")

    print("SSL Certificate Generation Script Completed Successfully")
    print("Files generated: private_key.key ( Private Key), certificate.pem ( Self-Signed Certificate)")

    copy_certificate()
    return True

if __name__ == "__main__":
    main()





