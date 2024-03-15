from datetime import datetime, timedelta
import os
import calendar
import bcrypt
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys
import PySimpleGUI as sg
import string
import secrets
import pyperclip


def generate_strong_passphrase(length=15):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    passphrase = ''.join(secrets.choice(alphabet) for i in range(length))
    return passphrase


# Check if the environment variable exists
#passphrase_env_var = os.environ.get('RESIDENT_MGMT_DB_KEY')
passphrase_env_var = 'caretechdevmode'
if passphrase_env_var:
    passphrase = passphrase_env_var.encode()  # Proceed with encoding if exists
else:
    passphrase = generate_strong_passphrase()  # Generate a new passphrase if not found

    detailed_instructions = (
        f"Passphrase: {passphrase}\n\n"
        "Setting the Environment Variable\n\n"
        "For Windows:\n"
        "1. Open the Start Search, type in 'env', and choose 'Edit the system environment variables'.\n"
        "2. In the System Properties window, click on the 'Environment Variables…' button.\n"
        "3. In the Environment Variables window, click 'New…' under the 'System variables' section.\n"
        "4. Set the variable name as RESIDENT_MGMT_DB_KEY and paste the passphrase in the variable value. Click OK.\n\n"
        "For macOS and Linux:\n"
        "1. Open a terminal window.\n"
        "2. Enter the following command, replacing <passphrase> with the actual passphrase:\n"
        "   echo 'export RESIDENT_MGMT_DB_KEY=\"<passphrase>\"' >> ~/.bash_profile\n"
        "3. For the change to take effect, you might need to reload the profile with source ~/.bash_profile or simply restart the terminal."
    )

    layout = [
        [sg.Text("Passphrase not found. Please follow the instructions below to set it up.")],
        [sg.Multiline(detailed_instructions, size=(80, 15), disabled=True)],
        [sg.Button("Copy Passphrase")]
    ]

    window = sg.Window("Setup Passphrase", layout)

    while True:
        event, values = window.read()

        if event == sg.WINDOW_CLOSED:
            break
        elif event == "Copy Passphrase":
            pyperclip.copy(passphrase)
            sg.popup("Passphrase copied to clipboard. Please follow the instructions to set it as an environment variable.", keep_on_top=True)

    window.close()
    sys.exit()  # Exit after displaying the instructions
 

if passphrase_env_var == None:
    sg.popup(detailed_instructions)
    sys.exit()

salt = b'\x00'*16  # Use a fixed salt; TO BE CHANGED TO BE RANDOM

# Generate a key from the passphrase
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(passphrase))
fernet = Fernet(key)


def encrypt_data(data):
    '''
    Encrypt the data with the key
    
    Args:
        data: The data to be encrypted
    
    Returns:
        The encrypted data
    '''
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data):
    '''
    Decrypt the data with the key

    Args:
        data: The data to be decrypted
    
    Returns:
        The decrypted data
    '''
    return fernet.decrypt(data.encode()).decode()  # Decrypt and convert back to string