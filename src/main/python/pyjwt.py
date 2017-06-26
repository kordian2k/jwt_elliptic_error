# Import
import logging
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from sys import exit
from jwt.exceptions import DecodeError
import jwt

# Constants
ALGORITHM = 'ES512'
VERTX_TOKEN_FILE = "jwt_vertx.txt"
PYJWT_TOKEN_FILE = "jwt_pyjwt.txt"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_keys():
    file1 = "jwt_public.pem"
    file2 = "jwt_private_key.pem"
    with open(file1, 'rb') as f1:
        cert_data = f1.read()
    with open(file2, 'rb') as f2:
        priv_data = f2.read()
    cert_obj = load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert_obj.public_key()
    private_key = load_pem_private_key(data=priv_data, password=None, backend=default_backend())
    return public_key, private_key

def decode_token(token, public_key, verify):
    decoded_token = jwt.decode(jwt=token, key=public_key, verify=verify)
    logging.info("Decoded token w/ verify= %s: %s.", str(verify), decoded_token)
    return decoded_token

def encode_token(data, private_key):
    token = jwt.encode(data, private_key, algorithm=ALGORITHM)
    logging.info("PyJWT generated token: %s.", token)
    return token

def read_token():
    with open(VERTX_TOKEN_FILE, 'rb') as f1:
        token = f1.read()
    logging.info("Read vertx token from file: %s.", token)
    return token

def write_token(token):
    file = PYJWT_TOKEN_FILE
    logging.info("Write pyJWT token to file: %s.", file)
    with open(file, 'wb') as f1:
        f1.write(token)
    pass

def main():
    logging.info("Running pyJWT...")
    pub, priv = get_keys()
    data = {'some': 'payload',
            'username': 'somebody'}
    new_token = encode_token(data, priv)
    try:
        write_token(new_token)
        vertx_token = read_token()
    except IOError as err:
        logging.error("Could not read / write file.", err)
        exit(1)

    try:
        decode_token(vertx_token, pub, False)
        decode_token(vertx_token, pub, True)
    except DecodeError as err:
        logging.error("Could not decode token.", err)
        exit(2)
    pass

if __name__ == "__main__":
    main()
