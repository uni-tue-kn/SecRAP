import sys
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

####
# For testing the module, import the keys
####
#if not os.path.isfile(public_key):
#    print('Public key does not exist.')
#else:
#    # Open the file and read its content.
#    with open(public_key) as f:
#        certificate = f.read()
#        print('Public key imported.')
#
#
## Private key used for creating signatures
#key = ""
#private_key = 'ec_key.pem'
#
#if not os.path.exists(private_key):
#    print('Private key does not exist!')
#else:
#    with open(private_key, 'rb') as pem_in:
#        key = pem_in.read()
#        print('Private key imported.')
###


class E2EProtection:
    @staticmethod
    def generate_signature(key, data):
        
        #print("Generating signature...")
        # Load Private Key
        private_key = load_pem_private_key(
            key,
            password=None,
            backend=default_backend()
        )
    
        # Create hash over data
        hasher = hashes.Hash(hashes.SHA256())
        #hasher.update(bytes(data, 'utf8'))
        hasher.update(data)
        digest = hasher.finalize()
        #print("Hash: ", digest)

        # Create signature
        sig = private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        

        #print("Resulting signature: " + str(sig))
        return sig

    @staticmethod
    def verify_signature(certificate, signature, data):

        #print("data in Hash:", data)
        #print("Verifying signature...")
        # Load public key from X.509
        #cert = x509.load_pem_x509_certificate(bytes(certificate, 'utf8'))
        cert = x509.load_pem_x509_certificate(certificate)
        #print(cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        cert_public_key = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        public_key = serialization.load_pem_public_key(cert_public_key)
        #print(public_key)

        hasher = hashes.Hash(hashes.SHA256())
        #hasher.update(bytes(data, 'utf8'))
        hasher.update(data)
        digest = hasher.finalize()
        #print("Hash: ", digest)

        try: 
            # Verfiy Hash (verify raises exception if signature is not valid)
            result = public_key.verify(
                signature,
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            print("Signature is valid!")
            return True
        
        except: 
            print("Signature is not valid!")
            return False

    @staticmethod
    def get_certificate():
        return certificate 



#signature = E2EProtection.generate_signature(key, 'asjhdkasd')
#E2EProtection.verify_signature(certificate, signature, 'asjhdkasd' )







