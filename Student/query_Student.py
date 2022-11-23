from database import TransactionDB, UnTransactionDB
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def Student_query(StudentID, sk):
    query_Result = TransactionDB().find(StudentID)
    if query_Result == {}:
        print('Error Occurred! The possible reasons are as follows:')
        print('\t1.Student ID Invalid.')
        print('\t2.Your grades have not been entered yet.')
        exit()
    GPA_to_Student = query_Result['GPA_to_Student']
    GPA = decrypt(sk, bytes.fromhex(GPA_to_Student))
    print('StudentID:',StudentID,'GPA:',GPA.decode())

def decrypt(sk, ciphertext):
    # decrypt the ciphertext using the private key
    # the decrypted plaintext should be unpadded
    private_key = serialization.load_pem_private_key(bytes.fromhex(sk), backend=default_backend(), password=None)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256(),
                     None))
    return plaintext