from cryptography.hazmat.backends import default_backend
from database import TransactionDB, UnTransactionDB, ENC_AccountDB
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def Teacher_query(StudentID):
    query_Result = TransactionDB().find(StudentID)
    if query_Result == {}:
        print('Error Occurred! The possible reasons are as follows:')
        print('\t1.Student ID Invalid.')
        print('\t2.Your grades have not been entered yet.')
        exit()
    GPA_to_Teacher = query_Result['GPA_to_Teacher']
    Teacher = ENC_AccountDB().find_one()
    sk = Teacher['privatekey']
    GPA = decrypt(sk, bytes.fromhex(GPA_to_Teacher))
    print('StudentID:',StudentID,'GPA:',GPA.decode())

def range_query(from_range,to_range,order='des',StudentID_only=True):
    if order == 'des':
        order = True
    elif order == 'asc':
        order = False
    if StudentID_only == 'false':
        StudentID_only = False
    StudentID_GPA = {}
    Teacher = ENC_AccountDB().find_one()
    sk = Teacher['privatekey']
    for student_tx in TransactionDB().find_all():
        GPA_to_Teacher = student_tx['GPA_to_Teacher']
        GPA = decrypt(sk, bytes.fromhex(GPA_to_Teacher))
        if float(GPA) >= float(from_range) and float(GPA) <= float(to_range):
            StudentID_GPA[student_tx['StudentID']] = float(GPA)
    # 按照字典的值进行排序
    StudentID_GPA = sorted(StudentID_GPA.items(), key=lambda x: x[1], reverse=order)
    print('GPA from', from_range, 'to', to_range, 'are as follows:')
    for StudentID, GPA in dict(StudentID_GPA).items():
        if StudentID_only:
            print('StudentID:', StudentID, 'GPA:', GPA)
        else:
            print('StudentID:',StudentID)


def decrypt(sk, ciphertext):
    # decrypt the ciphertext using the private key
    # the decrypted plaintext should be unpadded
    private_key = serialization.load_pem_private_key(bytes.fromhex(sk), backend=default_backend(), password=None)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256(),
                     None))
    return plaintext