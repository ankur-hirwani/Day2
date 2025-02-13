import rsa

def encrypt_patient_data():
    with open('doctor_public_key.pem', 'rb') as pub_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
    
    print("Enter Patient Details:")
    name = input("Name: ")
    age = input("Age: ")
    diagnosis = input("Diagnosis: ")
    ssn = input("SSN: ")
    
    patient_data = f"Name: {name}\nAge: {age}\nDiagnosis: {diagnosis}\nSSN: {ssn}"
    encrypted_data = rsa.encrypt(patient_data.encode(), public_key)
    with open('encrypted_patient_data.bin', 'wb') as enc_file:
        enc_file.write(encrypted_data)
    print("Patient data encrypted and saved.")

if __name__ == "__main__":
    encrypt_patient_data()
