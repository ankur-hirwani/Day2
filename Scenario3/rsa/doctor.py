import rsa

def generate_keys():
    public_key, private_key = rsa.newkeys(2048)
    with open('doctor_public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    with open('doctor_private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1('PEM'))
    print("Doctor's RSA keys generated.")

def decrypt_patient_data():
    with open('doctor_private_key.pem', 'rb') as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
    with open('encrypted_patient_data.bin', 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = rsa.decrypt(encrypted_data, private_key).decode()
    print("\nDecrypted Patient Data:")
    print(decrypted_data)

if __name__ == "__main__":
    generate_keys()
    input("Press Enter after the patient has entered their data...")
    decrypt_patient_data()
