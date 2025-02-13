from cryptography.fernet import Fernet
import getpass

key = Fernet.generate_key()
cipher = Fernet(key)

ADMIN_CREDENTIALS = {"admin": "password123"}

patient_records = []

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data.encode()).decode()

def authenticate_admin():
    username = input("Enter admin username: ")
    password = getpass.getpass("Enter admin password: ")
    return ADMIN_CREDENTIALS.get(username) == password

def add_patient():
    name = input("Enter patient name: ")
    age = input("Enter patient age: ")
    email = input("Enter patient email: ")
    ssn = input("Enter patient SSN: ")
    history = input("Enter patient history of illness: ")
    
    encrypted_record = {
        "name": encrypt_data(name),
        "age": encrypt_data(age),
        "email": encrypt_data(email),
        "ssn": encrypt_data(ssn),
        "history": encrypt_data(history)
    }
    patient_records.append(encrypted_record)
    print("Patient record added securely!\n")

def view_patients():
    if not patient_records:
        print("No patient records found.\n")
        return
    
    print("\nDecrypted Patient Records:")
    for idx, record in enumerate(patient_records, start=1):
        print(f"Patient {idx}:")
        print(f"  Name: {decrypt_data(record['name'])}")
        print(f"  Age: {decrypt_data(record['age'])}")
        print(f"  Email: {decrypt_data(record['email'])}")
        print(f"  SSN: {decrypt_data(record['ssn'])}")
        print(f"  History: {decrypt_data(record['history'])}")
        print("----------------------")

def main():
    print("Secure Patient Data Management System")
    if not authenticate_admin():
        print("Authentication failed! Access denied.")
        return
    
    while True:
        print("\nOptions:")
        print("1. Add Patient Record")
        print("2. View Patient Records")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_patient()
        elif choice == "2":
            view_patients()
        elif choice == "3":
            print("Exiting system.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
