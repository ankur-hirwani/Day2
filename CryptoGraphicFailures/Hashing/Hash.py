import bcrypt
 
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
 
def check_password(hashed_password, user_password):
    # print('hashed password:')
    # print(hashed_password)
    # print('hash of password entered')
    # print(hash_password(user_password))
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)
 
users = {
    "user1": hash_password("password123"),
    "user2": hash_password("mysecurepassword")
}
 
def main():
    username = input("Enter username: ")
    password = input("Enter password: ")
 
    if username in users and check_password(users[username], password):
        print("Login successful!")
    else:
        print("Invalid username or password.")
 
if __name__ == "__main__":
    main()
    login_attempts = {}
 
    def main():
        username = input("Enter username: ")
        password = input("Enter password: ")
 
        if username not in login_attempts:
            login_attempts[username] = 0
 
        if login_attempts[username] >= 3:
            print("Account locked due to too many failed login attempts.")
            return
 
        if username in users and check_password(users[username], password):
            print("Login successful!")
            login_attempts[username] = 0  # Reset the counter on successful login
        else:
            login_attempts[username] += 1
            print("Invalid username or password.")
            if login_attempts[username] >= 3:
                print("Account locked due to too many failed login attempts.")
 
    if __name__ == "__main__":
        main()
