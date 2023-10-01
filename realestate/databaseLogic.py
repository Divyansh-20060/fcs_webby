import pymongo

def verify_login(username, password, user_type):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]

    collection = db[user_type]

    matches = collection.count_documents({"uname": username, "password": password})
    
    client.close()

    print(matches)
    
    if(matches == 1):
        return True
    return False

def signUp_check(name_tb, username, password, user_type):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    collection = db[user_type]
    
    matches = collection.count_documents({"uname": username})

    if (matches == 1):
        client.close()
        return False
    ##Insert the entry into the database
    # file_data = file.read()
    collection.insert_one({"name_tb": name_tb, "uname":username, "password":password})
    client.close()
    return True
