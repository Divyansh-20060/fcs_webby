import pymongo


def signUp_check(file, username):
    # return True
    
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    
    collection = db["user_info"]

    matches = collection.count_documents({"uname": username})


    if (matches == 1):
        client.close()
        return False

    collection.insert_one(file)
    client.close()
    return True

def verify_login(username, password, user_type):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    
    collection = db["user_info"]

    matches = collection.count_documents({"uname": username, "password": password, "user_type": user_type})

    if (matches == 1):
        client.close()
        return True

    client.close()
    return False
