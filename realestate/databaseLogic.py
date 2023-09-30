import pymongo

def verify_login(username, password):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    collection = db["user_cred"]
    
    matches = collection.count_documents({"uname": username, "password": password})
    
    client.close()

    print(matches)
    
    if(matches == 1):
        return True
    
    return False