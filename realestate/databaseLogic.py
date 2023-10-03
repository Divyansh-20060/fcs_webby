import pymongo


def signUp_check(file, public_key, proof_of_id):
    # return True
    
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    
    collection = db["user_info"]

    # matches = collection.count_documents({"uname": username, "user_type": user_type})
    matches = collection.count_documents({"uname":file["uname"], "user_type":file["user_type"]})

    base = "/home/iiitd/fcs_website"
    if (matches == 1):
        client.close()
        return False

    collection.insert_one(file)
    x =  base+file["proof_of_id_path"]
    y =  base+file["public_key_path"]
    ##also save the file to  the server
    with open(x, "wb+") as dest_file1:
        for chunk1 in proof_of_id.chunks():
            dest_file1.write(chunk1)
    with open(y, "wb+") as dest_file:
        for chunk in public_key.chunks():
            dest_file.write(chunk)

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


def dbQuery(uname, user_type, requested):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["realestate"]
    collection = db["user_info"]
    obj = collection.find({"uname":uname, "user_type":user_type}, {requested:1, "_id":0})[0]
    return obj
