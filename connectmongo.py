import pymongo

if __name__ == "__main__":
    
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    print(client)
    
    db = client["realestate"]
    
    collection = db["user_cred"]
    
    # collection.insert_one({"uname": "root","password": "root"})
    # collection.insert_one({"uname": "sth", "password": "sthsth", "fileTitle": "filname"})

    client.close()
