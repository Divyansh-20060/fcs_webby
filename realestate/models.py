from django.db import models


class SellerInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=200)
    salt = models.CharField(max_length=200)
    public_key = models.FileField(upload_to='publicKeys/')
    proof_of_id = models.FileField(upload_to='proofIDs/')
    email = models.CharField(max_length=50, default="strings")
    malicious = models.BooleanField
    
    
class BuyerInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50,primary_key=True)
    password = models.CharField(max_length=200)
    salt = models.CharField(max_length=200)
    public_key = models.FileField(upload_to='public_keys/')
    proof_of_id = models.FileField(upload_to='proofIDs/')
    email = models.CharField(max_length=50)
    malicious = models.BooleanField
    
class AdminInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=200)
    salt = models.CharField(max_length=200)

class ListingInfo(models.Model):
    ID = models.AutoField(primary_key=True)
    typePropety = models.CharField(max_length=50) #apprartment or whatever
    seller = models.CharField(max_length=50)
    buyer = models.CharField(max_length=50, null = True)
    status = models.CharField(max_length=50)
    date = models.DateField()
    amenity = models.CharField(max_length=50)
    budget = models.IntegerField()
    locality = models.CharField(max_length=50)
    typeContract = models.CharField(max_length=50) # rentals or for sale
    ownershipDoc = models.FileField(upload_to='Ownership_Docs/')
    identityDoc = models.FileField(upload_to='Identity_Docs/')
    malicious = models.BooleanField(default=False)
    saleContract = models.FileField(upload_to='Sale_Contract/', null = True, blank=True)
    rentalContract_buyer = models.FileField(upload_to='Rental_buyer/', null = True, blank=True)
    rentalContract_seller = models.FileField(upload_to='Rental_seller/', null = True, blank=True)
    buyer_sign = models.CharField(max_length=512, null = True)
    seller_sign = models.CharField(max_length=512, null = True)