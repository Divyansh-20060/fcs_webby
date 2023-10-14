from django.db import models


class SellerInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=200)
    public_key = models.FileField(upload_to='publicKeys/')
    proof_of_id = models.FileField(upload_to='proofIDs/')
    email = models.CharField(max_length=50, default="strings")
    malicious = models.BooleanField
    
    
class BuyerInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50,primary_key=True)
    password = models.CharField(max_length=200)
    public_key = models.FileField(upload_to='public_keys/')
    proof_of_id = models.FileField(upload_to='proofIDs/')
    email = models.CharField(max_length=50)
    malicious = models.BooleanField
    
class AdminInfo(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=200)
    