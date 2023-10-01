from django.db import models

class Document(models.Model):
    username = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    # file = models.FileField(upload_to='pdfs/')
