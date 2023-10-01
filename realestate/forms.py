from django import forms
from .models import Document

class ModelWithFileField(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file']
