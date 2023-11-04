from django import forms


class SignupForm(forms.Form):
    name = forms.CharField(max_length=50)
    username = forms.CharField(max_length=50)
    password = forms.CharField(max_length=200)
    public_key = forms.FileField()
    proof_of_id = forms.FileField()
    user_type = forms.CharField(max_length=200)
    #email = forms.CharField(max_length=50)
    
class LoginForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(max_length=200)
    user_type = forms.CharField(max_length=200)
    
class PasswordForm(forms.Form):
    old_password = forms.CharField(max_length=200)
    new_password = forms.CharField(max_length=200)
    confirm_new_password = forms.CharField(max_length=200)

class CreateListingForm(forms.Form):
    type_property = forms.CharField(max_length=50)
    date = forms.DateField()
    amenities = forms.CharField(max_length=50)
    budget = forms.IntegerField()
    locality = forms.CharField(max_length=50)
    type_contract = forms.CharField(max_length=50)
    ownershipDoc = forms.FileField()
    identityDoc = forms.FileField()

class submitSignatureform(forms.Form):
    signature = forms.CharField(max_length=512)
