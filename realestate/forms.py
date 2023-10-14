from django import forms


class SignupForm(forms.Form):
    name = forms.CharField(max_length=50)
    username = forms.CharField(max_length=50)
    password = forms.CharField(max_length=200)
    public_key = forms.FileField()
    proof_of_id = forms.FileField()
    user_type = forms.CharField(max_length=200)
    email = forms.CharField(max_length=50)
    
class LoginForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(max_length=200)
    user_type = forms.CharField(max_length=200)