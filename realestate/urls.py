from django.urls import path
from .views import *

urlpatterns = [
    path('',welcomePage,name="index"),
    path('loginPage/',loginPage,name="wow"),
    path('signupPage/', signupPage, name = "sign up"),
    path('mainPage', mainPage, name="main page")
]
