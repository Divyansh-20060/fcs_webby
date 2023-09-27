from django.urls import path
from .views import *

urlpatterns = [
    path('',welcomePage,name="index"),
    path('loginPage/',loginPage,name="wow"),
    path('signupPage/', signupPage, name = "sign up"),
    path('mainPage', mainPage, name="main page"),
    path('loginCheck/',loginCheck,name="loginCheck"),
    path('buyerHome/',buyerHome,name="Home"),
    path('showListings/',showListings,name="showListings"),
    path('buyerProfile/',buyerProfile,name="Profile"),
    path('purchaseHistory/',purchaseHistory,name="Purchases"),
]
