from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static


##temporary just for testing
urlpatterns = [
    path('',ekycStart,name="ekyc page"),
    path('mainWelcome/',mainWelcome,name="main welcome"),


    path('adminHome/',adminHome,name="admin home"),
    path('buyerHome/',buyerHome,name="buyer home"),
    path('sellerHome/',sellerHome,name="seller home"),

    path('loginPage/',loginPage,name="login page"),
    path('signupPage/', signupPage, name = "sign up page"),


    path('showListings/',showListings,name="showListings"),
    path('buyerProfile/',buyerProfile,name="Profile"),
    path('purchaseHistory/',purchaseHistory,name="Purchases"),
    path('sellerProfile/', sellerProfile, name = "sellerProfile"),
    
]
