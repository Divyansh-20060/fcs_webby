from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('',ekycStart,name="ekyc page"),
    path('mainWelcome/',mainWelcome,name="main welcome"),
    
    path('emailVerify/',emailVerifyPage,name="email verify"),
    path('otpVerify/', otpPage, name= "otp verify"),
    path('signupPage/', signupPage, name = "sign up page"),
    
    path('loginPage/',loginPage,name="login page"),

    path('sellerHome/',sellerHome,name="seller home"),
    path('adminHome/',adminHome,name="admin home"),
    path('buyerHome/',buyerHome,name="buyer home"),

    path('userProfile/', userProfile, name = "user Profile"),
    path('updatePassword/',updatePassword,name="update password"),
    path('updateNamePOI/', updateNamePOI, name= "update Name POI"),

    path('showListings/',showListings,name="showListings"),
    path('purchaseHistory/',purchaseHistory,name="Purchases"),
    
]
