from django.urls import path
from .views import *

urlpatterns = [
    path('',ekycStart,name="ekyc page"),
    
    path('mainWelcome/',mainWelcome,name="main welcome"),
    path('buyerWelcome/',buyerWelcome,name="buyer welcome"),
    path('sellerWelcome/',sellerWelcome,name="seller welcome"),
    
    path('buyerSignup/',buyerSignup,name="buyer signup"),
    path('sellerSignup/',sellersignup,name="seller signup"),
    
    
    path('adminLogin/',adminLogin,name="admin login"),
    path('buyerLogin/',buyerLogin,name="buyer login"),
    path('sellerLogin/',sellerLogin,name="seller login"),
    
    path('adminHome/',adminHome,name="admin home"),
    path('buyerHome/',buyerHome,name="buyer home"),
    path('sellerHome/',sellerHome,name="seller home"),
    
    
    
    path('loginPage/',loginPage,name="wow"),
    path('signupPage/', signupPage, name = "sign up"),
    path('mainPage', mainPage, name="main page"),
    path('loginCheck/',loginCheck,name="loginCheck"),
    path('signupCheck/', signupCheck, name = "signupCheck"),
    path('buyerHome/',buyerHome,name="Home"),
    path('showListings/',showListings,name="showListings"),
    path('buyerProfile/',buyerProfile,name="Profile"),
    path('purchaseHistory/',purchaseHistory,name="Purchases"),
]
