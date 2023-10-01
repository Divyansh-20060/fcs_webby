from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # path('',test_upload_file,name="ekyc page"),
    path('',ekycStart,name="ekyc page"),
    

    path('mainWelcome/',mainWelcome,name="main welcome"),
    
    path('adminHome/',adminHome,name="admin home"),
    path('buyerHome/',buyerHome,name="buyer home"),
    path('sellerHome/',sellerHome,name="seller home"),
    
    
    
    path('loginPage/',loginPage,name="wow"),
    path('signupPage/', signupPage, name = "sign up"),

    path('loginCheck/',loginCheck,name="loginCheck"),
    path('signupCheck/', signupCheck, name = "signupCheck"),

    path('upload_pdf/', upload_pdf,name= "sdsd"),

    path('showListings/',showListings,name="showListings"),
    path('buyerProfile/',buyerProfile,name="Profile"),
    path('purchaseHistory/',purchaseHistory,name="Purchases"),
    path('upload/', upload, name = "opload"),
    ##temporary just for testing

]
