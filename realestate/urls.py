from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('',ekycStart,name="ekyc page"),
    
    path('ekyc2/<int:listing_id>',ekyc2,name="ekyc2"),
    
    path('mainWelcome/',mainWelcome,name="main welcome"),
    
    path('emailVerify/',emailVerifyPage,name="email verify"),
    path('otpVerify/', otpPage, name= "otp verify"),
    path('signupPage/', signupPage, name = "sign up page"),
    
    path('loginPage/',loginPage,name="login page"),

    path('sellerHome/',sellerHome,name="seller home"),
    path('createListing/',createListing, name="create listing"),
    path('viewSellerListings/', viewSellerListings, name="view seller listings"),
    path('edit_listing/<int:listing_id>', edit_listing, name="edit_listing"),
    path('delete_listing/<int:listing_id>', delete_listing, name = "delete_listing"),
    path('sellerSignContract/<int:listing_id>', sellerSignContract, name = "sellerSignContract"),
    path('sellerApprove/<int:listing_id>', sellerApprove, name = "sellerApprove"),
    path('sellerReject/<int:listing_id>', sellerReject, name = "sellerReject"),

    path('adminHome/',adminHome,name="admin home"),
    path('buyerHome/',buyerHome,name="buyer home"),
    path('viewBuyerListings/', viewBuyerListings, name ="view buyer listings"),
    path('buyerSignContract/<int:listing_id>', buyerSignContract, name = "buyerSignContract"),
    path('buyerInterested/<int:listing_id>', buyerInterested, name = "buyerInterested"),
    path('makePayment/<int:listing_id>', makePayment, name="makePayment"),
    path('view_currrent_listings', view_currrent_listings, name="view_currrent_listings"),
    
    path('userProfile/', userProfile, name = "user Profile"),
    path('updatePassword/',updatePassword,name="update password"),
    path('updateNamePOI/', updateNamePOI, name= "update Name POI"),
    
    path('returnHome/',returnHome,name="return home"),
    
    path('userProfile/', userProfile, name = "user Profile"),
    
    path('adminProfile/', adminProfile, name = "admin Profile"),
    
    path('transactionVerdict/<int:listing_id>',transactionVerdict,name="transaction verdict"),
    
    path('viewUsers/', viewUsers, name= "view users"),
    path('viewProfile/<str:username>/', viewProfile, name='view profile'),
    path('mark_malicious_buyer/<str:username>/<int:is_malicious>', mark_malicious_buyer, name="mark_malicious_buyer"),
    path('before_sign/<int:listing_id>', before_sign, name="before sign"),
    path('beforeListing/', beforeListing, name="before listing"),
    path('otp2/<int:listing_id>', otp2, name="otp2"),
    path('otp3/', otp3, name="otp3"),
    path('delete_buyer/<str:username>', delete_buyer, name="delete_buyer"),
    
    path('logout/', logout, name="logout"),
    #path('adminProfile/', admin, name = "admin password"),
    
    
]
