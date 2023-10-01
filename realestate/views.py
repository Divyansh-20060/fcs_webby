from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
import json
from .databaseLogic import *

def ekycStart(request):
    return render (request, 'realestate/ekycPage.html')

########################## Welcome #############
def mainWelcome(request):
    return render (request,'realestate/mainWelcome.html')

def buyerWelcome(request):
    return render(request,'realestate/buyerWelcome.html')

def sellerWelcome(request):
    return render(request,'realestate/sellerWelcome.html')

########################## Signup #############
def buyerSignup(request):
    return render(request,'realestate/buyerSignup.html')

def sellersignup(request):
    return render(request,'realestate/sellerSignup.html')

########################## Login #############
def adminLogin(request):
    return render(request,'realestate/adminLogin.html')

def buyerLogin(request):
    return render(request,'realestate/buyerLogin.html')

def sellerLogin(request):
    return render(request,'realestate/sellerLogin.html')


########################## Home #############


def adminHome(request):
    return render(request,'realestate/adminHome.html')

def buyerHome(request):
    return render(request,'realestate/adminHome.html')

def sellerHome(request):
    return render(request,'realestate/sellerHome.html')


########################### Legacy ############


def welcomePage(request):
    return render (request,'realestate/welcomePage.html')

def loginPage(request):
    return render(request, 'realestate/loginPage.html')

def signupPage(request):
    return render(request, 'realestate/signupPage.html')

def buyerHome(request):
    print("django log: great success wow")
    return render(request,'realestate/buyerHome.html')

def buyerProfile(request):
    return render(request,'realestate/buyerProfile.html')

def showListings(request):
    return render(request,'realestate/showListings.html')

def purchaseHistory(request):
    return render(request,'realestate/purchaseHistory.html')

def mainPage(request):
    print("django log:yahoo")
    return render(request, 'realestate/mainPage.html')

def loginCheck(request):
    
    print("hello")
    
    if request.method == 'POST':
        # Parse the JSON data from the request
        data = json.loads(request.body)

        print(data)
        # Extract the username and password from the data
        username = data.get('username', '')
        password = data.get('password', '')
        user_type = data.get('user_type', '')


        verdict = verify_login(username,password, user_type)


        # Compare the provided credentials to the fixed credentials
        if verdict == True:
            # Credentials match
            response_data = {'success': True, 'message': 'Login successful'}
        else:
            # Credentials do not match
            response_data = {'success': False, 'error': 'Invalid username or password'}

        return JsonResponse(response_data)

    # Handle other HTTP methods if needed
    return JsonResponse({'error': 'Invalid request method'})

def signupCheck(request):

    if request.method == 'POST':
        # Parse the JSON data from the request
        data = json.loads(request.body)

        print(data)
        # Extract the username and password from the data
        name_tb = data.get('name_tb', '')
        username = data.get('username', '')
        password = data.get('password', '')
        user_type = data.get('user_type', '')
        file = data.get('file', '')
        
        verdict = signUp_check(name_tb,username, password, user_type, file)


        # Compare the provided credentials to the fixed credentials
        if verdict == True:
            # Credentials match
            response_data = {'success': True, 'message': 'Signup successful'}
        else:
            # Credentials do not match
            response_data = {'success': False, 'error': 'user already exist'}

        return JsonResponse(response_data)
    # Handle other HTTP methods if needed
    return JsonResponse({'error': 'Invalid request method'})


