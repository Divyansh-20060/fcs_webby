from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
import json
from .databaseLogic import *

def ekycStart(request):
    return render (request, 'realestate/ekycPage.html')
    
def ekycR(request):
    return redirect (request, 'realestate/ekycPage.html')

def mainWelcome(request):
    return render (request,'realestate/mainWelcome.html')

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


        verdict = verify_login(username,password)


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
