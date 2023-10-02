from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
import json
from .databaseLogic import *
from realestate.models import Document
from django.http import HttpResponseRedirect
from django.shortcuts import render


def ekycStart(request):
    return render (request, 'realestate/ekycPage.html')

########################## Welcome #############
def mainWelcome(request):
    return render (request,'realestate/mainWelcome.html')


########################## Home #############


def adminHome(request):
    return render(request,'realestate/adminHome.html')

def buyerHome(request):
    return render(request,'realestate/adminHome.html')

def sellerHome(request):
    return render(request,'realestate/sellerHome.html')


########################### Legacy ############



def loginPage(request):
    return render(request, 'realestate/loginPage.html')

def signupPage(request):
    return render(request, 'realestate/signupPage.html')

def buyerHome(request):
    # print("django log: great success wow")
    return render(request,'realestate/buyerHome.html')

def buyerProfile(request):
    return render(request,'realestate/buyerProfile.html')

def showListings(request):
    return render(request,'realestate/showListings.html')

def purchaseHistory(request):
    return render(request,'realestate/purchaseHistory.html')


def loginCheck(request):
    if request.method == "POST":
        # # Parse the JSON data from the request
        data = json.loads(request.body)

        # # print(data)
        # # Extract the username and password from the data
        username = data.get('username', '')
        password = data.get('password', '')
        user_type = data.get('user_type', '')

        verdict = verify_login(username, password, user_type)


        # Compare the provided credentials to the fixed credentials
        if verdict == True:
            # Credentials match
            response_data = {'success': True, 'message': 'Login successful'}
            return JsonResponse(response_data)
        else:
            # Credentials do not match
            response_data = {'success': False, 'error': 'Invalid username or password'}
            return JsonResponse(response_data)

    # Handle other HTTP methods if needed
    return JsonResponse({'error': 'Invalid request method'}, satus = 400)


def signupCheck(request):

    if request.method == "POST":
        name = request.POST.get("name_tb")
        username = request.POST.get("username_tb")
        password = request.POST.get("password_tb")
        user_type = request.POST.get("user_type")
        public_key = request.FILES.get("public_key")
        proof_of_id = request.FILES.get("proof_of_id")
        
        public_key_data = public_key.read().hex()
        proof_of_id_data = proof_of_id.read().hex()
        file = {
            "name":name,
            "uname": username,
            "password": password,
            "user_type": user_type,
            "public_key": {
                
                "name": public_key.name,
                "data": public_key_data,
                "content_type": public_key.content_type   
            },

            "proof_of_id": {

                "name": proof_of_id.name,
                "data": proof_of_id_data,
                "content_type": proof_of_id.content_type   
            }
        }
           
        

        # Compare the provided credentials to the fixed credentials
        if verdict == signUp_check(file, username):
            # Credentials match
            response_data = {'success': True, 'message': 'Signup successful'}
            # response_data = ({'success': True,
            #                   "message": "sign up successful"})
            return JsonResponse(response_data)
        else:
            # Credentials do not match
            response_data = {'success': False, 'error': 'user already exist'}
            # response_data = ({"message": "sign up failed"})
            return JsonResponse(response_data)

    # Handle other HTTP methods if needed
    return JsonResponse({'error': 'Invalid request method'}, status=400)


