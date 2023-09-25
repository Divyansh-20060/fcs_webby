from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
import json

def welcomePage(request):
    return render (request,'realestate/welcomePage.html')


def loginPage(request):
    return render(request, 'realestate/loginPage.html')


def signupPage(request):
    return render(request, 'realestate/signupPage.html')

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

        # Define the fixed username and password for comparison
        fixed_username = 'root'
        fixed_password = 'root'

        # Compare the provided credentials to the fixed credentials
        if username == fixed_username and password == fixed_password:
            # Credentials match
            response_data = {'success': True, 'message': 'Login successful'}
        else:
            # Credentials do not match
            response_data = {'success': False, 'error': 'Invalid username or password'}

        return JsonResponse(response_data)

    # Handle other HTTP methods if needed
    return JsonResponse({'error': 'Invalid request method'})
