from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
import json
from .databaseLogic import *
from realestate.models import Document
from django.http import HttpResponseRedirect
from django.shortcuts import render
# from .forms import ModelWithFileField

def test_upload_file(request):
    return render (request, 'realestate/test_upload_file.html')

def upload(request):
    if request.method == "POST":
        # form = ModelFormWithFileField(request.POST, request.FILES)

        username = request.POST.get("username")
        title = request.POST.get("title")
        # file = request.POST.get("file")
        obj = Document(username = username, title = title)
        obj.save()
        # instance = ModelWithFileField(file_field=request.FILES["file"])
        # instance.save()
    return render (request, 'realestate/test_upload_file.html')
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
    print("django log: great success wow")
    return render(request,'realestate/buyerHome.html')

def buyerProfile(request):
    return render(request,'realestate/buyerProfile.html')

def showListings(request):
    return render(request,'realestate/showListings.html')

def purchaseHistory(request):
    return render(request,'realestate/purchaseHistory.html')


def loginCheck(request):
    
    
    if request.method == 'POST':
        # # Parse the JSON data from the request
        data = json.loads(request.body)

        # print(data)
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
        # file = data.get('file', '')
        
        verdict = signUp_check(name_tb,username, password, user_type)


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


def upload_pdf(request):
    if request.method == "POST":
        # Perform operations on the PDF file here
        # You can use libraries like PyPDF2 or pdfplumber to work with PDFs

        # For example, you can extract text from the PDF
        # import PyPDF2
        # pdf = PyPDF2.PdfFileReader(pdf_file)
        # text = ""
        # for page in range(pdf.getNumPages()):
        #     text += pdf.getPage(page).extractText()

        # print("django log: ")
        # print('-------------------------------')
        # name = request.POST.get("name_tb")
        # username = request.POST.get("username_tb")
        # password = request.POST.get("password_tb")
        # public_key = request.POST.get("public_key")
        # user_type = request.POST.get("user_type")
        uploaded_file = request.FILES.get("file")
        
        if uploaded_file:
            mongoupload(uploaded_file)
            # Process the uploaded file here
            # Save it in the same directory as your Django project
            # with open(f'my_uploaded_file.pdf', 'wb') as destination:
            #     for chunk in uploaded_file.chunks():
            #         destination.write(chunk)

        
        
        # print(name)
        # print(username)
        # print(password)
        # print(public_key)
        # print(user_type)
        
        #print(pdf_file)
        
        # Return some response
        return JsonResponse({"message": "PDF file uploaded and processed successfully."})

    return JsonResponse({"message": "Invalid request."}, status=400)



