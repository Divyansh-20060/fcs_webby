from django.shortcuts import render
from django.http import HttpResponse

def welcomePage(request):
    return render (request,'realestate/welcomePage.html')


def loginPage(request):
    return render(request, 'realestate/loginPage.html')


def signupPage(request):
    return render(request, 'realestate/signupPage.html')

def mainPage(request):
    return render(request, 'realestate/mainPage.html')