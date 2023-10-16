from django.shortcuts import render, redirect
from realestate.forms import *
from realestate.models import *
from django.contrib import messages
import rsa, hashlib
from django.core.mail import send_mail
from website.settings import EMAIL_HOST_USER
import random
# from sign_logic import *
import re

##input validation
def check_input(string, pattern):
    if re.match(pattern, string):
        return True
    else:
        return False


def otpPage(request):
    
    if 'otp_data' not in request.session:
        return redirect('main welcome')
    
    if request.method == 'POST':
        
        response = request.POST['otp']
        otp_pattern = r"^[0-9]{6}$"
        valid = check_input(response, otp_pattern)
        if not valid:
            messages.success(request, 'yerr on the code injector watchlist')
        else:
            otp_data_dict = request.session['otp_data']
            
            if(otp_data_dict['otp'] != response):
                messages.success(request, 'wrong otp')
            
            else:
                print("success!")
                
                return redirect('sign up page')
    
    return render (request, 'realestate/otpPage.html')

def emailVerifyPage(request):
    
    if request.method == 'POST':
        
        femail = request.POST['email']
        mail_pattern = r"^[\w\.-]{,64}@[\w\.-]{,255}$"
        valid = check_input(femail, mail_pattern)
        if not valid:
            messages.success(request, 'do not inject code, we know your intentions')

        else:
            existing_buyer_email = BuyerInfo.objects.filter(email=femail).exists()
            existing_seller_email = SellerInfo.objects.filter(email=femail).exists()
                
            if existing_buyer_email or existing_seller_email or (len(femail) > 49):
                messages.success(request, 'email already exists or too big')
            
            else:
                
                otp = str(random.randint(100000, 999999))
                
                otp_data = {
                    'email': femail,
                    'otp': otp,
                }
                
                request.session['otp_data'] = otp_data
                
                send_mail('OTP for sign up', otp, EMAIL_HOST_USER,[femail], fail_silently=True)
                
                return redirect('otp verify')
    
    return render(request, 'realestate/emailVerify.html')

def verify_doc(fpublic_key, fproof_of_id):
    user_public_key = rsa.PublicKey.load_pkcs1(fpublic_key.read())
    user_proof_of_id = fproof_of_id.read()
    content = user_proof_of_id[:-256]
    sign = user_proof_of_id[-256:]
    try:
        rsa.verify(content, sign, user_public_key)
        # messages.success(request, "document verified")
        return True
    except:
        # messages.success(request, "document verification failed")
        return False

def signupPage(request):
    
    if request.method == 'POST':
        form = SignupForm(request.POST, request.FILES)
        
        if form.is_valid():
            fname = form.cleaned_data['name']
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            fpublic_key = form.cleaned_data['public_key']
            fproof_of_id = form.cleaned_data['proof_of_id']
            user_type = form.cleaned_data['user_type']


            username_pattern = r"^[a-zA-Z0-9_\-]{4,50}$"
            name_pattern = r"^([a-zA-Z]\s{0,1})+$"
            password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#!%&])[A-Za-z\d@#!%&]{8,}$"

            valid_username_pattern = check_input(fusername, username_pattern)
            valid_name_pattern = check_input(fname, name_pattern)
            valid_password_pattern = check_input(fpassword, password_pattern)

            if not (valid_username_pattern and valid_name_pattern and valid_password_pattern and len(fpassword) >= 8 and len(fpassword) <= 50 and len(fname) >=4 and len(fname)<=50 ):
                messages.success(request, 'Do not inject code, bakayarou')
            else:
                femail = request.session['otp_data']['email']
                existing_seller = SellerInfo.objects.filter(username=fusername).exists()
                existing_buyer = BuyerInfo.objects.filter(username=fusername).exists()
                
                
                f = open("log.txt", "w")
                f.write("form vaid\n")
                f.close()

                if  (not verify_doc(fpublic_key, fproof_of_id)): ## check document signature
                    messages.success(request, 'document verification failed')
                
                elif (existing_seller and user_type == "seller") or (existing_buyer and user_type == "buyer"):
                    messages.success(request, 'already exsitig username or email')


                else:
                    ##store the hash of the password
                    sha512 = hashlib.sha512()
                    sha512.update(fpassword.encode())
                    hashed_fpassword = sha512.hexdigest()
                    
                    
                    if user_type == 'seller':
                        SellerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                        #print("user created ", user_type)
                        messages.success(request, 'sign up successful!')
                        del request.session['otp_data']
                        return redirect("login page")

                    elif user_type == 'buyer':
                        #print("user created ", user_type)
                        BuyerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                        messages.success(request, 'sign up successful!')
                        del request.session['otp_data']
                        return redirect("login page")

                    else:
                        #print("what da hell you doing cuh!")
                        messages.success(request, 'there was an error with your form please try again')
                        
                        
        else:
            f = open("log.txt", "w")
            f.write("form invaid\n")
            f.close()
            #print('erm what the scallop!')
            messages.success(request, 'there was an error with your form please try again')
            #print(form.errors)
    
    
    else:
        form = SignupForm()
        
    return render(request, 'realestate/signupPage.html', {'form':form})

def loginPage(request):
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        if form.is_valid():
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            user_type = form.cleaned_data['user_type']

            username_pattern = r"^[a-zA-Z0-9_\-]{4,50}$"
            password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#!%&])[A-Za-z\d@#!%&]{8,}$"

            valid_username_pattern = check_input(fusername, username_pattern)
            valid_password_pattern = check_input(fpassword, password_pattern)
            if not ( valid_username_pattern and valid_password_pattern and len(fpassword) >= 8 and len(fpassword) <= 50):
                messages.success(request, 'Do not inject code, bakayarou')
            else:
                ##calculate the hash of the password
                sha512 = hashlib.sha512()
                sha512.update(fpassword.encode())
                hashed_fpassword = sha512.hexdigest()
                if user_type == 'buyer':
                    ucheck = BuyerInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                    
                    if ucheck:
                        print("log in success ",user_type)
                        messages.success(request, 'log in successful! redirecting...')
                        return redirect("buyer home")
                    
                    else:
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credntials.')

                elif user_type == 'seller':
                    ucheck = SellerInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                    
                    if ucheck:
                        print("log in success ",user_type)
                        messages.success(request, 'log in successful! redirecting...')
                        return redirect("seller home")
                    
                    else:
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credntials.')
                
                elif user_type == 'admin':
                    ucheck = AdminInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                    
                    if ucheck:
                        print("log in success ",user_type)
                        messages.success(request, 'log in successful! redirecting...')
                        return redirect("admin home")
                    
                    else:
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credntials.')
                
                else:
                    print("invalid ass behavior")
                    messages.error(request, 'What is this behavior man')
            
        else:
            print("invalid form")
            messages.error(request, 'invalid form. Try again')
            
    else:
        form = LoginForm()
    
    messages.get_messages(request).used = True
    return render(request, 'realestate/loginPage.html',{'form':form})



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

def buyerHome(request):
    # print("django log: great success wow")
    return render(request,'realestate/buyerHome.html')

def buyerProfile(request):
    return render(request,'realestate/buyerProfile.html')

def showListings(request):
    return render(request,'realestate/showListings.html')

def purchaseHistory(request):
    return render(request,'realestate/purchaseHistory.html')

def sellerProfile(request):
    return render (request, 'realestate/sellerProfile.html')

