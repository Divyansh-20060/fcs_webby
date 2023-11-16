from django.shortcuts import render, redirect
from django.urls import reverse
import requests
from realestate.forms import *
from realestate.models import *
from django.contrib import messages
import rsa, hashlib
from django.core.mail import send_mail
from website.settings import EMAIL_HOST_USER
import secrets
import re
from datetime import date
from datetime import datetime
from django.core.files.base import ContentFile
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import razorpay
from django.views.decorators.csrf import csrf_exempt

##Regexes
otps = [int(i) for i in range(100000,1000000)]
username_pattern = r"^[a-zA-Z0-9_\-]{4,50}$"
name_pattern = r"^(?=.{4,50}$)([a-zA-Z]\s{0,1})+$"
password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#!%&])[A-Za-z\d@#!%&]{8,50}$"
otp_pattern = r"^[0-9]{6}$"
type_property_pattern = r"^[a-zA-Z]{4,50}$"
amenities_pattern = r"^[a-zA-Z]{4,50}$"
budget_pattern = r"^[1-9][0-9]{0,19}$"
locality_pattern = r"^(?=.{1,150}$)([a-zA-Z0-9\-]\s{0,1})+$"
type_contract_pattern = r"^(sale|rental)$"
date_pattern = r"^(((\d{4}\-((0[13578]\-|1[02]\-)(0[1-9]|[12]\d|3[01])|(0[13456789]\-|1[012]\-)(0[1-9]|[12]\d|30)|02\-(0[1-9]|1\d|2[0-8])))|((([02468][048]|[13579][26])00|\d{2}([13579][26]|0[48]|[2468][048])))\-02\-29)){0,10}$"


def generate_salt():
    salt_length = 64
    salt = secrets.token_hex(salt_length)
    return salt



def ekyc_info_checker(request):
    
    check = True
    if 'ekyc_data' not in request.session:
        check = False
        
    elif 'email' not in request.session['ekyc_data'] or 'status' not in request.session['ekyc_data']:
        check = False
        
    if (check == False):
        messages.success(request, 'ekyc not done')
        
    
    return check
    
def user_data_checker(request):
    
    check = True
    
    if 'user_data' not in request.session:
        check = False
        
    elif 'user_type' not in request.session['user_data'] or 'username' not in request.session['user_data']:
        check = False
        
    if (check == False):
        messages.success(request, 'please log in first!')
        
    return check


def position_checker(request):
    
    check = True
    
    if 'position' not in request.session:
        check = False
        
    if (check == False):
        messages.success(request, 'undifined behavior!')
        
    return check

def returnHome(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    user_type = request.session['user_data']['user_type']
    
    if(user_type == "seller"):
        return redirect("seller home")

    elif(user_type == "buyer"):
        return redirect("buyer home")
    
    elif(user_type == "admin"):
        return redirect("admin home")
    
    else:
        return redirect("main welcome")
    
def verify_doc(request, public_key_bin, document_bin, signer):
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_bin)
        content = document_bin.split(b"signature:")[0]
        signature = document_bin.split(signer.encode())[-2]
        rsa.verify(content, bytes.fromhex(signature.decode()), public_key)
        return True
    except rsa.pkcs1.CryptoError as crypto_error:
        # print(crypto_error)
        # messages.success(request, crypto_error)
        return False
    except Exception as e:
        # print("error:", e)
        messages.success(request, e)
        messages.success(request, len(content))
        return False

def verify_doc2(request, public_key_bin, document_bin, signature):
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_bin)
        content = document_bin.split(b"signature:")[0]
        # signature = document_bin.split(signer.encode())[-2]
        rsa.verify(content, bytes.fromhex(signature), public_key)
        return True
    except rsa.pkcs1.CryptoError as crypto_error:
        # print(crypto_error)
        # messages.success(request, crypto_error)
        return False
    except Exception as e:
        messages.success(request, e)
        messages.success(request, len(content))
        return False


def get_sign(private_key_bin, document_bin):##paths of the private key and the document to be signed
    ##load the private key into a variable
    private_key = rsa.PrivateKey.load_pkcs1(private_key_bin)

    file_content = document_bin.split(b"signature:")[0]
    signature = rsa.sign(file_content, private_key, "SHA-512").hex()
    return signature

def check_input(string, pattern):
    if re.match(pattern, string):
        return True
    else:
        return False

def ekyc2(request,listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    user_type = request.session['user_data']['user_type']
    
    if( user_type != 'buyer' and user_type != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        
        session_email = request.session['ekyc_data']['email']
        session_status = request.session['ekyc_data']['status']

        if email != session_email:
            messages.success(request, 'Use the same email as you did at initial ekyc!')
        
        elif session_status != 'success':
            messages.success(request, "Can't verify your initial ekyc login please start over.")
            return redirect('ekyc page')
        
        else:
            data = {
                'email': email,
                'password': password
            }

            response = requests.post("https://192.168.3.39:5000/kyc", json=data, verify=False)
                
            response_data = response.json()
            message = response_data['message']
            status = response_data['status']
            
            messages.success(request, message)

            if(status == 'success'):
                
                if 'user_data' not in request.session:
                    return redirect("main welcome")
                
                
                if request.session['user_data']['user_type'] == 'buyer':
                    request.session['ekyc2_status'] = True
                    val = listing_id
                    url =  reverse('makePayment', args=[val])
                    return redirect(url)
                
                elif request.session['user_data']['user_type'] == 'seller':
                    request.session['ekyc2_status'] = True
                    val = listing_id
                    url =  reverse('sellerSignContract', args=[val])
                    return redirect(url)
                
                else:
                    return redirect("main welcome")
    return render (request, 'realestate/ekycPage.html')

def ekycStart(request):
    if request.method == "POST":
        
        email = request.POST.get('email')
        password = request.POST.get('password')        
        
        data = {
            'email': email,
            'password': password
        }

        response = requests.post("https://192.168.3.39:5000/kyc", json=data, verify=False)
            
        response_data = response.json()
            
        message = response_data['message']
        status = response_data['status']
            
        messages.success(request, message)

        if(status == 'success'):
            request.session['ekyc_data'] = {
                'email': email,
                'status' : status
            }
            return redirect('main welcome')

    return render (request, 'realestate/ekycPage.html')

def mainWelcome(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    request.session['position'] = 'main_welcome'
    return render (request,'realestate/mainWelcome.html')

def emailVerifyPage(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if (position_checker(request) == False):
        return redirect('ekyc page')
    
    if request.method == 'POST':
        
        femail = request.POST['email']
        mail_pattern = r"^[\w\.-]{,64}@[\w\.-]{,255}$"
        valid = check_input(femail, mail_pattern)
        if not valid:
            messages.success(request, 'do not inject code, we know your intentions')

        else:
            existing_buyer_email = BuyerInfo.objects.filter(email=femail).exists()
            existing_seller_email = SellerInfo.objects.filter(email=femail).exists()
                
            if existing_buyer_email or existing_seller_email:
                messages.success(request, 'email already exists or too big')
            
            else:
                
                # otp = str(random.randint(100000, 999999))
                otp = str(secrets.choice(otps))
                otp_data = {
                    'email': femail,
                    'otp': otp,
                }
                
                request.session['otp_data'] = otp_data
                
                send_mail('OTP for sign up', otp, EMAIL_HOST_USER,[femail], fail_silently=True)
                
                return redirect('otp verify')
    
    return render(request, 'realestate/emailVerify.html')


def otpPage(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if 'otp_data' not in request.session:
        messages.success(request,"weird behavior!")
        return redirect('main welcome')
    
    if (position_checker(request) == False):
        return redirect(request,"wowowowowoowowowowowowowowowowoowowowowowkdsjsjfkjdjfdjlakfjalfskfsjdfjlksdfjk ahhhhhhhhhhhhhhhhhh i can't do this anymore ahhhhhhhhhhhhhhhhh god help mememmemememasdkd asddhhhh")
    
    if request.method == 'POST':
        
        response = request.POST['otp']
        
        valid = check_input(response, otp_pattern)
        
        if not valid:
            messages.success(request, 'yerr on the code injector watchlist')
            
        else:
            otp_data_dict = request.session['otp_data']
            
            if(otp_data_dict['otp'] != response):
                messages.success(request, 'wrong otp')
            
            else:
            
                
                if request.session['position'] == 'main_welcome':
                
                    return redirect('sign up page')

                elif request.session['position'] == 'profile_page':
                    
                    if (user_data_checker(request) == False):
                        return redirect('main welcome')
    
                    user_type = request.session['user_data']['user_type']
                    cusername = request.session['user_data']['username']
                    
                    user_entry_buyer = BuyerInfo.objects.filter(username=cusername).first()
                    user_entry_seller = SellerInfo.objects.filter(username=cusername).first()
                    
                    if user_type == 'buyer' and user_entry_buyer:
                        
                        user_entry_buyer.email = otp_data_dict['email']
                        user_entry_buyer.save()
                        messages.success(request,"email updated!")
                        del request.session['otp_data']
                        return redirect('user Profile')
                        
                    elif user_type == 'seller' and user_entry_seller:
                        user_entry_seller.email = otp_data_dict['email']
                        user_entry_seller.save()
                        messages.success(request,"email updated!")
                        del request.session['otp_data']
                        return redirect('user Profile')
                    
                    else:
                        print('user not found!')
                        del request.session['otp_data']
                        return redirect('main welcome')
                
                else:
                    return redirect('main welcome')
    
    return render (request, 'realestate/otpPage.html')


def signupPage(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if 'otp_data' not in request.session:
        return redirect('main welcome')
    
    if request.method == 'POST':
        form = SignupForm(request.POST, request.FILES)
        
        if form.is_valid():
            fname = form.cleaned_data['name']
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            fpublic_key = form.cleaned_data['public_key']
            fproof_of_id = form.cleaned_data['proof_of_id']
            user_type = form.cleaned_data['user_type']
            # messages.success(request, type(fpublic_key))


            valid_username_pattern = check_input(fusername, username_pattern)
            valid_name_pattern = check_input(fname, name_pattern)
            valid_password_pattern = check_input(fpassword, password_pattern)

            if not (valid_username_pattern and valid_name_pattern and valid_password_pattern ):
                messages.success(request, 'Do not inject code, bakayarou')
            else:
                femail = request.session['otp_data']['email']
                existing_seller = SellerInfo.objects.filter(username=fusername).exists()
                existing_buyer = BuyerInfo.objects.filter(username=fusername).exists()
                
                
                f = open("log.txt", "w")
                f.write("form vaid\n")
                f.close()

                # if  (not verify_doc(request, fpublic_key.read(), fproof_of_id.read(), "")): ## check document signature
                #     messages.success(request, 'document verification failed')
                
                if (existing_seller and user_type == "seller") or (existing_buyer and user_type == "buyer"):
                    messages.success(request, 'already exsitig username or email')


                else:
                    ##salt the password and store the hash of the password and the salt
                    sha512 = hashlib.sha512()
                    salt = generate_salt()
                    salted_password = fpassword + salt
                    sha512.update(salted_password.encode())
                    hashed_fpassword = sha512.hexdigest()
                    
                    
                    if user_type == 'seller':
                        if  (not verify_doc(request, fpublic_key.read(), fproof_of_id.read(), "seller")): ## check document signature
                            messages.success(request, 'document verification failed')
                        else:
                            SellerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, salt = salt,  public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                            #print("user created ", user_type)
                            messages.success(request, 'sign up successful!')
                            del request.session['otp_data']
                            return redirect("login page")

                    elif user_type == 'buyer':
                        #print("user created ", user_type)
                        if  (not verify_doc(request, fpublic_key.read(), fproof_of_id.read(), "buyer")): ## check document signature
                            messages.success(request, 'document verification failed')
                        else:
                            BuyerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, salt = salt, public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
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
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        if form.is_valid():
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            user_type = form.cleaned_data['user_type']


            valid_username_pattern = check_input(fusername, username_pattern)
            valid_password_pattern = check_input(fpassword, password_pattern)

            if not ( valid_username_pattern and valid_password_pattern):
                messages.success(request, 'Do not inject code, bakayarou')
            else:

                if user_type == 'buyer' and BuyerInfo.objects.filter(username= fusername).exists():
                    ##get the salt first
                    obj = BuyerInfo.objects.get(username= fusername)
                    if obj:
                        stored_salt = obj.salt

                        ##calculate the hash of the password
                        sha512 = hashlib.sha512()
                        salted_password = fpassword + stored_salt
                        sha512.update(salted_password.encode())
                        hashed_fpassword = sha512.hexdigest()

                        ucheck = BuyerInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                        
                        if ucheck:
                            print("log in success ",user_type)
                            messages.success(request, 'log in successful! redirecting...')
                            
                            user_data = {
                                'username': fusername,
                                'user_type': user_type,
                            }
                    
                            request.session['user_data'] = user_data
                            
                            return redirect("buyer home")
                        
                        else:
                            print("log in failed ",user_type)
                            messages.error(request, 'log in failed. Chek credentials.')
                    else:
                        # print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credentials.')

                elif user_type == 'seller' and SellerInfo.objects.filter(username= fusername).exists():
                    obj = SellerInfo.objects.get(username= fusername)
                    if obj:
                        stored_salt = obj.salt
                        ##calculate the hash of the password
                        sha512 = hashlib.sha512()
                        salted_password = fpassword + stored_salt
                        sha512.update(salted_password.encode())
                        hashed_fpassword = sha512.hexdigest()

                        ucheck = SellerInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                        
                        if ucheck:
                            print("log in success ",user_type)
                            messages.success(request, 'log in successful!')
                            
                            user_data = {
                                'username': fusername,
                                'user_type': user_type,
                            }
                    
                            request.session['user_data'] = user_data
                            
                            return redirect("seller home")
                        
                        else:
                            print("log in failed ",user_type)
                            messages.error(request, 'log in failed. Chek credentials.')
                    else:
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credentials.')

                
                elif user_type == 'admin' and AdminInfo.objects.filter(username= fusername).exists():
                    obj = AdminInfo.objects.get(username= fusername)
                    if obj:
                        stored_salt = obj.salt
                        ##calculate the hash of the password
                        sha512 = hashlib.sha512()
                        salted_password = fpassword + stored_salt
                        sha512.update(salted_password.encode())
                        hashed_fpassword = sha512.hexdigest()

                        ucheck = AdminInfo.objects.filter(username= fusername, password = hashed_fpassword).exists()
                        
                        if ucheck:
                            print("log in success ",user_type)
                            messages.success(request, 'log in successful!')
                            
                            
                            user_data = {
                                'username': fusername,
                                'user_type': user_type,
                            }
                    
                            request.session['user_data'] = user_data
                            
                            return redirect("admin home")
                        
                        else:
                            print("log in failed ",user_type)
                            messages.error(request, 'log in failed. Chek credentials.')
                    else:
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credentials.')
                
                else:
                    print("invalid ahh behavior")
                    messages.error(request, 'What is this behavior man')
            
        else:
            print("invalid form")
            messages.error(request, 'invalid form. Try again')
            
    else:
        form = LoginForm()
    
    messages.get_messages(request).used = True
    return render(request, 'realestate/loginPage.html',{'form':form})

def sellerHome(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if (user_data_checker(request) == False):
        return redirect('main welcome')
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    return render(request,'realestate/sellerHome.html')

def createListing(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if 'before_verdict' not in request.session:
        messages.success(request,"please do the otp check")
        return redirect('seller home')
    
    if  request.session['before_verdict']['success'] != True:
        messages.success(request,"please do the otp check correctly")
        return redirect('seller home')
    
    if request.method == "POST":
        
        form = CreateListingForm(request.POST, request.FILES)
        
        if form.is_valid():
            # messages.success(request, "yo form is valid")  
            ftype_property = form.cleaned_data['type_property']
            fdate = form.cleaned_data['date']
            famenities = form.cleaned_data['amenities']
            fbudget = form.cleaned_data['budget']
            flocality = form.cleaned_data['locality']
            ftype_contract = form.cleaned_data['type_contract']
            fownershipDoc = form.cleaned_data['ownershipDoc']
            fidentityDoc = form.cleaned_data['identityDoc']
            username = request.session['user_data']['username']


            ##validate input
            valid_ftype_property = check_input(ftype_property, type_property_pattern)
            valid_fdate = check_input(str(fdate), date_pattern)
            valid_famenities = check_input(famenities, amenities_pattern)
            valid_fbudget = check_input(str(fbudget), budget_pattern)
            valid_flocality = check_input(flocality, locality_pattern)
            valid_ftype_contract = check_input(ftype_contract, type_contract_pattern)
            
            ##check signature on ownershipdoc and identity doc
            pulic_key = SellerInfo.objects.get(username= username).public_key.open('rb').read()
            # messages.success(request, (pulic_key.read()))
            fownershipDoc_signature_valid = verify_doc(request, pulic_key, fownershipDoc.read(), "seller")
            fidentityDoc_signature_valid = verify_doc(request, pulic_key, fidentityDoc.read(), "seller")
            if not (fidentityDoc_signature_valid and fownershipDoc_signature_valid):
                messages.success(request, "document verification failed")  

            else:
                if not (valid_ftype_property and valid_fdate and valid_famenities and valid_fbudget and valid_flocality and valid_ftype_contract):
                    messages.success(request, 'Do not inject code, bakayarou')
                else:
                    ListingInfo.objects.create(typePropety = ftype_property, seller = username, status = "unsold", date = fdate, amenity = famenities, budget = fbudget, locality = flocality, typeContract = ftype_contract, ownershipDoc = fownershipDoc, identityDoc = fidentityDoc, malicious = False )
                    messages.success(request, 'listing created successfully')
                    del request.session['before_verdict']
                    return redirect("seller home")
        else:
            messages.success(request, 'what is wrong with you')
    else:
        form = CreateListingForm()
    
    return render(request,"realestate/createListing.html", {'form':form})


def userProfile(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    user_type = request.session['user_data']['user_type']
    
    if( user_type != 'buyer' and user_type != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    user_data_checker(request)
    
    username = request.session['user_data']['username']
    user_type = request.session['user_data']['user_type']
    
    user_info = None
    
    if user_type == 'seller':
        user_info = SellerInfo.objects.get(username=username)
    elif user_type == 'buyer':
        user_info = BuyerInfo.objects.get(username=username)
    else:
        messages.success(request, 'invalid user type!')
        return redirect('main welcome')
    
    request.session['position'] = 'profile_page'
    
    return render (request, 'realestate/userProfile.html', {'user_info': user_info})

def updatePassword(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if request.method == 'POST':
        
        form = PasswordForm(request.POST)
        
        if form.is_valid():
            foldpass = form.cleaned_data['old_password']
            fnewpass = form.cleaned_data['new_password']
            fconfpass = form.cleaned_data['confirm_new_password']
            
            check_old_pass_regx = check_input(foldpass,password_pattern)
            check_new_pass_regx = check_input(fnewpass,password_pattern)
            check_conf_regx = check_input(fconfpass,password_pattern)
            
            if not (check_conf_regx) or not(check_new_pass_regx) or not(check_old_pass_regx):
                messages.success(request,"Please stick to the password format")
            
            else:
                # sha512 = hashlib.sha512()
                # sha512.update(foldpass.encode())
                # hashed_fpassword = sha512.hexdigest()

                user_type = request.session['user_data']['user_type']
                cusername = request.session['user_data']['username']

                if user_type == 'buyer':
                    obj = BuyerInfo.objects.filter(username=cusername).first()
                    sha512 = hashlib.sha512()
                    stored_salt = obj.salt
                    salted = foldpass + stored_salt
                    sha512.update(salted.encode())
                    hashed_fpassword = sha512.hexdigest()
                    if BuyerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
                        if fnewpass != fconfpass:
                            messages.success(request,"new passwords don't match")
                        else:
                            sha512 = hashlib.sha512()
                            salt = generate_salt()
                            salted_fnewpass = fnewpass + salt
                            sha512.update(salted_fnewpass.encode())
                            hashed_newpassword = sha512.hexdigest()
                    
                            user_entry = BuyerInfo.objects.filter(username=cusername).first()
                            
                            if user_entry:
                                user_entry.password = hashed_newpassword
                                user_entry.salt = salt
                                user_entry.save()
                                messages.success(request,"password updated!")
                                return redirect('user Profile')
                                
                            else:
                                messages.success(request,"user does not exist!")
                                return redirect('main welcome')
                    else:
                        messages.success(request,'old password dose not match!')

                elif user_type == 'seller':
                    obj = SellerInfo.objects.filter(username=cusername).first()
                    sha512 = hashlib.sha512()
                    stored_salt = obj.salt
                    salted = foldpass + stored_salt
                    sha512.update(salted.encode())
                    hashed_fpassword = sha512.hexdigest()
                    if SellerInfo.objects.filter(username=cusername,password= hashed_fpassword).exists():
                        if fnewpass != fconfpass:
                            messages.success(request,"new passwords don't match")
                        
                        else:
                            
                            sha512 = hashlib.sha512()
                            salt = generate_salt()
                            salted_fnewpass = fnewpass + salt
                            sha512.update(salted_fnewpass.encode())
                            hashed_newpassword = sha512.hexdigest()
                    
                            user_entry = SellerInfo.objects.filter(username=cusername).first()
                            
                            if user_entry:
                                user_entry.password = hashed_newpassword
                                user_entry.salt = salt
                                user_entry.save()
                                messages.success(request,"password updated!")
                                return redirect('user Profile')
                                
                            else:
                                messages.success(request,"user does not exist!")
                                return redirect('main welcome')   
                    else:
                        messages.success(request,'old password dose not match!')
                
                elif user_type == 'admin':
                    obj = AdminInfo.objects.filter(username=cusername).first()
                    sha512 = hashlib.sha512()
                    stored_salt = obj.salt
                    salted = foldpass + stored_salt
                    sha512.update(salted.encode())
                    hashed_fpassword = sha512.hexdigest()
                    if AdminInfo.objects.filter(username=cusername,password= hashed_fpassword).exists():
                        if fnewpass != fconfpass:
                            messages.success(request,"new passwords don't match")
                        
                        else:
                            
                            sha512 = hashlib.sha512()
                            salt = generate_salt()
                            salted_fnewpass = fnewpass + salt
                            sha512.update(salted_fnewpass.encode())
                            hashed_newpassword = sha512.hexdigest()
                    
                            user_entry = AdminInfo.objects.filter(username=cusername).first()
                            
                            if user_entry:
                                user_entry.password = hashed_newpassword
                                user_entry.salt = salt
                                user_entry.save()
                                messages.success(request,"password updated!")
                                return redirect('admin Profile')
                                
                            else:
                                messages.success(request,"user does not exist!")
                                return redirect('main welcome')   
                    else:
                        messages.success(request,'old password dose not match!')
                
                
                else:
                    messages.success(request,'invalid user_type')
                    
        else:
            messages.success(request,'please fill the form correctly')
    
    else:
        form = PasswordForm()
        
    return render(request,'realestate/updatePassword.html',{'form':form})


def updateNamePOI(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    user_type = request.session['user_data']['user_type']
    
    if( user_type != 'buyer' and user_type != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if request.method == 'POST':
        
        name = None
        proof_of_id = None
        
        # if request.POST['name'] == None:
        #     print("name empty")
        
        # print(request.POST.get('name'))
        # if request.FILES.get('proof_of_id') == None:
        #     print('file empty')
        
        if 'name' in request.POST:
            name = request.POST['name']
        
        if 'proof_of_id' in request.FILES:
            proof_of_id = request.FILES['proof_of_id']
        
        password = request.POST['password']
            
        # sha512 = hashlib.sha512()
        # sha512.update(password.encode())
        # hashed_fpassword = sha512.hexdigest()
            
        user_type = request.session['user_data']['user_type']
        cusername = request.session['user_data']['username']
            
            
        user_entry_buyer = BuyerInfo.objects.filter(username=cusername).first()
        user_entry_seller = SellerInfo.objects.filter(username=cusername).first()
            
        # if user_type == 'buyer' and BuyerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
        if user_type == 'buyer' and BuyerInfo.objects.filter(username=cusername).exists():
            obj = BuyerInfo.objects.get(username= cusername)
            stored_salt = obj.salt
            ##calculate the hash of the password
            sha512 = hashlib.sha512()
            salted_password = password + stored_salt
            sha512.update(salted_password.encode())
            hashed_fpassword = sha512.hexdigest()

            if (BuyerInfo.objects.filter(password=hashed_fpassword).exists()):
                name_check = False
                file_check = False
                
                if name and name != '':
                    
                    if (check_input(name,name_pattern) and len(name) >=4):
                        user_entry_buyer.name = name
                        name_check = True
                    else:
                        messages.success(request, "Format of name is incorrect. Not updated.")
                        
                if proof_of_id:
                        
                    public_key = user_entry_buyer.public_key
                        
                    if(verify_doc(request, public_key.open('rb').read(),proof_of_id.read(), "buyer" )):
                        
                        user_entry_buyer.proof_of_id = proof_of_id
                        file_check = True

                    else:
                        messages.success(request, "Public key does not match. Not updated.")
                        
                user_entry_buyer.save()
                
                if name_check:
                    messages.success(request, "name updated!")
                
                if file_check:
                    messages.success(request, "Proof of id updated!")
                
                return redirect('user Profile')
            else:
                messages.success(request, "Incorrect password!")

                
        # elif user_type == 'seller' and  SellerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
        elif user_type == 'seller' and  SellerInfo.objects.filter(username=cusername).exists():
            obj = SellerInfo.objects.get(username= cusername)
            stored_salt = obj.salt
            ##calculate the hash of the password
            sha512 = hashlib.sha512()
            salted_password = password + stored_salt
            sha512.update(salted_password.encode())
            hashed_fpassword = sha512.hexdigest()


            if (SellerInfo.objects.filter(password=hashed_fpassword).exists()):
                name_check = False
                file_check = False
                
                
                if name and name != '':
                    
                    if (check_input(name,name_pattern) and len(name) >=4):
                        user_entry_seller.name = name
                        name_check = True
                    else:
                        messages.success(request, "Format of name is incorrect. Not updated.")
                    
                    
                if proof_of_id:
                        
                    public_key = user_entry_seller.public_key
                        
                    if(verify_doc(request, public_key.open('rb').read(),proof_of_id.read(), "seller")):
                        
                        user_entry_seller.proof_of_id = proof_of_id
                        file_check = True

                    else:
                        messages.success(request, "Public key does not match. Not updated.")
                    
                user_entry_seller.save()
                    
                if name_check:
                    messages.success(request, "Name updated!")
                
                if file_check:
                    messages.success(request, "Proof of id updated!")
                
                return redirect('user Profile')
            else:
                messages.success(request, "Incorrect password!")
            
        else:
            messages.success(request, "Incorrect password!1")
            
    return render(request,'realestate/updateNamePOI.html')


def adminHome(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    elif (user_data_checker(request) == False):
        return redirect('main welcome')
    
    elif( request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    else:
        return render(request,'realestate/adminHome.html')

def buyerHome(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    else:
        return render(request,'realestate/buyerHome.html')

########################### Legacy ############

# def buyerHome(request):
    
#     if (ekyc_info_checker(request) == False):
#         return redirect('ekyc page')
    
#     # print("django log: great success wow")
#     return render(request,'realestate/buyerHome.html')




def viewSellerListings(request):

    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    username = request.session['user_data']['username']

    if username:
        seller_info = ListingInfo.objects.filter(seller=username)
        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
    else:
        # Handle the case where username is not in the session
        # Redirect to an error page, display a message, etc.
        return render(request, 'error.html', {'message': 'Username not found in session'})

def viewBuyerListings(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')

    if request.method == "POST":
        form = filterForm(request.POST)
        if form.is_valid():
            # messages.success(request, "yo form is valid")  
            ftype_property = form.cleaned_data['type_property']
            famenities = form.cleaned_data['amenities']
            flocality = form.cleaned_data['locality']
            ftype_contract = form.cleaned_data['type_contract']

            f_min_date = form.cleaned_data['min_date']
            f_max_date = form.cleaned_data['max_date']

            f_min_budget = form.cleaned_data['min_budget']
            f_max_budget = form.cleaned_data['max_budget']


            ##validate input
            valid_ftype_property = check_input(ftype_property, type_property_pattern)
            valid_famenities = check_input(famenities, amenities_pattern)
            valid_flocality = check_input(flocality, locality_pattern)
            valid_ftype_contract = check_input(ftype_contract, type_contract_pattern)

            valid_f_min_date = check_input(str(f_min_date), date_pattern)
            valid_f_max_date = check_input(str(f_max_date), date_pattern)

            valid_f_min_budget = check_input(str(f_min_budget), budget_pattern)
            valid_f_max_budget = check_input(str(f_max_budget), budget_pattern)

            if not (valid_ftype_property and valid_f_min_date and valid_f_max_date and valid_famenities and valid_f_min_budget and valid_f_max_budget and valid_flocality and valid_ftype_contract):
                messages.success(request, 'Do not inject code, bakayarou')
            else:
                ## now apply filters 
                queryset = ListingInfo.objects.filter(status="unsold")
                queryset = queryset.filter(typePropety__icontains=ftype_property)
                queryset = queryset.filter(amenity__icontains=famenities)
                queryset = queryset.filter(locality__icontains=flocality)
                queryset = queryset.filter(typeContract__icontains=ftype_contract)
                queryset = queryset.filter(date__gte=f_min_date)
                queryset = queryset.filter(date__lte=f_max_date)
                queryset = queryset.filter(budget__gte=f_min_budget)
                queryset = queryset.filter(budget__lte=f_max_budget)
                return render(request, 'realestate/viewBuyerListings.html', {'listing_info': queryset,'form':form})
        else:
            messages.success(request, 'what is wrong with you')
    else:
        form = filterForm()
        listing_info = ListingInfo.objects.filter(status="unsold")
        return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info, 'form':form})

def edit_listing(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "unsold":
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    # return render(request, 'realestate/edit_listing.html', {'listing': listing})

    if request.method == 'POST':
        form = CreateListingForm(request.POST, request.FILES)
        # form = CreateListingForm(request.POST, request.FILES)

        if form.is_valid():
            ftype_property = form.cleaned_data['type_property']
            fdate = form.cleaned_data['date']
            famenities = form.cleaned_data['amenities']
            fbudget = form.cleaned_data['budget']
            flocality = form.cleaned_data['locality']
            ftype_contract = form.cleaned_data['type_contract']
            fownershipDoc = form.cleaned_data['ownershipDoc']
            fidentityDoc = form.cleaned_data['identityDoc']
            username = request.session['user_data']['username']

            ##validate input
            valid_ftype_property = check_input(ftype_property, type_property_pattern)
            valid_fdate = check_input(str(fdate), date_pattern)
            valid_famenities = check_input(famenities, amenities_pattern)
            valid_fbudget = check_input(str(fbudget), budget_pattern)
            valid_flocality = check_input(flocality, locality_pattern)
            valid_ftype_contract = check_input(ftype_contract, type_contract_pattern)

            ##check signature on ownershipdoc and identity doc
            pulic_key = SellerInfo.objects.get(username= username).public_key.open('rb').read()
            # messages.success(request, (pulic_key.read()))
            fownershipDoc_signature_valid = verify_doc(request, pulic_key, fownershipDoc.read(), "seller")
            fidentityDoc_signature_valid = verify_doc(request, pulic_key, fidentityDoc.read(), "seller")
            if not (fidentityDoc_signature_valid and fownershipDoc_signature_valid):
                messages.success(request, "document verification failed")  
            else:
                if not (valid_ftype_property and valid_fdate and valid_famenities and valid_fbudget and valid_flocality and valid_ftype_contract):
                    messages.success(request, 'Do not inject code, bakayarou')
                else:
                    listing.type_property = form.cleaned_data['type_property']
                    listing.date = form.cleaned_data['date']
                    listing.amenities = form.cleaned_data['amenities']
                    listing.budget = form.cleaned_data['budget']
                    listing.locality = form.cleaned_data['locality']
                    listing.type_contract = form.cleaned_data['type_contract']
                    listing.ownershipDoc = form.cleaned_data['ownershipDoc']
                    listing.identityDoc = form.cleaned_data['identityDoc']
                    listing.save()  # Save the updated data to the listing
                    return redirect('view seller listings')  # Redirect to the seller info page or other appropriate page
        else:
            messages.success(request, 'what is wrong with you')

    else:
        form = CreateListingForm()

    return render(request, 'realestate/edit_listing.html', {'form': form, 'listing': listing})

def delete_listing(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')

    
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "unsold":
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')

    if request.method == "POST":
        listing.delete()
        return redirect('view seller listings')
    return render(request, 'realestate/confirm_delete_listing.html', {'listing': listing})



def create_contract_sale(filename, typePropety, seller, buyer, date_of_availibility, amenity, price, locality, typeContract ):
    current_datetime = datetime.now()
    current_date_string = current_datetime.strftime("%d %B %Y")

    c = canvas.Canvas(filename, pagesize = letter)
    delta = 30
    base = 750
    c.drawString(100, base-1*delta, "typePropety: {}".format(typePropety) )
    if typeContract == "sale":
        c.drawString(250, base-0*delta, "Sale Contract")
        c.drawString(100, base-2*delta, "seller: {}".format(seller) )
        c.drawString(100, base-3*delta, "buyer: {}".format(buyer) )
    else:
        c.drawString(250, base-0*delta, "Rent Contract")
        c.drawString(100, base-2*delta, "lessor: {}".format(seller) )
        c.drawString(100, base-3*delta, "lessee: {}".format(buyer) )
    c.drawString(100, base-4*delta, "date_of_availibility: {}".format(date_of_availibility) )
    c.drawString(100, base-5*delta, "amenity: {}".format(amenity) )
    c.drawString(100, base-6*delta, "price: {}".format(price) )
    c.drawString(100, base-7*delta, "locality: {}".format(locality) )
    c.drawString(100, base-8*delta, "typeContract: {}".format(typeContract) )
    c.drawString(100, base-9*delta, "Date of contract: {}".format(current_date_string) )
    c.showPage()
    # c.save()
    pdf_data = c.getpdfdata()
    return pdf_data

def buyerSignContract(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    
    
    if 'sign_otp_verdict' not in request.session:
        messages.success(request,"please do the otp check")
        return redirect('seller home')
    
    if  request.session['sign_otp_verdict']['success'] != True:
        messages.success(request,"please do the otp check correctly")
        return redirect('seller home')
    
    
    listing_info = ListingInfo.objects.filter(buyer=request.session['user_data']['username'])
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "seller_interested":
        messages.success(request,"please do the otp check correctly")
        return redirect('seller home')

    type_contract = listing.typeContract
    if request.method == "POST": ##when buyer submits the signature form
        form = submitSignatureform(request.POST)
        if form.is_valid():
            try:
                buyer_signature = form.cleaned_data['signature']
                ## validate the signature too for code injection and stuff
                buyer_public_key = BuyerInfo.objects.get(username = request.session['user_data']['username'] ).public_key
                buyer_public_key_bin = buyer_public_key.open("rb").read()
                if type_contract == "sale":
                    contract = listing.saleContract.open("rb").read()
                    buyer_sign_valid = verify_doc2(request, buyer_public_key_bin, contract, buyer_signature)
                    if buyer_sign_valid:
                        listing.buyer_sign = buyer_signature
                        if listing.seller_sign:
                            listing.status = "signs_uploaded"
                        listing.save()
                        messages.success(request, "signature verified")
                        return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})
                    else:
                        if listing.saleContract:
                            listing.saleContract.delete()
                        listing.save()
                        messages.success(request, "signature NOT valid")
                        return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})
                else:
                    contract = listing.rentalContract_buyer.open("rb").read()
                    buyer_sign_valid = verify_doc2(request, buyer_public_key_bin, contract, buyer_signature)
                    if buyer_sign_valid:
                        listing.buyer_sign = buyer_signature
                        if listing.seller_sign:
                            listing.status = "signs_uploaded"
                        listing.save()
                        messages.success(request, "signature verified")
                        return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})
                    else:
                        if listing.rentalContract_buyer:
                            listing.rentalContract_buyer.delete()
                        listing.save()
                        messages.success(request, "signature NOT valid")
                        return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})


            except Exception as e:
                messages.success(request, e)

    else:## when buyer clicks on buy
        # type_contract = listing.typeContract
        buyer_username = request.session['user_data']['username']
        if  (type_contract == "sale"):
            if not listing.saleContract:
                contract_binary = create_contract_sale("contract.pdf", listing.typePropety, listing.seller, buyer_username, listing.date, listing.amenity, listing.budget, listing.locality, listing.typeContract)
                if contract_binary:
                    ##load the privatekey and sign the contract
                    with open("/home/iiitd/private.pem", "rb") as f:
                        private_key = f.read()
                    admin_signature = get_sign(private_key, contract_binary)
                    contract_binary = contract_binary + b"signature:" + b"admin" + admin_signature.encode() + b"admin"

                    listing.saleContract.save("contract.pdf", ContentFile(contract_binary), save=True)
                    listing.save()
                else:
                    messages.success(request, "the file wasn't created")
                form = submitSignatureform()
        ##rental
        else:
            contract_binary = create_contract_sale("contract.pdf", listing.typePropety, listing.seller, buyer_username, listing.date, listing.amenity, listing.budget, listing.locality, listing.typeContract)
            if contract_binary:
                ##load the privatekey and sign the contract
                with open("/home/iiitd/private.pem", "rb") as f:
                    private_key = f.read()
                admin_signature = get_sign(private_key, contract_binary)
                contract_binary = contract_binary + b"signature:" + b"admin" + admin_signature.encode() + b"admin"
                listing.rentalContract_buyer.save("contract.pdf", ContentFile(contract_binary), save=True)
                listing.save()
            else:
                messages.success(request, "the file wasn't created")
        form = submitSignatureform()
            


    return render(request, 'realestate/buyerSignContract.html', {'form': form, 'listing':listing})

def sellerSignContract(request, listing_id):

    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if( 'ekyc2_status' not in request.session):
        messages.success(request,"2nd ekyc not done !")
        return redirect('seller home')
    
    if(request.session['ekyc2_status'] != True):
        messages.success(request,"2nd ekyc not done propely !")
        return redirect('seller home')
    
    
    seller_info = ListingInfo.objects.filter(seller=request.session['user_data']['username'])
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "seller_interested":
        messages.success(request,"2nd ekyc not done propely !")
        return redirect('seller home')

    type_contract = listing.typeContract

    if request.method == "POST": ##when buyer submits the signature form
        form = submitSignatureform(request.POST)
        if form.is_valid():
            try:
                seller_signature = form.cleaned_data['signature']
                ## validate the signature too for code injection and stuff
                seller_public_key = SellerInfo.objects.get(username = request.session['user_data']['username'] ).public_key
                seller_public_key_bin = seller_public_key.open("rb").read()
                if type_contract == "sale":
                    contract = listing.saleContract.open("rb").read()
                    seller_sign_valid = verify_doc2(request, seller_public_key_bin, contract, seller_signature)
                    if seller_sign_valid:
                        listing.seller_sign = seller_signature
                        if listing.buyer_sign:
                            listing.status = "signs_uploaded"
                        listing.save()
                        messages.success(request, "signature verified")
                        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
                    else:
                        if listing.saleContract:
                            listing.saleContract.delete()
                        listing.save()
                        messages.success(request, "signature NOT valid")
                        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
                else:
                    contract = listing.rentalContract_seller.open("rb").read()
                    seller_sign_valid = verify_doc2(request, seller_public_key_bin, contract, seller_signature)
                    if seller_sign_valid:
                        listing.seller_sign = seller_signature
                        if listing.buyer_sign:
                            listing.status = "signs_uploaded"
                        listing.save()
                        messages.success(request, "signature verified")
                        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
                    else:
                        if listing.rentalContract_seller:
                            listing.rentalContract_seller.delete()
                        listing.save()
                        messages.success(request, "signature NOT valid")
                        
                        del request.session['ekyc2_status']
                        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
            except Exception as e:
                messages.success(request, e)

    else:## when seller clicks on buy
        type_contract = listing.typeContract
        buyer_username = request.session['user_data']['username']
        if  (type_contract == "sale"):
            if not listing.saleContract:
                contract_binary = create_contract_sale("contract.pdf", listing.typePropety, listing.seller, buyer_username, listing.date, listing.amenity, listing.budget, listing.locality, listing.typeContract)
                if contract_binary:
                    ##load the privatekey and sign the contract
                    with open("/home/iiitd/private.pem", "rb") as f:
                        private_key = f.read()
                    admin_signature = get_sign(private_key, contract_binary)
                    contract_binary = contract_binary + b"signature:" + b"admin" + admin_signature.encode() + b"admin"
                    listing.saleContract.save("contract.pdf", ContentFile(contract_binary), save=True)
                    listing.save()
                else:
                    messages.success(request, "the file wasn't created")
                form = submitSignatureform()
        ##rental
        else:
            contract_binary = create_contract_sale("contract.pdf", listing.typePropety, listing.seller, buyer_username, listing.date, listing.amenity, listing.budget, listing.locality, listing.typeContract)
            if contract_binary:
                ##load the privatekey and sign the contract
                with open("/home/iiitd/private.pem", "rb") as f:
                    private_key = f.read()
                admin_signature = get_sign(private_key, contract_binary)
                contract_binary = contract_binary + b"signature:" + b"admin" + admin_signature.encode() + b"admin"

                listing.rentalContract_seller.save("contract.pdf", ContentFile(contract_binary), save=True)
                listing.save()
            else:
                messages.success(request, "the file wasn't created")
        form = submitSignatureform()
            


    return render(request, 'realestate/buyerSignContract.html', {'form': form, 'listing':listing})

def buyerInterested(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    listing_info = ListingInfo.objects.filter(status="unsold")
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "unsold":
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    listing.status = "buyer_interested"
    buyer_username = request.session['user_data']['username']
    listing.buyer = buyer_username
    listing.save()
    return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})

def sellerApprove(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    seller_info = ListingInfo.objects.filter(seller=request.session['user_data']['username'])
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "buyer_interested":
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    listing.status = "seller_interested"
    listing.save()
    return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})

def sellerReject(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    seller_info = ListingInfo.objects.filter(seller=request.session['user_data']['username'])
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "buyer_interested" and  listing.status != "seller_interested":
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    listing.status = "unsold"
    listing.buyer = None
    if listing.saleContract:
        listing.saleContract.delete()
    if listing.rentalContract_buyer:
        listing.rentalContract_buyer.delete()
    if listing.rentalContract_seller:
        listing.rentalContract_seller.delete()
    listing.save()
    return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})

def add_signatures(request, listing_id):
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    seller_sing = listing.seller_sign.encode()
    buyer_sign = listing.buyer_sign.encode()
    type_contract = listing.typeContract
    if type_contract == "sale":
        contract = listing.saleContract.open("rb").read()
        contract = contract + b"signature:" + b"seller" + seller_sing + b"seller"
        contract = contract + b"signature:" + b"buyer" + buyer_sign + b"buyer"
        listing.saleContract.save("contract.pdf", ContentFile(contract), save=True)
    else:
        seller_contract = listing.rentalContract_seller.open("rb").read()
        buyer_contract = listing.rentalContract_buyer.open("rb").read()

        seller_contract = seller_contract + b"signature:" + b"seller" + seller_sing + b"seller"
        buyer_contract = buyer_contract + b"signature:" + b"buyer" + buyer_sign + b"buyer"
        listing.rentalContract_seller.save("contract.pdf", ContentFile(seller_contract), save=True)
        listing.rentalContract_buyer.save("contract.pdf", ContentFile(buyer_contract), save=True)
    listing.status = "sold"
    listing.save()


def makePayment(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if( 'ekyc2_status' not in request.session):
        messages.success(request,"2nd ekyc not done !")
        return redirect('buyer home')
    
    if(request.session['ekyc2_status'] != True):
        messages.success(request,"2nd ekyc not done propely !")
        return redirect('buyer home')
    
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if listing.status != "signs_uploaded":
        messages.success(request,"2nd ekyc not done propely !")
        return redirect('buyer home')
    
    del request.session['ekyc2_status']
    
    amount = listing.budget
    client = razorpay.Client(auth= ('rzp_test_DQb2iWTK131DuM','VjneqA7APbwDsQI0uW5FpNiT'))
    payment = client.order.create({'amount': amount*100, 'currency':'INR','payment_capture':1})
    
    log = {'order_id': payment['id'], 'amount': amount, 'seller': listing.seller, 'buyer': listing.buyer}
    
    listing.payment_log = log
    
    succ_url = "https://192.168.2.246/transactionVerdict/" + str(listing_id)
    
    listing.save()
    
    return render(request, 'realestate/makePayment.html', {'payment':payment, 'succ_url':succ_url, 'key':'rzp_test_DQb2iWTK131DuM'})

@csrf_exempt
def transactionVerdict(request, listing_id):
    
    
    if request.method == 'POST':
        
        data = request.POST.dict()
        
        if 'error[code]' not in data:
            
            payment_id = data['razorpay_payment_id']
            signature = data['razorpay_signature']
            
            client = razorpay.Client(auth=('rzp_test_DQb2iWTK131DuM','VjneqA7APbwDsQI0uW5FpNiT'))

            response = client.payment.fetch(payment_id)
            
            if "error" not in response:
            
                listing = ListingInfo.objects.filter(ID=listing_id).first()
            
                new_log = listing.payment_log
            
                new_log['status'] = "success"
                new_log['payment_id'] = payment_id
                new_log['signature'] = signature
                
                listing.payment_log = new_log
                
                listing.save()
                ##invoke the function to add the buyer and seller signatures to the contract
                add_signatures(request, listing_id)
                return render(request, 'realestate/succ.html')
            
            else:
                return render(request, 'realestate/fail.html')
            
        else:
            return render(request, 'realestate/fail.html')

    
def adminProfile(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    username = request.session['user_data']['username']
    user_type = request.session['user_data']['user_type']
    user_info = AdminInfo.objects.get(username=username)
    
    if user_type != 'admin':
        return redirect('main welcome')
    
    return render(request,'realestate/adminProfile.html', {'user_info': user_info})


def viewUsers(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    sellers = SellerInfo.objects.values_list('username', flat=True)
    buyers = BuyerInfo.objects.values_list('username', flat=True)
    
    return render(request, 'realestate/viewUsers.html', {'sellers': sellers, 'buyers': buyers})

def viewProfile(request, username):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    user_details = None
    user_type = None
    
    if BuyerInfo.objects.filter(username=username).exists():
        user_details = BuyerInfo.objects.get(username=username)
        user_type = 'buyer'
    
    elif SellerInfo.objects.filter(username=username).exists():
        user_details = SellerInfo.objects.get(username=username)
        user_type = 'seller'
    
    else:
        messages.success(request,"user does not exist. (it won't work)")
        return redirect('view users')

    return render(request, 'realestate/viewProfile.html', {'user_info': user_details, 'type': user_type})

def mark_malicious_buyer(request, username, is_malicious):

    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')

    if( is_malicious == 0 and request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')

    if BuyerInfo.objects.filter(username=username).exists():
        if is_malicious == 1:
            user = BuyerInfo.objects.get(username=username)
            user.malicious = True
            user.save()
            return redirect('seller home')
        if is_malicious == 0:
            user = BuyerInfo.objects.get(username=username)
            user.malicious = False
            user.save()
            return redirect('view users')
    elif SellerInfo.objects.filter(username=username).exists():
        if is_malicious == 1:
            user = SellerInfo.objects.get(username=username)
            user.malicious = True
            user.save()
            return redirect('seller home')
        if is_malicious == 0:
            user = SellerInfo.objects.get(username=username)
            user.malicious = False
            user.save()
            return redirect('view users')
    else:
        return redirect('view users')

def view_currrent_listings(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    username = request.session['user_data']['username']
    listing_info = ListingInfo.objects.filter(buyer=username)
    return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})

# check for userdata and ekyc
def before_sign(request, listing_id):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
        
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    otp = str(secrets.choice(otps))
    
    user_type = request.session['user_data']['user_type']
    cusername = request.session['user_data']['username']
    
    instance = None
    
    if user_type == "buyer":        
        instance = BuyerInfo.objects.get(username=cusername)
    
    elif user_type == "seller":
        instance = SellerInfo.objects.get(username=cusername)
    
    if instance == None:
        return redirect("main welcome")
        
    femail = instance.email
     
    
    send_mail('OTP for sign up', otp, EMAIL_HOST_USER,[femail], fail_silently=True)
                
    request.session['sign_otp'] = otp
 
    val = listing_id
    url =  reverse('otp2', args=[val])
    return redirect(url)
    # if 'otp_data' not in request.session:
    #     return redirect('main welcome')

# check for userdata and ekyc
def otp2(request, listing_id):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
        
    if( request.session['user_data']['user_type'] != 'buyer'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    if 'sign_otp' not in request.session:
        return redirect("main welcome")
    
    if request.method == 'POST':
        
        sign_otp = request.session['sign_otp']
        otp = request.POST['otp']

        if sign_otp != otp:
            messages.success(request,"otp is incorrect")
        
        else:
            del request.session['sign_otp']
            
            request.session['sign_otp_verdict'] = {
                "success": True
            }
            
            val = listing_id
            url =  reverse('buyerSignContract', args=[val])
            return redirect(url)
    
    return render (request, 'realestate/otpPage.html')

def beforeListing(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
        
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    otp = str(secrets.choice(otps))
    
    user_type = request.session['user_data']['user_type']
    cusername = request.session['user_data']['username']
    
    instance = None
    
    if user_type == "seller":
        instance = SellerInfo.objects.get(username=cusername)
    
    if instance == None:
        return redirect("main welcome")
        
    femail = instance.email
     
    
    send_mail('OTP for sign up', otp, EMAIL_HOST_USER,[femail], fail_silently=True)
                
    request.session['before_otp'] = otp
 
    return redirect('otp3')
    
def otp3(request):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
        
    if( request.session['user_data']['user_type'] != 'seller'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    
    if 'before_otp' not in request.session:
        return redirect("main welcome")
    
    if request.method == 'POST':
        
        before_otp = request.session['before_otp']
        otp = request.POST['otp']

        if before_otp != otp:
            messages.success(request,"otp is incorrect")
        
        else:
            del request.session['before_otp']
            
            request.session['before_verdict'] = {
                "success": True
            }
            
            return redirect("create listing")
    
    return render (request, 'realestate/otpPage.html')

def delete_buyer(request, username):
    
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')
    
    elif (user_data_checker(request) == False):
        return redirect('main welcome')
    
    elif( request.session['user_data']['user_type'] != 'admin'):
        messages.success(request,"unauthorised user access !")
        return redirect('main welcome')
    
    ## first revert the active listings to unsold
    # seller_info = ListingInfo.objects.filter()
    if BuyerInfo.objects.filter(username=username).exists():
        listing = ListingInfo.objects.filter(buyer=username)
        listing = listing.filter(status__in=["buyer_interested", "seller_interested", "signs_uploaded"])
        listing.update(status="unsold", buyer=None)
        for item in listing:
            if item.saleContract:
                item.saleContract.delete()
            if item.rentalContract_buyer:
                item.rentalContract_buyer.delete()
            if item.rentalContract_seller:
                item.rentalContract_seller.delete()
        # listing.save()
        buyer = BuyerInfo.objects.get(username=username)
        buyer.delete()
        return redirect('view users')
    elif SellerInfo.objects.filter(username=username).exists():
        ##simply delete the seller
        listing = ListingInfo.objects.filter(seller=username)
        listing = listing.filter(status__in=["buyer_interested", "seller_interested", "signs_uploaded", "unsold"])
        listing.delete()

        seller = SellerInfo.objects.get(username=username)
        seller.delete()
        return redirect('view users')
    else:
        return redirect('view users')
    
def logout(request):
    if (ekyc_info_checker(request) == False):
        return redirect('ekyc page')

    if (user_data_checker(request) == False):
        return redirect('main welcome')
    
    del request.session['user_data']
    
    return redirect("main welcome")