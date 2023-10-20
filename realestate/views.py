from django.shortcuts import render, redirect
from realestate.forms import *
from realestate.models import *
from django.contrib import messages
import rsa, hashlib
from django.core.mail import send_mail
from website.settings import EMAIL_HOST_USER
import random
import secrets
# from sign_logic import *
import re


otps = [int(i) for i in range(100000,1000000)]
username_pattern = r"^[a-zA-Z0-9_\-]{4,50}$"
name_pattern = r"^([a-zA-Z]\s{0,1})+$"
password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#!%&])[A-Za-z\d@#!%&]{8,}$"
otp_pattern = r"^[0-9]{6}$"

def generate_salt():
    salt_length = 64
    salt = secrets.token_hex(salt_length)
    return salt

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

def check_input(string, pattern):
    if re.match(pattern, string):
        return True
    else:
        return False

def ekycStart(request):
    return render (request, 'realestate/ekycPage.html')

def mainWelcome(request):
    
    request.session['position'] = 'main_welcome'
    return render (request,'realestate/mainWelcome.html')

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
    
    if 'otp_data' not in request.session:
        return redirect('main welcome')
    
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
                print("success!")
                
                if request.session['position'] == 'main_welcome':
                
                    return redirect('sign up page')

                elif request.session['position'] == 'profile_page':
                    
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
    
    if request.method == 'POST':
        form = SignupForm(request.POST, request.FILES)
        
        if form.is_valid():
            fname = form.cleaned_data['name']
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            fpublic_key = form.cleaned_data['public_key']
            fproof_of_id = form.cleaned_data['proof_of_id']
            user_type = form.cleaned_data['user_type']


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
                    ##salt the password and store the hash of the password and the salt
                    sha512 = hashlib.sha512()
                    salt = generate_salt()
                    salted_password = fpassword + salt
                    sha512.update(salted_password.encode())
                    hashed_fpassword = sha512.hexdigest()
                    
                    
                    if user_type == 'seller':
                        SellerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, salt = salt,  public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                        #print("user created ", user_type)
                        messages.success(request, 'sign up successful!')
                        del request.session['otp_data']
                        return redirect("login page")

                    elif user_type == 'buyer':
                        #print("user created ", user_type)
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
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        if form.is_valid():
            fusername = form.cleaned_data['username']
            fpassword = form.cleaned_data['password']
            user_type = form.cleaned_data['user_type']


            valid_username_pattern = check_input(fusername, username_pattern)
            valid_password_pattern = check_input(fpassword, password_pattern)
            if not ( valid_username_pattern and valid_password_pattern and len(fpassword) >= 8 and len(fpassword) <= 50):
                messages.success(request, 'Do not inject code, bakayarou')
            else:
                # ##calculate the hash of the password
                # sha512 = hashlib.sha512()
                # sha512.update(fpassword.encode())
                # hashed_fpassword = sha512.hexdigest()
                if user_type == 'buyer':
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
                        print("log in failed ",user_type)
                        messages.error(request, 'log in failed. Chek credentials.')

                elif user_type == 'seller':
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

                
                elif user_type == 'admin':
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
    return render(request,'realestate/sellerHome.html')

def userProfile(request):
    
    username = request.session['user_data']['username']
    
    user_info = SellerInfo.objects.get(username=username)
    request.session['position'] = 'profile_page'
    
    return render (request, 'realestate/userProfile.html', {'user_info': user_info})

def updatePassword(request):
    
    if request.method == 'POST':
        
        form = PasswordForm(request.POST)
        
        if form.is_valid():
            foldpass = form.cleaned_data['old_password']
            fnewpass = form.cleaned_data['new_password']
            fconfpass = form.cleaned_data['confirm_new_password']
            
            check_old_pass_regx = check_input(foldpass,password_pattern)
            check_new_pass_regx = check_input(fnewpass,password_pattern)
            check_conf_regx = check_input(fconfpass,password_pattern)
            
            if not (check_conf_regx) or not(check_new_pass_regx) or not(check_old_pass_regx) or not(len(foldpass) >= 8) or not(len(fnewpass) >= 8) or not(len(fconfpass) >= 8):
                messages.success(request,"Please stick to the password format")
            
            else:
                sha512 = hashlib.sha512()
                sha512.update(foldpass.encode())
                hashed_fpassword = sha512.hexdigest()
                
                user_type = request.session['user_data']['user_type']
                cusername = request.session['user_data']['username']
                if user_type == 'buyer' and BuyerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
                    
                    if fnewpass != fconfpass:
                        messages.success(request,"new passwords don't match")
                    
                    else:
                        
                        sha512 = hashlib.sha512()
                        sha512.update(fnewpass.encode())
                        hashed_newpassword = sha512.hexdigest()
                
                        user_entry = BuyerInfo.objects.filter(username=cusername).first()
                        
                        if user_entry:
                            user_entry.password = hashed_newpassword
                            user_entry.save()
                            messages.success(request,"password updated!")
                            return redirect('user Profile')
                            
                        else:
                            messages.success(request,"user does not exist!")
                            return redirect('main welcome')
                
                elif user_type == 'seller' and SellerInfo.objects.filter(username=cusername,password= hashed_fpassword).exists():
                    
                    if fnewpass != fconfpass:
                        messages.success(request,"new passwords don't match")
                    
                    else:
                        
                        sha512 = hashlib.sha512()
                        sha512.update(fnewpass.encode())
                        hashed_newpassword = sha512.hexdigest()
                
                        user_entry = SellerInfo.objects.filter(username=cusername).first()
                        
                        if user_entry:
                            user_entry.password = hashed_newpassword
                            user_entry.save()
                            messages.success(request,"password updated!")
                            return redirect('user Profile')
                            
                        else:
                            messages.success(request,"user does not exist!")
                            return redirect('main welcome')    
                
                else:
                    messages.success(request,'old password dose not match!')
                    
        else:
            messages.success(request,'please fill the form correctly')
    
    else:
        form = PasswordForm()
        
    return render(request,'realestate/updatePassword.html',{'form':form})


def updateNamePOI(request):
    
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
            
        sha512 = hashlib.sha512()
        sha512.update(password.encode())
        hashed_fpassword = sha512.hexdigest()
            
        user_type = request.session['user_data']['user_type']
        cusername = request.session['user_data']['username']
            
            
        user_entry_buyer = BuyerInfo.objects.filter(username=cusername).first()
        user_entry_seller = SellerInfo.objects.filter(username=cusername).first()
            
        if user_type == 'buyer' and BuyerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
            
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
                    
                if(verify_doc(public_key,proof_of_id)):
                    
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
                
        elif user_type == 'seller' and  SellerInfo.objects.filter(username=cusername, password= hashed_fpassword).exists():
            
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
                    
                if(verify_doc(public_key,proof_of_id)):
                    
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
            
    return render(request,'realestate/updateNamePOI.html')


def adminHome(request):
    return render(request,'realestate/adminHome.html')

def buyerHome(request):
    return render(request,'realestate/adminHome.html')

########################### Legacy ############

def buyerHome(request):
    # print("django log: great success wow")
    return render(request,'realestate/buyerHome.html')

def showListings(request):
    return render(request,'realestate/showListings.html')

def purchaseHistory(request):
    return render(request,'realestate/purchaseHistory.html')
