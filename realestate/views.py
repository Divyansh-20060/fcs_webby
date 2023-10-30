from django.shortcuts import render, redirect
from realestate.forms import *
from realestate.models import *
from django.contrib import messages
import rsa, hashlib
from django.core.mail import send_mail
from website.settings import EMAIL_HOST_USER
# import random
import secrets
# from sign_logic import *
import re
from datetime import date



otps = [int(i) for i in range(100000,1000000)]
username_pattern = r"^[a-zA-Z0-9_\-]{4,50}$"
name_pattern = r"^(?=.{4,50}$)([a-zA-Z]\s{0,1})+$"
password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#!%&])[A-Za-z\d@#!%&]{8,50}$"
otp_pattern = r"^[0-9]{6}$"

type_property_pattern = r"^[a-zA-Z]{4,50}$"
amenities_pattern = r"^[a-zA-Z]{4,50}$"
budget_pattern = r"^[1-9][0-9]{0,19}$"
locality_pattern = r"^(?=.{1,150}$)([a-zA-Z0-9\-]\s{0,1})+$"
# type_contract_pattern = r"[a-z]{1,20}"
type_contract_pattern = r"^(sale|rental)$"
date_pattern = r"^(((\d{4}\-((0[13578]\-|1[02]\-)(0[1-9]|[12]\d|3[01])|(0[13456789]\-|1[012]\-)(0[1-9]|[12]\d|30)|02\-(0[1-9]|1\d|2[0-8])))|((([02468][048]|[13579][26])00|\d{2}([13579][26]|0[48]|[2468][048])))\-02\-29)){0,10}$"


def generate_salt():
    salt_length = 64
    salt = secrets.token_hex(salt_length)
    return salt


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
    return render(request,'realestate/sellerHome.html')

def createListing(request):
    
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
                    # return redirect("seller home")
        else:
            messages.success(request, 'what is wrong with you')
    else:
        form = CreateListingForm()
    
    return render(request,"realestate/createListing.html", {'form':form})


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
                else:
                    messages.success(request,'invalid user_type')
                    
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


            if (BuyerInfo.objects.filter(password=hashed_fpassword).exists()):
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


def viewSellerListings(request):

    username = request.session['user_data']['username']

    if username:
        seller_info = ListingInfo.objects.filter(seller=username)
        return render(request, 'realestate/viewSellerListings.html', {'seller_info': seller_info})
    else:
        # Handle the case where username is not in the session
        # Redirect to an error page, display a message, etc.
        return render(request, 'error.html', {'message': 'Username not found in session'})

def viewBuyerListings(request):
    listing_info = ListingInfo.objects.filter()
    return render(request, 'realestate/viewBuyerListings.html', {'listing_info': listing_info})

def edit_listing(request, listing_id):
    listing = ListingInfo.objects.filter(ID=listing_id).first()
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
    listing = ListingInfo.objects.filter(ID=listing_id).first()
    if request.method == "POST":
        listing.delete()
        return redirect('view seller listings')
    return render(request, 'realestate/confirm_delete_listing.html', {'listing': listing})