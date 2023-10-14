from django.shortcuts import render, redirect
from realestate.forms import *
from realestate.models import *
from django.contrib import messages
import rsa, hashlib
# from sign_logic import *


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
            femail = form.cleaned_data['email']
            
            existing_seller = SellerInfo.objects.filter(username=fusername).exists()
            existing_buyer = BuyerInfo.objects.filter(username=fusername).exists()
            
            f = open("log.txt", "w")
            f.write("form vaid\n")
            f.close()

            if  (not verify_doc(fpublic_key, fproof_of_id)): ## check document signature
                messages.success(request, 'document verification failed')
            
            elif (existing_seller and user_type == "seller") or (existing_buyer and user_type == "buyer"):
                messages.success(request, 'already exsitig user')


            else:
                ##store the hash of the password
                sha512 = hashlib.sha512()
                sha512.update(fpassword.encode())
                hashed_fpassword = sha512.hexdigest()
                if user_type == 'seller':
                    SellerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                    #print("user created ", user_type)
                    messages.success(request, 'sign up successful! redirecting...')
                    return redirect("login page")

                elif user_type == 'buyer':
                    #print("user created ", user_type)
                    BuyerInfo.objects.create(name = fname, username= fusername, password=hashed_fpassword, public_key = fpublic_key, proof_of_id = fproof_of_id, email=femail)
                    messages.success(request, 'sign up successful! redirecting...')
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

