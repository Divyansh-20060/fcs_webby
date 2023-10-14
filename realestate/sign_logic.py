# import rsa
# def verify_doc(fpublic_key, fproof_of_id):
#     user_public_key = rsa.PublicKey.load_pkcs1(fpublic_key.read())
#     user_proof_of_id = fproof_of_id.read()
#     content = user_proof_of_id[:-256]
#     sign = user_proof_of_id[-256:]
#     try:
#         rsa.verify(content, sign, user_public_key)
#         messages.success(request, "document verified")
#         return True
#     except:
#         messages.success(request, "document verification failed")
#         return False