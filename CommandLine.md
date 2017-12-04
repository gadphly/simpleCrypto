#RSA File De- and Encryption Docu for encrypt and decrypt a large file with AES and RSA

##Keypairs

###Generate RSA Keypairs

//generates a private Key with 8196 Bit. 
openssl genrsa -out private.pem 8196

//strips out the public key from the private key
openssl rsa -in private.pem -out public.pem -outform PEM -pubout
Note: Currently 16384 is the max modulo lenght

###Generate AES Key

//generate a Radnom 32 Byte (256 Bit) AES Key an save the key to the aesKey.txt file
openssl rand -base64 32 | cut -c1-31 > aesKey.txt
##Encryption

###Encrypt File with AES Key

//encrypt the file.txt with the generated AES Key to the file.enc
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -pass file:./aesKey.txt
###Encrypt AES Key with RSA Public Key

//encrpyt the AES Key with the RSA Public Key and save the outcome int the aesKey.txt.crypted file. 
openssl rsautl -encrypt -inkey public.pem -pubin -in aesKey.txt -out aesKey.txt.crypted
###Generate a Signature for the file.txt

//Generate the signature.txt for the file.txt
openssl dgst -sha256 -sign private.pem -out signature.txt file.txt 
You can now send the file.enc, aesKey.txt.crypted, signature.txt and the public.pem via email or something similar. Dont send the private.pem!

##Decryption

###Decrypt AES Key with RSA Private Key

//decrypt the AES Key with the Private RSA Key and save the result in aesKey.txt.decrypted
openssl rsautl -decrypt -inkey private.pem -in aesKey.txt.crypted -out aesKey.txt.decrypted
###Decrypt File with AES Key

//decrypt the encrypted file with the decrypted AES Key
openssl enc -d -aes-256-cbc -in file.enc -out file.txt.decrypted -pass file:./aesKey.txt.decrypted
//The file.txt.decrypted and file.txt should be te same
###Verify the signature for the recieved file.txt and the signature.txt

openssl dgst -sha256 -verify public.pem -signature signature.txt file.txt
# in case of success: prints "Verified OK"
# in case of failure: prints "Verification Failure"


