
# Crypto Play                 
 


## description:
    
Crypto play is a python3 script to encrypt and decrypt files content not file itself, using AES 256bits CTR, EAX modes and RSA.
It uses PyCryptodome library to perform its operation.

## To install dependencies : 

since every needed library is inside a virtual environement ( the folder 'venv'), you have to enable it first to use the script without installing anything on your system.
On Unix-like & MacOS:
        
    source venv/bin/activate
    
On Windows Powershell:
     
     win_venv\Scripts\Activate.ps1
     
NB: If you encounter any problem saying that a script can be executed on your powershell for security reasons, you will have to allow it as follows:

     Set-ExecutionPolicy Unrestricted -scope process
     
To set it back to the previous secure state:
      
      Set-ExecutionPolicy restricted -scope process
    
       
 In case you want thoses dependencies on your system permanently, you can install the required librairies as follows: 

    pip3 install -r requirements.txt
    
    
 To deactivate the virtual environment:
 
       deactivate
    


## Block Ciphers used:
* AES:
   - size: 256
   - mode: CTR, EAX. By default it uses CTR mode
* RSA:
   - size: 2048 by default. one can specify other key size i.e 4096


## Expected Input: 
* The script expect an input file containing the data to encrypt or decrypt.

* An output file where to save the result of operation (optional)
    
* When encrypting in AES, a secret code will be asked so that it can be used  with a generated salt to derive the key


## Expected Output:
* If output file is specified, the operation result will be saved in it.
* In all cases the result will be printed on screen.
 
* in RSA, when a key is not specified it will generate a keypair (public & private) following this pattern: public_FILENAME.pem / private_FILENAME.pem
    
* NB: After being encrypted , the contents are encoded in base64. Hence the output file contains the encoded of the ciphered text. 


## Usage: 
let's suppose we are in the script directory and there is  a file in it called: confidiential.txt.

To encrypt the content using AES EAX mode:
      
      ./cryptoplay.py encrypt -a aes -m eax -if confidential.txt -of secrets.enc
      

To decrypt in that same mode: 
      
      ./cryptoplay.py decrypt -a aes -m eax -if secrets.enc -of pt.txt
      

To encrypt in RSA with a key size 4096 bits
    
    python3 cryptoplay.py encrypt -a rsa -b 4096 -if INPUT_FILE -of OUTPUT_FILE
    

To decrypt in RSA :
    
    python3 cryptoplay.py decrypt -a rsa -k PRIVATE_KEY -if CIPHERED_FILE -of OUTPUT_FILE
    

    

## For more Information:
    
     python3 cryptoplay.py --help  
    
