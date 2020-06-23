#!/usr/bin/env python3

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64, json, argparse, sys, os, subprocess, pbkdf2, getpass
from termcolor import colored





################################ Arguments Parsing ##########################
#
def get_arguments():
    
    key_size_rsa = 2048
    key_size_aes = 256
    private_key_filepath = ""
    aes_mode = "ctr"
    output_file = ""

    parser = argparse.ArgumentParser(
            description="A script to encrypt/decrypt file contents (strings)"\
                    "in AES, RSA, using PyCryptodome library.",
            epilog="Warning: This script doesnt encrypt/decrypt file "\
                    "itself but content of the file.",
            formatter_class=argparse.RawTextHelpFormatter) 

    parser.add_argument("operation", choices=['encrypt','decrypt'],\
            help='\t\t\tEncrypt/decrypt a file')
    parser.add_argument('-a',"--algoritm", dest="algo", required=True,\
            choices=['rsa','aes','xor'],\
            help="\t\t\tAlgorithm to use for operations")
    parser.add_argument('-m',"--mode", choices=["ctr","eax"], dest="mode",\
            help="\t\t\tMode of operations for symmetric block ciphers")
    parser.add_argument('-k',"--key", dest="keyfile",\
            help="\t\t\tprivate key to be use to decrypt a cipher in RSA" )
    parser.add_argument('-b',"--bits", dest="keylength", help="\t\t\tthe key"\
            "size in bits. By default, it's 2048bits for RSA",\
            choices=['1024','2048','4096'])
    parser.add_argument('-if',"--infile", dest="input_file",required=True,\
            help="\t\t\tinput filepath to perform encryption/decryption on ")
    parser.add_argument('-of', "--outfile", dest="output_file",\
            help="\t\t\tOutput filepath to save encryption/decryption result")

    args = parser.parse_args()

    if args.operation:
        print("[+] Operation : "+colored(f"{args.operation.upper()}",\
                 "yellow"))
        print("[+] Algorithm : "+colored(f"{args.algo.upper()}",\
                "yellow"))
        if args.algo == "rsa":

            #for RSA, we need :
            #       key size = 2048bits by default
            #       the private key for decryption
            #       the public key for encryption. if not given then generate
            ###################

            if args.keylength:
                key_size_rsa = args.keylength
            #if the key length is not specified it is st to 2048bits by default
            print("[+] Key length: "+colored(f"{key_size_rsa}", "yellow"))
            if not args.keyfile: 
                if args.operation == "decrypt": #no private key
                    print(colored("in case of RSA decryption, Specify the "\
                            "private key file with -k/--key", "red"))
                    sys.exit(127)
                else:
                    # generating for encryption
                    # thepublic key will be used to encrypt
                    
                    # private_key_filepath is following this pattern:
                    # private_{name_of_input_file).pem
                    input_filename = os.path.basename(args.input_file)
                    private_key_filepath = "private_" + \
                            input_filename.split('.')[0] + ".pem"
                    public_key_path = "public_" + \
                            input_filename.split('.')[0] + ".pem"
                    generate_rsa(int(key_size_rsa),private_key_filepath, public_key_path)
            if args.keyfile:
                private_key_filepath = args.keyfile
                
            return args.operation, args.algo, key_size_rsa,\
                    private_key_filepath,args.input_file, args.output_file

        if args.algo == "aes":
            #for AES, we need :
            #       key size = 256bits by defaults
            #       mode = ctr by default
            #       the key filepath to perform both encryption and decryption
            ###########
            
            if args.mode:
                aes_mode = args.mode
            print("[+] Mode: " + colored(f"{aes_mode.upper()}","yellow"))

            # if args.keylength:
            #     key_size_aes = args.keylength 
            print("[+] Key size: " + colored(f"{key_size_aes}","yellow"))

            return args.operation, args.algo, key_size_aes,\
                    private_key_filepath, args.input_file,\
                    args.output_file, aes_mode


#############################  End of Argument Parsing  #####################


##############################  AES ZONE  ###################################
#
def ask_password():
    try:
        while True:
            password = getpass.getpass("[*] Enter your secret code:  ")
            password2 = getpass.getpass("[*] Renter your code,to verify:  ")
            if password == password2:
               return password 
            else:
                print("[*] Secret code does not match, try again ")
    except KeyboardInterrupt:
        print(colored("\n[-] Exiting...", "red"))
        sys.exit(127)




def aes_encrypt(in_file, k_size, mode, out_file):
    print(colored("[+] Generating AES key... ","yellow"))

    #derive key from user password
    password = ask_password()
    salt = get_random_bytes(16)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    if k_size == 256:
        key = pbkdf2.PBKDF2(password,salt).read(32)
    elif k_size == 192:
        key = pbkdf2.PBKDF2(password,salt).read(24)

    elif k_size == 128:
        key = pbkdf2.PBKDF2(password,salt).read(16)

    
    #read content of input file
    try:
        with open(in_file,"r") as f:
            data = f.read()
    except FileNotFoundError:
        print(colored("[-] File not found !", "red"))
        sys.exit(127)

    #encode data into bytes in order to be able to encrypt it
    data = data.encode()

    if mode == "ctr":

        #cipher creation. a kind of AES box with the key and the mode specified
        cipher = AES.new(key, AES.MODE_CTR)
        
        #turn the nonce from bytes to base64
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')

        #encrypt data
        ciphered_text_bytes = cipher.encrypt(data)
        ct_b64 = base64.b64encode(ciphered_text_bytes).decode('utf-8')

        #create a json format to save the ciphertext, nonce& salt in a file
        json_obj = json.dumps({'nonce':nonce, 'ciphertext':ct_b64,\
                'salt':salt_b64 })

        print(f"[+] Encryption ==> " + \
                        colored(f"{ct_b64}","green") +"\n"+\
                        f"Salt:{salt_b64} \n"+\
                        f"nonce: {nonce}")

        #save the json_result inside output file.
        if not out_file is None:
            with open(out_file,"w") as f:
                f.write(json_obj)
            print(f"[+] results successfully saved  in {out_file}")
            
    elif mode ==  "eax":
        header = b"header"
        cipher = AES.new(key, AES.MODE_EAX)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        ct_64 = base64.b64encode(ciphertext).decode('utf-8')

        json_key = ['nonce', 'header', 'ciphertext', 'tag', 'salt' ]
        json_value = [ base64.b64encode(x).decode('utf-8')\
            for x in (cipher.nonce, header, ciphertext, tag, salt) ]
        json_result = json.dumps(dict(zip(json_key, json_value)))

        print(f"[+] Encryption ==> " + \
                colored(f"{ct_64}","green") +"\n"+\
                f"Salt: {salt_b64} \n"+\
                f"header: {base64.b64encode(header).decode('utf-8')} \n"+\
                f"tag: {base64.b64encode(tag).decode('utf-8')} \n" +\
                f"nonce: {base64.b64encode(tag).decode('utf-8')}")
        
        if not out_file is None:
            #Save the json containing the ciphertext, nonce, tag, header
            with open(out_file, "w") as f:
                f.write(json_result)
                print(f"[+] encryption result saved in {out_file}")




    

def aes_decrypt(in_file, key_size, mode, out_file):
    #read the encoded-encrypted data from input file
    try:
        with open(in_file,"r") as f:
            data_enc = f.read()
    except FileNotFoundError:
        print(colored("[-] File not found !", "red"))
        sys.exit(127)

    #load the data in json format
    data_json = json.loads(data_enc)

    #decode the salt from base64 to bytes
    salt = base64.b64decode(data_json['salt'])

    #derive key from password & salt
    password = ask_password()
    if key_size == 256:
        key = pbkdf2.PBKDF2(password,salt).read(32)
    if key_size == 192:
        key = pbkdf2.PBKDF2(password,salt).read(24)
    if key_size == 128:
        key = pbkdf2.PBKDF2(password,salt).read(16)

    #decode nonce from base64 into bytes 
    nonce = base64.b64decode(data_json['nonce'])

    #ciphertext in bytes format
    ciphertext = base64.b64decode(data_json['ciphertext'])

    if mode == "ctr":
        try:
            #create AES cipher or Box with the nonce , the mode and the key
            cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)
            plaintext = cipher.decrypt(ciphertext).decode()
            print("[+] Decryption ==>> " +colored(f"{plaintext}","green"))
            
            if not out_file is None:
            # in case the output file has been specified,
            #it saves result in a file
                with open(out_file, "w") as f:
                    f.write(plaintext)
                    print(f"[+] encryption result saved in {out_file}")

        except (ValueError, KeyError):
            print(colored("[-] Incorrect Decryption", "red"))

    if mode == "eax":
        try:
            json_k = ['nonce', 'header', 'ciphertext', 'tag' ]
            json_v = { k:base64.b64decode(data_json[k]) for k in json_k}
            #create AES mode EAX Box with the nonce
            cipher = AES.new(key, AES.MODE_EAX, nonce=json_v['nonce'])
            #specify the header
            cipher.update(json_v['header'])

            plaintext = cipher.decrypt_and_verify(json_v['ciphertext'],\
                    json_v['tag']).decode('utf-8')
        
            print("[+] decryption ==>> " + colored(f"{plaintext}","green"))

            if not out_file is None:
            # in case the output file has been specified,
            #it saves result in a file
                with open(out_file, "w") as f:
                    f.write(plaintext)
                    print(f"[+] encryption result saved in {out_file}")

        except (ValueError, KeyError):
            print(colored("Incorrect decryption","red"))

#################################   END AES #################################




#############################################################################
#                                   RSA
#

def generate_rsa(key_size, priv_filename, pub_filename):
    print(colored("[+] Generating RSA keypair private &"\
                            " public... ","yellow"))
    key = RSA.generate(key_size)
    with open(priv_filename,'wb') as f:
        f.write(key.export_key('PEM'))

    #extract the public key from private with openSSL
    result = subprocess.run(["openssl", "rsa", "-in", priv_filename,\
            "-out", pub_filename, "-pubout" ] )


            
def rsa_encrypt(in_file, kpath, out_file):
    #read content of file
    with open(in_file, "r") as f:
        data = f.read()

    #convert data to bytes
    data_bytes = data.encode('utf-8')

    #read the key from file.
    key = RSA.importKey(open(kpath,'r').read())
    
    #create the cipher
    cipher = PKCS1_OAEP.new(key)
    ciphertext_bytes = cipher.encrypt(data_bytes)
    ct_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8') 
    
    print('[+] encryption ==>> ' + colored(f' {ct_b64}', 'green'))
    #save ciphertext in output file in base64 format
    if not out_file is None:
        with open(out_file,'w') as f:
            f.write(ct_b64)
            print(f'[+] results saved in {out_file}')




def rsa_decrypt(in_file, kpath, out_file):
    #read content of file
    with open(in_file,'r') as f:
        data_enc_b64 = f.read()

    #turn data from b64 to bytes
    data_enc_b = base64.b64decode(data_enc_b64)

    #read the key from file
    key = RSA.importKey(open(kpath,'r').read())
    cipher = PKCS1_OAEP.new(key)
    deciphertext_bytes = cipher.decrypt(data_enc_b)
    plaintext = deciphertext_bytes.decode('utf-8')

    print('[+] decryption ==>> ' + colored(f' {plaintext}', 'green'))
    #save ciphertext in output file in base64 format
    if not out_file is None:
        with open(out_file,'w') as f:
            f.write(plaintext)
            print(f'[+] results saved in {out_file}')

##############################   END RSA ####################################
    

#############################################################################
#                                Main Function
#
if __name__ == "__main__":

    args = get_arguments()
    operation = args[0]
    algo = args[1]
    key_size = args[2]
    key_path = args[3]
    in_file = args[4]
    out_file = args[5]

    if algo == "aes":
        mode = args[6]
        if operation == "encrypt":
            aes_encrypt(in_file, key_size, mode, out_file)
        else:
            aes_decrypt(in_file, key_size, mode, out_file)

    elif algo == "rsa":
        if operation == "encrypt":
            rsa_encrypt(in_file, key_path, out_file)
        else:
            rsa_decrypt(in_file, key_path, out_file)

    else:
        #Xor
        print('[-] Fonction en cours de maintenance')


###############################  END MAIN  ####################################
