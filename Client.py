import socket
import sys
import string
import random
import hashlib
import fileinput
import os.path
from Crypto.Cipher import AES

#This function uploads the file 16 byte blocks at a time, possibly encrypted
def upload (f_name, c_sock, encrypter, customfile, cipher):
    lastblock = 0
    x = 0
    if customfile != "" or os.path.isfile(f_name): #if "|" was used in command
        if(customfile == ""):
            f = open(f_name, 'rb')
        while lastblock == 0:
            b = ""
            if(customfile == ""):
                b = f.read(16)
            else:
                for y in range(0,16):
                    if x < len(customfile):
                        b += customfile[x]
                        x += 1
                    else:
                        lastblock = 1
                        break

            if (not b) or (customfile != "" and b == ""):
                # eof
                if(cipher != "null"):
                    c_sock.sendall(encrypter.encrypt("END" + '{' * 13))
                else:
                    c_sock.sendall("END" + '{' * 13)
                break
            elif len(b) != 16:
                b = b.ljust(16,"{") #Adds padding if necessary
                lastblock = 1
                if(cipher != "null"):
                    bencr = encrypter.encrypt(b)
                    c_sock.sendall(bencr)
                    c_sock.sendall(encrypter.encrypt("END" + '{' * 13)) #marks end of transfer
                else:
                    c_sock.sendall(b)
                    c_sock.sendall("END" + '{' * 13)
            else:
                if(cipher != "null"):
                    bencr = encrypter.encrypt(b)
                    c_sock.sendall(bencr)
                else:
                    c_sock.sendall(b)
        return True
    else:
        if(cipher != "null"):
            c_sock.sendall(encrypter.encrypt("err" + '{' * 13))
        else:
            c_sock.sendall("err" + '{' * 13)
        sys.stderr.write("ERROR: file could not be written to server\n")
        return False

#downloads a file 16 byte blocks at a time, possible encrypted.
def download (f_name, c_sock, decrypter, redirect, cipher):

    done = 0
    data = c_sock.recv(16)
    if(cipher != "null"):
        dataplain = decrypter.decrypt(data)
    else:
        dataplain = data

    if dataplain == "err" + '{' * 13:
        sys.stderr.write("ERROR: file could not be read from server\n")
        return False
    else:
        if(redirect == 0):           #if ">" was used in command line
            f = open(f_name, 'w')

        datanext = c_sock.recv(16)
        if(cipher != "null"):
            nextplain = decrypter.decrypt(datanext)
        else:
            nextplain = datanext

        while done == 0:
            if nextplain != ("END" + '{' * 13): #if the last read block was last one
                if(redirect == 0):
                    f.write(dataplain)
                else:
                    sys.stdout.write(dataplain)
                dataplain = nextplain
                datanext = c_sock.recv(16)
                if(cipher != "null"):
                    nextplain = decrypter.decrypt(datanext)
                else:
                    nextplain = datanext
            else:
                dataplain = dataplain.rstrip('{') #Removes padding
                if(redirect == 0):
                    f.write(dataplain)
                else:
                    sys.stdout.write(dataplain)
                done = 1
    return True

#computes hash of challenge (possibly encrypted) and sends it back (possibly encrypted)
def authentication (k, n, c_sock,encrypter,decrypter, cipher):

    challengepre = c_sock.recv(16)
    if(cipher != "null"):
        challenge = decrypter.decrypt(challengepre)
    else:
        challenge = challengepre
    hash_cpre = hashlib.sha256(k + n + challenge).hexdigest()
    if(cipher != "null"):
        hash_c = encrypter.encrypt(hash_cpre)
    else:
        hash_c = hash_cpre
    c_sock.sendall(hash_c)

    response = c_sock.recv(16)
    if (cipher != "null"):
        response = decrypter.decrypt(response)
    response = response.rstrip('{')
    if response == "OK":    #if no errors
        return True
    else:
        return False

#Sends anything over the socket, encrypted (unless cipher == null)
def genericsend(c_sock,encrypter,tosend, cipher):
    pad = 0
    x = 0
    nextplain = ""
    while x < len(tosend):
        for y in range(0,16):
            if(x >= len(tosend)):
               pad = 1
            if pad == 1:
               nextplain += '{'
            else:
               nextplain += tosend[x]
               x += 1
        if(cipher != "null"):
            nextencr = encrypter.encrypt(nextplain)
            c_sock.sendall(nextencr)
        else:
            c_sock.sendall(nextplain)
        nextplain = ""
    if(cipher != "null"):
        end = encrypter.encrypt("END" + '{' * 13)
    else:
        end = "END" + '{' * 13
    c_sock.sendall(end)


###################################################################
if  len(sys.argv) == 6:
    redirect = 0
    customfile = ""
    if not sys.stdin.isatty():
        for line in sys.stdin:
            customfile += line
    if not sys.stdout.isatty():
        redirect = 1
    operation = sys.argv[1]
    filename = sys.argv[2]
    hostname, port = (sys.argv[3]).split(':', 1)
    port = int(port)
    cipher = sys.argv[4]
    key = sys.argv[5]             #the secret key, but not the session key
    #connect to server
    sock = socket.socket()
    try:
        sock.connect((hostname, port))
        ##Protocol:
        ##First Mesage
        nonce = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        data = cipher + " " + nonce
        sock.sendall(data)
        #Set up session key and IV
        if(cipher == "aes256"):
            encr_key = hashlib.sha256(key + nonce + "SK").hexdigest()
            encr_key = encr_key[:32]
        else:
            encr_key = hashlib.sha256(key+nonce+"SK").hexdigest()
            encr_key = encr_key[:16]
        IV = hashlib.sha256(key + nonce + "IV").hexdigest()
        IV = IV[:16]
        mode = AES.MODE_CBC
        #Initializes encrypter and decrypter
        if(cipher != "null"):
            encrypter = AES.new(encr_key,mode,IV=IV)
            decrypter = AES.new(encr_key,mode,IV=IV)
        else:
            encrypter = 0
            decrypter = 0
        #Authentication
        if authentication(key, nonce, sock, encrypter, decrypter, cipher) == True:
            #Request
            genericsend(sock,encrypter,operation + " " + filename, cipher)
            response = sock.recv(16)
            if(cipher != "null"):
                response = decrypter.decrypt(response)
            response = response.rstrip('{')
            if response == "OK":
                ##Data Exchange
                if operation == "write":
                    check = upload(filename, sock, encrypter, customfile, cipher)
                else:
                    check = download(filename, sock, decrypter, redirect,cipher)
                ##Final Success
                if check == True:
                    response = sock.recv(16)
                    if(cipher != "null"):
                        response = decrypter.decrypt(response)
                    response = response.rstrip('{')
                    if(response == "OK"):     #if no errors
                        sys.stderr.write("Operation completed successfully!\n")
            else:
                sys.stderr.write("Error: wrong command line arguments\n")
        else:
            sys.stderr.write("Error: wrong key\n")

        #print "Sent:     {}".format(data)
        #print "Received: {}".format(received)
    finally:
        sock.close()
else:
    sys.stderr.write("Error: wrong command line arguments\n")
