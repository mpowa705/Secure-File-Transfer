import socket
import random
import string
import sys
import hashlib
import os.path
from Crypto.Cipher import AES
from time import gmtime, strftime

#downloads a file from client 16 byte blocks at a time, possibly encrypted
def download (f_name, c_sock, decrypter, cipher):
    done = 0                #if last read from file was last one == 1
    data = c_sock.recv(16)
    if(cipher != "null"):
        dataplain = decrypter.decrypt(data)
    else:
        dataplain = data

    if dataplain == "err" + '{' * 13:
        return False
    else:
        f = open(f_name,'w')
        datanext = c_sock.recv(16)
        if(cipher != "null"):
            nextplain = decrypter.decrypt(datanext)
        else:
            nextplain = datanext

        while done == 0:
            if nextplain != ("END" + '{' * 13):   #indicates last block was last one
                f.write(dataplain)
                dataplain = nextplain
                datanext = c_sock.recv(16)
                if(cipher != "null"):
                    nextplain = decrypter.decrypt(datanext)
                else:
                    nextplain = datanext
            else:
                dataplain = dataplain.rstrip('{')   #Removes padding of last block
                f.write(dataplain)
                done = 1
        return True

#uploads file to client 16 byte blocks at a time, possibly encrypted
def upload (f_name, c_sock, encrypter, cipher):
    lastblock = 0
    if os.path.isfile(f_name):
        with open(f_name, 'rb') as f:
            while lastblock == 0:
                b = f.read(16)
                if not b:
                    #eof
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
                        c_sock.sendall(encrypter.encrypt("END" + '{' * 13))
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
        return False

#sends a random challenge (possibly encrypted), computes the hash of key+nonce+challenge then compares to client's response (possibly encrypted) if they match, authentication is complete.
def authentication (k, n, c_sock,encrypter,decrypter,cipher):
    #make challenge
    challengepre = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    if(cipher != "null"):
        challenge = encrypter.encrypt(challengepre)
    else:
        challenge = challengepre
    #send challenge
    c_sock.sendall(challenge)
    #compute hash
    hash_s = hashlib.sha256(k + n + challengepre).hexdigest()
    #get response
    hash_cpre = c_sock.recv(64)
    if(cipher != "null"):
        hash_c = decrypter.decrypt(hash_cpre)
    else:
        hash_c = hash_cpre
    if hash_s == hash_c:
        return True
    else:
        return False


    #gets the encrypted request+filename from client
def getdouble (c_sock, decrypter, cipher):
    first = ""
    second = ""
    readfirst = 1
    done = 0
    data = c_sock.recv(16)
    datanext = c_sock.recv(16)
    if(cipher != "null"):
        dataplain = decrypter.decrypt(data)
        nextplain = decrypter.decrypt(datanext)
    else:
        dataplain = data
        nextplain = datanext
    if data != "err":
        while done == 0:
            if nextplain != ("END" + '{' * 13):
                if(' ' in dataplain):
                    firstend, secondstart = dataplain.split(' ',1)
                    first += firstend
                    second += secondstart
                    readfirst = 0
                elif(readfirst == 1):
                    first += dataplain
                else:
                    second += dataplain
                dataplain = nextplain
                datanext = c_sock.recv(16)
                if(cipher != "null"):
                    nextplain = decrypter.decrypt(datanext)
                else:
                    nextplain = datanext
            else:
                if(' ' in dataplain):  #if we've reached the space delimiter
                    firstend, secondstart = dataplain.split(' ',1)
                    first += firstend
                    second += secondstart.rstrip('{')
                    done = 1
                elif(readfirst == 0):
                    second += dataplain.rstrip('{')
                    done = 1
    return first, second

##################################################################

if len(sys.argv) == 3:
    port = int(sys.argv[1])
    key = sys.argv[2]
    server_socket = socket.socket()

    server_socket.bind(('localhost', port))
    server_socket.listen(0)

    try:
        print("Listening on port: " + sys.argv[1])
        print("Using secret key : " + sys.argv[2])
        while True:
            #set up connection
            client_socket, info = server_socket.accept()
            #Get First Response
            first_response = client_socket.recv(128)
            cipher, nonce = first_response.split(" ", 1)
            #LOGGING
            print(strftime("%H:%M:%S: ", gmtime()) +" new connection from {} cipher={}").format(info, cipher)
            print(strftime("%H:%M:%S: ", gmtime()) +" nonce={}").format(nonce)
            #Set up encryption key and and IV
            if(cipher == "aes256"):
                encr_key = hashlib.sha256(key + nonce + "SK").hexdigest()
                encr_key = encr_key[:32]
            else:
                encr_key = hashlib.sha256(key + nonce + "SK").hexdigest()
                encr_key = encr_key[:16]
            IV = hashlib.sha256(key + nonce + "IV").hexdigest()
            IV = IV[:16]
            mode = AES.MODE_CBC
            #LOGGING
            print(strftime("%H:%M:%S: ", gmtime()) + " IV={}").format(IV)
            print(strftime("%H:%M:%S: ", gmtime()) + " SK={}").format(encr_key)
            #Initializes encrypter and decrypter
            encrypter = AES.new(encr_key,mode,IV=IV)
            decrypter = AES.new(encr_key,mode,IV=IV)
            #Authentication
            if authentication(key, nonce, client_socket,encrypter,decrypter, cipher):
                if(cipher != "null"):
                    tosend = encrypter.encrypt("OK" + '{' * 14)
                else:
                    tosend = "OK" + '{' * 14
                client_socket.send(tosend)
                #Request
                request = getdouble(client_socket,decrypter, cipher)
                operation = request[0]
                filename = request[1]
                #LOGGING
                print(strftime("%H:%M:%S: ", gmtime()) + " command={}").format(operation)
                print(strftime("%H:%M:%S: ", gmtime()) + " filename={}").format(filename)

                if operation == "read" or operation == "write":
                    if(cipher != "null"):
                        tosend = encrypter.encrypt("OK" + '{' * 14)
                    else:
                        tosend = "OK" + '{' * 14
                    client_socket.send(tosend)
                    #Data Exchange
                    if operation == "write":
                        check = download(filename, client_socket, decrypter, cipher)
                    else:
                        check = upload(filename, client_socket, encrypter, cipher)
                    #Final Success
                    if check == True:
                        if(cipher != "null"):
                            tosend = encrypter.encrypt("OK" + '{' * 14)
                        else:
                            tosend = "OK" + '{' * 14
                        client_socket.send(tosend)
                        print(strftime("%H:%M:%S: ", gmtime()) + " status: success")
                    else:
                        if(cipher != "null"):
                            tosend = encrypter.encrypt("err" + '{' * 13)
                        else:
                            tosend = "err" + '{' * 13
                        client_socket.send(tosend)
                        if operation == "read":
                            print(strftime("%H:%M:%S: ", gmtime()) + " status: error - could not read file")
                        elif operation == "write":
                            print(strftime("%H:%M:%S: ", gmtime()) + " status: error - could not write file")
                else:
                    if(cipher != "null"):
                        tosend = encrypter.encrypt("err" + '{' * 13)
                    else:
                        tosend = "err" + '{' * 13
                    client_socket.send(tosend)
                    print(strftime("%H:%M:%S: ", gmtime()) + " status: error - command '{}' not recofnized").format(operation)
            else:
                if(cipher != "null"):
                    tosend = encrypter.encrypt("err" + '{' * 13)
                else:
                    tosend = "err" + '{' * 13
                client_socket.send(tosend)
                print(strftime("%H:%M:%S: ", gmtime()) + " status: error - bad key")
    except Exception as err:
        print("Exception Occuried: {}".format(err))
        pass
else:
    print("Error: wrong command line arguments")
