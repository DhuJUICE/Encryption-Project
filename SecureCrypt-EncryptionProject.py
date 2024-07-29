"""
    SecureCrypt Encryption Project
"""

#import modules to be used - tkinter for GUI
import tkinter as tk
from tkinter import IntVar
from tkinter import filedialog

#First install pycryptodome
#Crypto for AES modules
#from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import *

#import key hash library
import hashlib

#import the operating system to remove files
import os

#setup initial gui window instance of tkinter
root = tk.Tk()

# call intvar for radio buttons (defines groups)
varType = IntVar()
varEncrypt = IntVar()
fileName = ""  ##just to create filename variable

#function for browsing file directory
def browseClick():
    #create global variable to store filename
    global fileName

    #get filename from filebrowse
    fileName = filedialog.askopenfilename(initialdir="", title="Select file")

    #display the filename
    lblPath = tk.Label(root, text=fileName, wraplength=(root.winfo_width()-40))
    lblPath.grid(row=1, column=0, sticky="NEWS", columnspan=2, padx=20, pady=10)

    #return the filename
    return fileName

#function for running the whole application on the run button click
def runClick():
    #create global variable for storing the password or security key
    global setPassword  ##set in here for validation

    #get the key from the Entry
    setPassword = txtKey.get()

    #create global key variable to hold generated key
    global key

    #generate security key
    key = pad(setPassword.encode('UTF-8'), AES.block_size)  ##converted to unique string of bytes for correct blocksize

    #hash our given security key
    keyOwn = int(hashlib.md5(setPassword.encode('UTF-8')).hexdigest(), 16) % 256

    #check to see if it is our own algorithm or the generic
    if varType.get() == 1: 
        if varEncrypt.get() == 3:

            #call encryption function to encrypt using aes encryption
            encrypt(fileName, key)

            #remove the original copy of the file
            os.remove(fileName)
            
        if varEncrypt.get() == 4:
            #call encryption function to decrypt using aes decryption
            decrypt(fileName, key)

            #create variable to save path
            #splits .encryption off to rename
            #renames file after splitting off last "."
            newFileName = os.path.splitext(fileName)[0]

            #rename file
            os.rename(fileName,newFileName)
            
    if varType.get() == 2: #own
        if varEncrypt.get() == 3:
            #call own encryption function to encrypt using XOR encryption
            ownEncrypt(fileName, keyOwn)

            #remove the original copy of the file
            os.remove(fileName)
        if varEncrypt.get() == 4:
            #call own decryption function to decrypt using XOR decryption
            ownDecrypt(fileName, keyOwn)

            #create variable to save path
            newFileName2 = os.path.splitext(fileName)[0]

            #rename file
            os.rename(fileName,newFileName2)

# GUI visual parameters
root.title("Secure-Crypt")

#Widget Layout of tkinter gui controls
lblFile = tk.Label(root, text="File Directory:", borderwidth=2)
lblFile.grid(row=0, column=0, sticky="E", padx=10)

btnBrowse = tk.Button(root, text="Browse", command=browseClick)
btnBrowse.grid(row=0, column=1, sticky="NEWS", padx=30, pady=5)

lblPath = tk.Label(root, text="*File directory will appear here*", padx=30)
lblPath.grid(row=1, column=0, sticky="NEWS", columnspan=2, padx=20, pady=10)

lblMethod = tk.Label(root, height=2, width=15, text="ENCRYPTION METHOD:", borderwidth=2, relief="sunken")
lblMethod.grid(row=2, column=0, sticky="EW", columnspan=2, padx=10)

rdoGeneric = tk.Radiobutton(root, height=2, width=15, text="AES", variable=varType, value=1)
rdoGeneric.grid(row=3, column=0)

rdoCustom = tk.Radiobutton(root, height=2, width=15, text="CUSTOM", variable=varType, value=2)
rdoCustom.grid(row=3, column=1)

lblKey = tk.Label(root, height=2, width=15, text="Security Key:")
lblKey.grid(row=4, column=0, sticky="NEWS")

txtKey = tk.Entry(root, width=30, borderwidth=2)
txtKey.grid(row=4, column=1, sticky="EW", padx=30)

rdoEncrypt = tk.Radiobutton(root, height=2, width=15, text="Encrypt", variable=varEncrypt, value=3)
rdoEncrypt.grid(row=5, column=0)

rdoDecrypt = tk.Radiobutton(root, height=2, width=15, text="Decrypt", variable=varEncrypt, value=4)
rdoDecrypt.grid(row=5, column=1)

btnRun = tk.Button(root, height=2, width=15, text="RUN", command=runClick)
btnRun.grid(row=6, column=0, sticky="NEWS", columnspan=2, padx=10, pady=10)

############################AES#################################
#AES function to encrypt using AES
def encrypt(fileNameParam, keyParam):
    #open file to read from
    with open(fileNameParam, 'rb') as openedFile:
        #read data from file
        data = openedFile.read()

        #create new cipher with key and CFB mode
        cipher = AES.new(keyParam, AES.MODE_CFB)

        #cipher to bytes, padding bytes to match blocksize
        ciphertextHolder = cipher.encrypt(pad(data, AES.block_size))

        # initialization vector, BECAUSE WE USE BASE64 ENCODING, THE IV IS 24 BYTES and NOT 16, BLOCKsize is still
        iv = b64encode(cipher.iv).decode('UTF-8') 
        ciphertext = b64encode(ciphertextHolder).decode('UTF-8')
        encryptedData = iv + ciphertext

    #close the read file
    openedFile.close()

    #create write file to write encrypted data to
    # creates new .enc encrypted file
    with open(fileNameParam + '.encrypted', 'w') as data:
        #write encrypted data to file
        data.write(encryptedData)

    #close the write file
    data.close()

#function to decrypt using AES
def decrypt(fileNameParam, keyParam):
    #open file to read from
    with open(fileNameParam, 'r') as openedFile:
        #read data from file
        data = openedFile.read()
        
        #get the number of characters represented as data
        totalLength = len(data)

        # stores IV, first 24 characters of encrypted file because we used b64 encoding
        ivHolder = data[:24]

        #decodes string into binary, sets new iv
        iv = b64decode(ivHolder)

        # sets cipher text from past IV value to end of file
        cipherTextHolder = data[24:totalLength]

        ##cipher to binary
        cipherText = b64decode(cipherTextHolder)  
        newCipher = AES.new(key, AES.MODE_CFB, iv)

        #decrypt(decipher) the returned ciphertext
        decryptedData = newCipher.decrypt(cipherText)

        #make the data free to use
        decryptedData = unpad(decryptedData, AES.block_size)

    #close the read file
    openedFile.close()    

    #open write file
    with open(fileNameParam, 'wb') as data:
        #write my decrypted data to my file
        data.write(decryptedData)

    #close the write file
    data.close()

#OWN function to encrypt using XOR encryption
def ownEncrypt(fileNameParam, keyParam):
    #open the read file 
    with open(fileNameParam, "rb") as fileToEncrypt:
        #read file data
        dataRead = fileToEncrypt.read()

    #store file data as bytes in a bytearray
    dataArr = bytearray(dataRead)

    #go through the whole bytearray
    for dataIndex, element in enumerate(dataArr, 0):
        #apply XOR operator to each byte in the array with key byte
        dataArr[dataIndex] = element ^ keyParam

    #close the read file
    fileToEncrypt.close()

    #create write file
    with open(fileNameParam + ".enc", "wb") as fileEncrypted:
        fileEncrypted.write(dataArr)

    #close write file
    fileEncrypted.close()

#own function to decrypt using XOR decryption
def ownDecrypt(fileNameParam, keyParam):
    #open the read file 
    with open(fileNameParam, "rb") as fileToDecrypt:
        #read data from file
        dataRead = fileToDecrypt.read()

    #store file data as bytes in a bytearray
    dataArr = bytearray(dataRead)

    #go through the whole bytearray
    for dataIndex, element in enumerate(dataArr, 0):
        #apply XOR operator to each byte in the array with key byte
        dataArr[dataIndex] = element ^ keyParam

    #close the read file
    fileToDecrypt.close()

    #create write file
    with open(fileNameParam, "wb") as fileDecrypted:
        #write decrypted data to file
        fileDecrypted.write(dataArr)

    #close write file
    fileDecrypted.close()

#run main loop to execute tkinter gui and controls
root.mainloop()
