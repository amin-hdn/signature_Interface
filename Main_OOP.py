import hashlib
import tkinter as tk
from tkinter import ttk

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import binascii


class Root(tk.Tk):
    def __init__(self):
        super().__init__()
        # Windows parameters 
        self.title("Hash Generator")
        self.geometry("600x400")
        self.resizable(1, 1)

        # variables that I will need 
        self.message = tk.StringVar(self)
        self.selected_hash =tk.StringVar(self, value='md5')
        self.Encyption_Method = tk.StringVar(self, value='RSA')
        self.hash_Result = tk.StringVar(self)
        self.PublicKey = None
        self.PrivateKey = None
        self.Signature_Result = tk.StringVar(self, value='walo')

        # all Entries

        self.Input_Message = tk.Entry(self,textvariable=self.message,justify="left" ,bd='3px')
        

        # all Button
        self.Send_Button = tk.Button(self,text='Send', command=self.Send_to_Salma, activebackground='#959595', width=17)
        self.Sign_Button = tk.Button(self,text='Sign', command=self.Sign_THE_Hash, activebackground='#959595', width=17)
        
        # all Combobox
        self.hash = ttk.Combobox(self, textvariable=self.selected_hash, values=('md5','sha1','sha224','sha256','sha384', 'sha512') , state='readonly', justify='center' )
        self.Crypto = ttk.Combobox(self, textvariable=self.Encyption_Method, values=('RSA') , state='readonly', justify='center' )

        # all labels
        self.Signature_label = tk.Label(self, textvariable=self.Signature_Result, justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        # grid positions

        self.columnconfigure(0,weight=2)
        self.rowconfigure(0,weight=2)
        self.columnconfigure(1,weight=2)
        self.rowconfigure(1,weight=1)
        self.columnconfigure(2,weight=2)
        self.rowconfigure(2,weight=3)
        self.columnconfigure(3,weight=2)
        self.rowconfigure(3,weight=1)
    
        self.Input_Message.grid(column=0,row=0, sticky=tk.W, padx=0, pady=1)
        self.Send_Button.grid(column=0,row=1, sticky=tk.W, padx=0, pady=1)
        self.Sign_Button.grid(column=0,row=2, sticky=tk.W, padx=0, pady=1)
        
        self.hash.grid(column=1,row=0, sticky=tk.W, padx=0, pady=1)
        self.Crypto.grid(column=1,row=1, sticky=tk.W, padx=0, pady=1)
        self.Signature_label.grid(column=1,row=3, sticky=tk.W, padx=0, pady=1)

    def Send_to_Salma(self):
        #Send message 
        #Send Hash
        pass 

    def RSA_Key_Generation(self,Number):
        self.PrivateKey = RSA.generate(Number)
        # generate RSA Key
        self.PublicKey = self.PrivateKey.publickey()

        pubKeyPEM = self.PublicKey.exportKey()
        # print(pubKeyPEM.decode('ascii'))

        privKeyPEM = self.PrivateKey.exportKey()
        # print(privKeyPEM.decode('ascii'))


    def Sign_THE_Hash(self):
        self.RSA_Key_Generation(3072)

        hash_fonction= getattr(hashlib ,self.selected_hash.get() )
        self.hash_Result.set(hash_fonction(self.Input_Message.get().encode()).hexdigest())


        msg = bytes(str(self.hash_Result.get()), encoding='ascii')
        encryptor = PKCS1_OAEP.new(self.PublicKey)
        encrypted = encryptor.encrypt(msg)
        cypher_txt = binascii.hexlify(encrypted)
        self.Signature_Result.set(cypher_txt.decode('ascii'))
        # self.Signature_label.config(text=self.Signature_Result.get())

        # print("Encrypted:", binascii.hexlify(encrypted))
        # msg = b'A message for encryption'
        # encryptor = PKCS1_OAEP.new(pubKey)
        # encrypted = encryptor.encrypt(msg)
        # print("Encrypted:", binascii.hexlify(encrypted))

 



        




        
if __name__ == "__main__":
    
    root = Root()
    root.mainloop()
