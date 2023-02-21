import hashlib
import tkinter as tk
from tkinter import ttk

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import binascii

class Receiver(tk.Toplevel):

    def __init__(self) :
        super().__init__()
        # wondows paramaters
        self.title("signator reciever/ verifier")
        self.geometry("600x400")
        self.resizable(1,1)
        # variables that i will need
    
        self.signature_Sender_Var = tk.StringVar(self)
        self.message_Sender_Var = tk.StringVar(self)
        self.result_of_Hashed_message_Var = tk.StringVar(self)
        self.result_of_decrypted_signature_Var = tk.StringVar(self)
        

        
        # all Button
        self.hash_button = tk.Button(self,
                                       text="Hash",
                                       command=lambda:self.hash_string(),
                                       activebackground='#959595',
                                       width=17)
        self.decrypt_button = tk.Button(self,
                                     text="Decrypt the message",
                                      command=lambda:self.decrypt_string(),
                                      activebackground='#959595',
                                      width=17)
        self.valide_button= tk.Button(self,
                                    text="Verify",
                                    command=self.compare_hash,activebackground='#959595',
                                    width=17 )
      
        self.exit_button = tk.Button(self,text='exit', command=lambda:self.destroy(), width= 17)
        

        # all labels
        self.message_Sender_label  = tk.Label(self, text="the recieved message",textvariable=self.message_Sender_Var, justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.result_of_hashed_message_label = tk.Label(self, text="the hash of the message", textvariable=self.result_of_Hashed_message_Var ,justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.signature_Sender_label = tk.Label(self, text="the recieved signature",textvariable=self.signature_Sender_Var, justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.result_of_decrypted_signature_label = tk.Label(self, text=" the decrypted signature", textvariable=self.result_of_decrypted_signature_Var , justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.validation = tk.Label(self, text="valide message?", justify='center',bg='#FFFFFF', width=20  )
        
        # grid positions
        self.columnconfigure(0,weight=2)
        self.rowconfigure(0,weight=2)
        self.columnconfigure(1,weight=2)
        self.rowconfigure(1,weight=1)
        self.columnconfigure(2,weight=2)
        self.rowconfigure(2,weight=3)
        

        self.message_Sender_label.grid(column=0,row=0, sticky=tk.W, padx=0, pady=1)
        self.hash_button.grid(column=0,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_of_hashed_message_label.grid(column=0,row=2, sticky=tk.W, padx=0, pady=1)


        self.signature_Sender_label.grid(column=1,row=0, sticky=tk.W, padx=0, pady=1)
        self.decrypt_button.grid(column=1,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_of_decrypted_signature_label.grid(column=1,row=2, sticky=tk.W, padx=0, pady=1)

        self.valide_button.grid(column=2,row=0, sticky=tk.W, padx=0, pady=1)
        self.validation.grid(column=2,row=1, sticky=tk.W, padx=0, pady=1)
        self.exit_button.grid(column=2,row=2, sticky=tk.W, padx=0, pady=1)
    
    def Set_Signature_Sender(self, Sign:str):
        self.signature_Sender_Var.set(Sign[:100])
        
        # self.signature_Sender_label.configure(text=self.signature_Sender_Var.get()[:100])

    def Set_Message_Sender(self, Msg):
        self.message_Sender_Var.set(Msg)
        self.message_Sender_label.configure(text=self.message_Sender_Var.get())
    
    def hash_string(self): 
        selected = root.Get_selected_hash()
        hash_fonction= getattr(hashlib,selected  )# transformer le string a une fonction de hashage du bib "hashlib"
        self.result_of_Hashed_message_Var.set(hash_fonction(self.message_Sender_Var.get().encode('ascii')).hexdigest())
      
    def decrypt_string(self): 
        decryptor = PKCS1_OAEP.new(root.Get_Private_Key())
        decrypted = decryptor.decrypt(root.Get_Native_encrypted()).decode('ascii')
        self.result_of_decrypted_signature_Var.set(decrypted)
        self.result_of_decrypted_signature_label.configure(text=self.result_of_decrypted_signature_Var.get())

      
    def compare_hash(self):
        if str(self.result_of_Hashed_message_Var.get()) == str(self.result_of_decrypted_signature_Var.get()) : 
            self.validation.config(text="valide message", fg='#32cd32')
        else : self.validation.config(text="not valide",fg='#ff0000')
 

class Sender(tk.Tk):
    def __init__(self):
        super().__init__()
        # Windows parameters 
        self.title("THE sender signature")
        self.geometry("600x400")
        self.resizable(1, 1)

        # variables that I will need 
        self.message = tk.StringVar(self)
        self.selected_hash =tk.StringVar(self, value='md5')
        self.selected_hash_str = self.selected_hash.get()
        self.Encyption_Method = tk.StringVar(self, value='RSA')
        self.hash_Result = tk.StringVar(self)
        self.PublicKey = None
        self.PrivateKey = None
        self.Native_encrypted = bytes()
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
        self.Signature_txt = tk.Text(self, width=17  , height=10, state='disabled' )
        # scroll Bar 

        self.scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.Signature_txt.yview)
        # self.scrollbar.grid(row=0, column=1, sticky=tk.NS)
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
        self.Signature_txt.grid(column=1,row=3, sticky=tk.W, padx=0, pady=1)
    
    def Get_Private_Key(self):
        return self.PrivateKey

    def Get_selected_hash(self):
        return self.selected_hash_str
    def Get_Native_encrypted(self):
        return self.Native_encrypted
    def Send_to_Salma(self):
        # open the window
        Win = Receiver()
        #Send message 
        Win.Set_Signature_Sender(self.Signature_Result.get())
        #Send Hash
        Win.Set_Message_Sender(self.message.get())

    def RSA_Key_Generation(self,Number):
        self.PrivateKey = RSA.generate(Number)
        # generate RSA Key
        self.PublicKey = self.PrivateKey.publickey()

        # pubKeyPEM = self.PublicKey.exportKey()
        # print(pubKeyPEM.decode('ascii'))

        # privKeyPEM = self.PrivateKey.exportKey()
        # print(privKeyPEM.decode('ascii'))


    def Sign_THE_Hash(self):

        self.RSA_Key_Generation(3072)

        hash_fonction= getattr(hashlib ,self.selected_hash.get() )
        self.hash_Result.set(hash_fonction(self.Input_Message.get().encode()).hexdigest())


        msg = bytes(str(self.hash_Result.get()), encoding='ascii')
        encryptor = PKCS1_OAEP.new(self.PublicKey)
        self.Native_encrypted = encryptor.encrypt(msg)
        cypher_txt = binascii.hexlify(self.Native_encrypted).decode('ascii')
        self.Signature_Result.set(cypher_txt)
        self.Signature_txt['state']= 'normal'
        self.Signature_txt.insert('1.0',cypher_txt)
        self.Signature_txt['state']= 'disabled'
        # self.Signature_txt.config(text=self.Signature_Result.get())

        # print("Encrypted:", binascii.hexlify(encrypted))
        # msg = b'A message for encryption'
        # encryptor = PKCS1_OAEP.new(pubKey)
        # encrypted = encryptor.encrypt(msg)
        # print("Encrypted:", binascii.hexlify(encrypted))
        


 



        




        
if __name__ == "__main__":
    
    root = Sender()
    root.mainloop()
