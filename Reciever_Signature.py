import hashlib
import tkinter as tk
from tkinter import ttk

class Root(tk.Tk):
    # hash_str_1 = ''
    # hash_str_2 = ''
    def __init__(self) :
        super().__init__()
        # wondows paramaters
        self.title("signator reciever/ verifier")
        self.geometry("600x400")
        self.resizable(1,1)
        # variables that i will need
    
        self.sign_label = tk.StringVar(self)
        self.msg_label = tk.StringVar(self)
   


        
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
        self.message_label  = tk.Label(self, text="the recieved message", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.result_message_label = tk.Label(self, text="the hash of the message", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.signature_label = tk.Label(self, text="the recieved signature", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.result_signature_label = tk.Label(self, text=" the decrypted signature", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.validation = tk.Label(self, text="valide message?", justify='center',bg='#FFFFFF', width=20  )
        
        # grid positions
        self.columnconfigure(0,weight=2)
        self.rowconfigure(0,weight=2)
        self.columnconfigure(1,weight=2)
        self.rowconfigure(1,weight=1)
        self.columnconfigure(2,weight=2)
        self.rowconfigure(2,weight=3)
        

        self.message_label.grid(column=0,row=0, sticky=tk.W, padx=0, pady=1)
        self.hash_button.grid(column=0,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_message_label.grid(column=0,row=2, sticky=tk.W, padx=0, pady=1)


        self.signature_label.grid(column=1,row=0, sticky=tk.W, padx=0, pady=1)
        self.decrypt_button.grid(column=1,row=1, sticky=tk.W, padx=0, pady=1)
        self.result_signature_label.grid(column=1,row=2, sticky=tk.W, padx=0, pady=1)

        self.valide_button.grid(column=2,row=0, sticky=tk.W, padx=0, pady=1)
        self.validation.grid(column=2,row=1, sticky=tk.W, padx=0, pady=1)
        self.exit_button.grid(column=2,row=2, sticky=tk.W, padx=0, pady=1)
        
    
    def hash_string(self): 
        hash_fonction= getattr(hashlib,self.selected_hash.get() )# transformer le string a une fonction de hashage du bib "hashlib"
        self.msg_label.set(hash_fonction(self.message_label.get().encode()).hexdigest())
        self.result_message_label.config(text=self.msg_label.get())
      
    def decrypt_string(self): 
        #hash_fonction= getattr(hashlib,self.selected_hash.get() )# transformer le string a une fonction de hashage du bib "hashlib"
        #self.sign_label.set(hash_fonction(self.signature_label.get().encode()).hexdigest())
        decryptor = PKCS1_OAEP.new(keyPair)
        sign_label = decryptor.decrypt(self.signature_label)
        self.result_signature_label.config(text=self.sign_label.get())
      
    def compare_hash(self): # comparer les deux hash
        if self.result_message_label.get() == self.result_sign_label.get() : 
            self.validation.config(text="valide message", fg='#32cd32')
        else : self.validation.config(text="not valide",fg='#ff0000')
    



        
if __name__ == "__main__":
    
    root = Root()
    root.mainloop()