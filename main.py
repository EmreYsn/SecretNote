from tkinter import *
from tkinter import messagebox
from PIL import ImageTk , Image
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_files():
    title = entry_1.get()
    message = text_1.get("1.0" , END)
    master_secret = entry_2.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error",message="Please enter all info !!!")
    else:
        message_encrypted = encode(master_secret , message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            entry_1.delete(0,END)
            entry_2.delete(0,END)
            text_1.delete("1.0",END)

def decrypt_notes():
    message_encrypted = text_1.get("1.0", END)
    master_secret = entry_2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            text_1.delete("1.0", END)
            text_1.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

window = Tk()
window.title("Secret Notes")
window.config(width=400 ,height=400 )

FONT = ("Ariel",20,"italic")

img = ImageTk.PhotoImage(Image.open("top secret.jpg"))
pic_label = Label(window ,image=img )
pic_label.pack()

label_1 = Label()
label_1.config(text="Enter your title",font=FONT)
label_1.pack()

entry_1 = Entry()
entry_1.config(width=60)
entry_1.pack()

label_2 = Label()
label_2.config(text="Enter your secret",font=FONT)
label_2.pack()

text_1 = Text()
text_1.config(width=40 ,height=15)
text_1.pack()

label_4 = Label()
label_4.config(text="Enter master key",font=FONT)
label_4.pack()

entry_2 = Entry()
entry_2.config(width=30)
entry_2.pack()

button_1 = Button(text="Save & Encrypt",width=15 , command=save_files)
button_1.pack()

button_2 = Button(text="Decrypt",width=5,command=decrypt_notes)
button_2.pack()

window.mainloop()
