# import tkinter module & other necessary modules
from tkinter import *
from tkinter import scrolledtext, messagebox
import tkinter as tk
import base64, time, random


class Decrpyt:
    def __init__(self, master):

        self.master = master

        # TIME
        localtime = time.asctime(time.localtime(time.time()))

        self.title_l = Label(master, font=('bazooka', 20, 'bold'),text="SECRET MESSAGING \n Vigenère cipher")
        self.title_l.place(x=380, y=30)

        self.time_l = Label(master, font='italic 15 bold', text=localtime, fg="Steel Blue", )
        self.time_l.place(x=380, y=120)

        self.name_l = Label(master, font='arial 16 bold', text="Name:")
        self.name_l.place(x=350, y=170)

        self.name_e = Entry(master, font='arial 16 bold')
        self.name_e.place(x=440, y=170)

        # labels
        self.lblMsg = Label(master, font='arial 16 bold',text="Message")
        self.lblMsg.place(x=350, y=350)

        self.txtMsg = tk.scrolledtext.ScrolledText(master, font='arial 15 bold', height=5, width=40)
        self.txtMsg.place(x=440, y=350)

        self.lblkey = Label(master, font=('arial', 16, 'bold'),text="Key:")
        self.lblkey.place(x=350, y=220)

        self.txtkey = Entry(master, font=('arial 16 bold'))
        self.txtkey.place(x=440, y=220)

        self.lblmode = Label(master, font='arial 16 bold',text="Mode:")
        self.lblmode.place(x=350, y=270)

        self.txtmode = Entry(master, font='arial 16 bold')
        self.txtmode.place(x=440, y=270)

        self.lblService = Label(master, font='arial 16 bold',text="Result:")
        self.lblService.place(x=350, y=490)

        self.txtService = tk.scrolledtext.ScrolledText(master, font='arial 15 bold', height=5, width=40)
        self.txtService.place(x=440, y=490)

        # Show message button
        self.btnTotal = Button(master, font=('arial', 16, 'bold'),text="Show Message",command=self.Ref)
        self.btnTotal.place(x=400, y=650)

        # Reset button
        self.btnReset = Button(master, font=('arial', 16, 'bold'), text="Reset", bg="green",command=self.Reset)
        self.btnReset.place(x=670, y=650)

        # Exit button
        self.btnExit = Button(master,font=('arial', 16, 'bold'), text="Exit", bg="red", command=self.qExit)
        self.btnExit.place(x=780, y=650)

    # exit function
    def qExit(self):
        root.destroy()

    # Function to reset the window
    def Reset(self):
        self.name_e.delete(0, END)
        self.txtMsg.delete('1.0', END)
        self.txtkey.delete(0, END)
        self.txtmode.delete(0, END)
        self.txtService.delete('1.0', END)

    def verify(self):
        if self.txtMsg.get('1.0', END) == '' and self.txtkey.get() == '':
            messagebox.showerror('Empty Inputs', 'Check your Message/Key')
        elif self.txtmode.get() == '':
            messagebox.showerror('Empty Mode', 'Invalid mode')
        else:
            pass

    # Vigenère cipher
    # Function to encode

    def encode(self, key, clear):
        self.verify()
        enc = []

        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) +
                         ord(key_c)) % 256)

            enc.append(enc_c)

        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    # Function to decode
    def decode(self, key, enc):
        dec = []

        enc = base64.urlsafe_b64decode(enc).decode()
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) -
                         ord(key_c)) % 256)

            dec.append(dec_c)
        return "".join(dec)

    def Ref(self):
        Msg = self.txtMsg
        key = self.txtkey
        mode = self.txtmode
        Result = self.txtService
        self.verify()

        clear = Msg.get('1.0', END)
        k = key.get()
        m = mode.get()

        if (m == 'e'):

            Result.insert('1.0', self.encode(k, clear))
        else:
            Result.insert('1.0', self.decode(k, clear))


root = Tk()
Decrpyt(root)
# defining size of window
root.geometry("1200x6000")
# setting up the title of window
root.title("Message Encryption and Decryption")
# keeps window alive
root.mainloop()
