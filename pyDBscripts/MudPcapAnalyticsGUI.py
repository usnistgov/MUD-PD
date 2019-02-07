#! /usr/bin/python

import tkinter
from tkinter import messagebox

top = tkinter.Tk()
top.title("MUD Packet Capture GUI")

def helloCallBack():
    messagebox.showinfo( "Hello Python", "Hello World")

B = tkinter.Button(top, text ="Hello", command = helloCallBack)
B.pack()

top.mainloop()
