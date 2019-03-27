#!/usr/bin/python3

from database import CaptureDatabase
import sys

import tkinter as tk
from tkinter.filedialog import askopenfilename
'''
from tkinter import *
from tkinter.filedialog import askopenfilename
'''
#from tkinter import messagebox

dbFields = 'host', 'database', 'user', 'passwd'
captureFields = 'File', 'Activity', 'Details'
deviceFields = 'Model', 'Internal Name', 'Device Category', 'Communication Standards', 'Notes'
deviceOptions = 'WiFi', 'Bluetooth', 'Zigbee', 'ZWave', '4G', '5G', 'Other'
deviceStateFields = 'Firmware Version' #maybe include this with device fields entry and note that it will be associated with the capture only

fields = 'Last Name', 'First Name', 'Job', 'Country'

#GUI Class for the MUD Capture Analysis
class  MUDcapGUI(tk.Frame):
    def __init__(self,parent=None): 
        tk.Frame.__init__(self,parent)
        self.parent = parent
        self.pack()
        #self.makeDbForm()
        self.ents = self.make_form_database(dbFields)

        #self.bind('<Return>', (lambda event, e=ents: self.fetch(e)))   
        self.bind('<Return>', (lambda event, e=self.ents: self.database_connect(e)))   

        self.b_connect = tk.Button(self.parent, text='Connect',
                         #command=(lambda e=ents: self.fetch(e)))
                         command=(lambda e=self.ents: self.database_connect(e)))
        self.b_quit = tk.Button(self.parent, text='Quit', command=self.__exit__)#self.parent.quit)

        if sys.platform == "win32":
            self.b_quit.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_quit.pack(side=tk.RIGHT, padx=5, pady=5)

    def make_form_database(self, fields):
        self.winfo_toplevel().title("MUD Capture - Connect to Database")

        entries = []

        try:
            db_config = read_db_config()
        except:
            db_config = {"host": "", "database" : "", "user" : "", "passwd" : ""}

        for field in fields:
            row = tk.Frame(self)
            #row = Frame(root)
            lab = tk.Label(row, width=15, text=field, anchor='w')
            if field == "passwd":
                ent = tk.Entry(row, show="\u2022", width=15)
            else:
                ent = tk.Entry(row)
            ent.insert( 10, db_config.get(field,"none") )

            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            lab.pack(side=tk.LEFT)
            ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
            entries.append((field, ent))

        return entries

    def fetch(entries):
        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            print('%s: "%s"' % (field, text)) 

    def database_connect(self, entries):
        db_config = {}

        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            db_config[field] = text
            print('%s: "%s"' % (field, text)) 

        self.db = CaptureDatabase(db_config)

    def __exit__(self):
        try:
            self.db.__exit__()
            print("Cleaned up on exit")
        except:
            print("Problem with cleanup")

        self.parent.quit()






def openFileCallBack(entry):
    Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing

    #filename = tk.filedialog.askopenfilename() # show an "Open" dialog box and return the path to the selected file
    filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
    entry.delete(0, END)
    entry.insert(0, filename)

def makeCaptureForm(root, fields):
    entries = []
    for i, field in enumerate(fields):
        row = Frame(root)
        lab = Label(row, width=15, text=field, anchor='w')
        ent = Entry(row)
        
        if i == 0:
            b = Button(row, text='...', command=(lambda e=ent: openFileCallBack(e)))#openFileCallBack())
            row.pack(side=TOP, fill=X, padx=5, pady=5)
            lab.pack(side=LEFT)
            ent.pack(side=LEFT, fill=X)
            b.pack(side=LEFT, expand=YES, fill=X)
        else:
            row.pack(side=TOP, fill=X, padx=5, pady=5)
            lab.pack(side=LEFT)
            ent.pack(side=RIGHT, expand=YES, fill=X)
            
        entries.append((field, ent))

    return entries
         
def fetch(entries):
    for entry in entries:
        field = entry[0]
        text  = entry[1].get()
        print('%s: "%s"' % (field, text)) 

def makeform(root, fields):
    entries = []
    for field in fields:
        row = Frame(root)
        lab = Label(row, width=15, text=field, anchor='w')
        ent = Entry(row)
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lab.pack(side=LEFT)
        ent.pack(side=RIGHT, expand=YES, fill=X)
        entries.append((field, ent))

    return entries
    
def importFileWindow(entry):
    #Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
    importFile = Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
    
    f_details = makeImportForm(importFile, captureFields)
    importFile.bind('<Return>', (lambda event, e=ents: fetch(e)))

    b_submit = Button(importFile, text="Submit",
                      command=(lambda e=ents: fetch(e)))
    b_submit.pack(side=LEFT, padx=5, pady=5)

    b_submit = Button(importFile, text="Quit", command=root.quit)
    b_submit.pack(side=LEFT, padx=5, pady=5)

    importFile.mainloop()

#class 

def makeDbForm(root, fields):
    entries = []

    try:
        db_config = read_db_config()
    except:
        db_config = {"host": "", "database" : "", "user" : "", "passwd" : ""}
    
    for field in fields:
        row = Frame(root)
        lab = Label(row, width=15, text=field, anchor='w')
        if field == "passwd":
            ent = Entry(row, show="\u2022", width=15)
        else:
            ent = Entry(row)
            #ent.insert( 10, db_config.get(field,"none") )
        ent.insert( 10, db_config.get(field,"none") )

        #print(field + " = " + db_config.get(field,"none"))

        row.pack(side=TOP, fill=X, padx=5, pady=2)
        lab.pack(side=LEFT)
        ent.pack(side=RIGHT, expand=YES, fill=X)
        entries.append((field, ent))

    return entries


#Password field:
#widget = Entry(parent, show="\u2022", width=15) #show="*"
from configparser import ConfigParser
def read_db_config(filename='config.ini', section='mysql'):
    parser = ConfigParser()
    parser.read(filename)

    db = {}
    if parser.has_section(section):
        items = parser.items(section)
        for item in items:
            db[item[0]] = item[1]
    else:
        raise Exception('{0} not found in the {1} file'.format(section, filename))

    return db


if __name__ == '__main__':
    root = tk.Tk()

    gui = MUDcapGUI(root)

    '''
    #ents = makeform(root, fields)
    ents = makeDbForm(root, dbFields)
    #dbents = makeDbForm(root, dbFields)
    #ents = makeCaptureForm(root, captureFields)
    root.bind('<Return>', (lambda event, e=ents: fetch(e)))   

    b1 = Button(root, text='Submit',
                command=(lambda e=ents: fetch(e)))
    b2 = Button(root, text='Quit', command=root.quit)

    if sys.platform == "win32":
        b2.pack(side=RIGHT, padx=5, pady=5)
        b1.pack(side=RIGHT, padx=5, pady=5)
    else:
        b1.pack(side=RIGHT, padx=5, pady=5)
        b2.pack(side=RIGHT, padx=5, pady=5)






    '''
    '''
    if sys.platform == "win32":
        b1 = Button(root, text='Submit',
                    command=(lambda e=ents: fetch(e)))
        b1.pack(side=LEFT, padx=5, pady=5)

        b2 = Button(root, text='Quit', command=root.quit)
        b2.pack(side=LEFT, padx=5, pady=5)
    else:
        b2 = Button(root, text='Quit', command=root.quit)
        b2.pack(side=LEFT, padx=5, pady=5)

        b1 = Button(root, text='Submit',
                    command=(lambda e=ents: fetch(e)))
        b1.pack(side=LEFT, padx=5, pady=5)
    '''
    root.mainloop()


'''
#! /usr/bin/python

import tkinter
from tkinter.filedialog import askopenfilename
from tkinter import messagebox

top = tkinter.Tk()
top.title("MUD Packet Capture GUI")

def helloCallBack():
    messagebox.showinfo( "Hello Python", "Hello World")

def openFileCallBack():
    tkinter.Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
    filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
    print(filename)
    

B_hello = tkinter.Button(top, text ="Hello", command = helloCallBack)
B_hello.pack()

B_file = tkinter.Button(top, text ="File", command = openFileCallBack)
B_file.pack()

top.mainloop()
'''
