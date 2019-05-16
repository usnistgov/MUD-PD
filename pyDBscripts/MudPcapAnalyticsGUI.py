#!/usr/bin/python3

from bidict import BiDict
from capture_database import CaptureDatabase
#from capture_database import DatabaseHandler
from capture_database import CaptureDigest
import hashlib
from lookup import lookup_mac, lookup_hostname
from multicolumn_listbox import MultiColumnListbox
import sys

import tkinter as tk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
'''
from tkinter import *
from tkinter.filedialog import askopenfilename
'''

field2db = BiDict({'File':'fileName', 'Activity':'activity', 'Details':'details',
                   'Date of Capture':'capDate', 'Time of Capture':'capTime',
                   'Manufacturer':'mfr' , 'MAC':'mac_addr', 'Model':'model', 'Internal Name':'internalName',
                   'Category':'deviceCategory', 'Notes':'notes',
                   'MUD':'mudCapable', 'WiFi':'wifi', 'Bluetooth':'bluetooth', 'Zigbee':'zigbee',
                   'ZWave':'zwave', '3G':'G3', '4G':'G4', '5G':'G5', 'Other':'otherProtocols',
                   'Firmware Version': 'fw_ver', 'IP Address' : 'ipv4_addr', 'IPv6 Address' : 'ipv6_addr'})
dbFields = 'host', 'database', 'user', 'passwd'
#dbField2Var = {'Host' : 'host', 'Database' : 'database', 'Username' : 'user', 'Password' : 'passwd'}
captureFields = 'File', 'Activity', 'Details'
#captureField2Var = {'File' : 'fileLoc', 'Activity' : 'activity', 'Details' : 'details'}
captureInfoFields = 'Date of Capture', 'Time of Capture'#, 'Devices'
#deviceFields = 'Model', 'Internal Name', 'Device Category', 'Communication Standards', 'Notes'
deviceFields = 'Manufacturer', 'Model', 'MAC', 'Internal Name', 'Category', 'Notes', 'Capabilities'
#deviceField2Var = {'Model' : 'model', 'Internal Name' : 'internalName', 'Device Category' : 'deviceCategory', 'Communication Standards', 'Notes': 'notes'}
#deviceOptions = 'WiFi', 'Bluetooth', 'Zigbee', 'ZWave', '4G', '5G', 'Other'
deviceOptions = 'MUD', 'WiFi', 'Bluetooth', 'Zigbee', 'ZWave', '3G', '4G', '5G', 'Other'
#deviceOptions2Var = {'WiFi' : 'wifi', 'Bluetooth' : 'bluetooth', 'Zigbee' : 'zigbee', 'ZWave' : 'zwave', '4G' : '4G', '5G' : '5G', 'Other', 'other'}
#deviceStateFields = 'Firmware Version' #maybe include this with device fields entry and note that it will be associated with the capture only

#fields = 'Last Name', 'First Name', 'Job', 'Country'



'''
class popupWindow(object):
    def __init__(self, master):
        top=self.top = tk.Toplevel(master)
        self.l = tk.Label(top,text="Hello World")
        self.l.pack()
        self.e = tk.Entry(top)
        self.e.pack()
        self.b = tk.Button(top, text='Ok', command=self.cleanup)
    def cleanup(self):
        self.value=self.e.get()
        self.top.destroy()
'''

'''
  +--------+--------+
  |        |        |
  |  menu bar frame |
  |        |        |
  +--------+--------+
  | capture| device |
  | list   | list   |
  |   |    |        |
  +-- | ---+--------+
  |   V    | comm   |
  |        | detail |
  |        |        |
  +--------+--------+
  |        |        |
  | status bar frame|
  |        |        |
  +--------+--------+

  +----------------------------------------------------------------------+
  | Menu bar (menuFrame)                                                 |
  +-------------------+--------------------------------------------------+
  | Capture List (capFrame) | Device List (devFrame)                     |
  +-------------------------+--------------------------------------------+
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         +--------------------------------------------+
  |                         | Communications Details (commFrame)         |
  |                         +--------------------------------------------+
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  |                         |                                            |
  +-------------------------+--------------------------------------------+
  | Status bar                                                           |
  +----------------------------------------------------------------------+

'''

#GUI Class for the MUD Capture Analysis
class  MudCaptureApplication(tk.Frame):


    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.parent.title("MUDdy Networks") #MUDdy Airwaves

        self.window_stack = []
        self.yield_focus(self.parent)

        # Main menu bar
        self.fileMenu = tk.Menu(self.parent)
        self.parent.config(menu=self.fileMenu)
        self.fileSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="File", menu=self.fileSubMenu)
        self.fileSubMenu.add_command(label="Connect to Database...", command=self.popup_connect2database)
        self.fileSubMenu.add_command(label="Import Capture File...", command=self.popup_import_capture)
        self.fileSubMenu.add_separator()
        self.fileSubMenu.add_command(label="Quit", command=self.__exit__)
        
#        self.helpMenu = tk.Menu(self.parent)
#        self.parent.config(menu=self.helpMenu)
#        self.helpSubMenu = tk.Menu(self.helpMenu)
        self.helpSubMenu = tk.Menu(self.fileMenu)
#        self.helpMenu.add_cascade(label="Help", menu=self.helpSubMenu)
        self.fileMenu.add_cascade(label="Help", menu=self.helpSubMenu)
        self.helpSubMenu.add_command(label="About", command=self.popup_about)


        #### Main Window ####
        # Menu top
        self.menuFrame = tk.Frame(self.parent, bd=1, bg="#dfdfdf") #, bg="#dfdfdf"
        #b_connect = tk.Button(self.menuFrame)
        #b_connect = tk.Button(self.menuFrame, text="Connect", command=self.popup_connect2database, fg="black", highlightbackground="#dfdfdf")#, anchor=tk.N+tk.W)
        #icon_connect = tk.PhotoImage(file="icons/database40px.png")
        icon_connect = tk.PhotoImage(file="icons/database40px.png")
        #b_connect = tk.Button(self.menuFrame, compound="top", image=icon_connect, width="40", height="40", command=self.popup_connect2database, highlightbackground="#dfdfdf", activebackground="black", bd=0, highlightthickness=0)
        b_connect = tk.Button(self.menuFrame, compound="top", image=icon_connect, width="40", height="40", command=self.popup_connect2database, highlightthickness=0, activebackground="black", bd=0)
        b_connect.image = icon_connect
        b_connect.pack(side="left")

        #b_connect.config(image=icon_connect_small, width="40",height="40", command=self.popup_connect2database, activebackground="black", bd=0, compound="left")

        #b_import = tk.Button(self.menuFrame, text="Import", command=self.popup_import_capture, highlightbackground="#dfdfdf")#, anchor=tk.N+tk.W)
        icon_import = tk.PhotoImage(file="icons/import40px.png")
        #b_import = tk.Button(self.menuFrame, compound="top", image=icon_import, width="40", height="40", command=self.popup_import_capture, highlightbackground="#dfdfdf", activebackground="black", bd=0, highlightthickness=0)
        b_import = tk.Button(self.menuFrame, compound="top", image=icon_import, width="40", height="40", command=self.popup_import_capture, highlightthickness=0, activebackground="black", bd=0)
        b_import.image = icon_import
        b_import.pack(side="left")
        #b_import.config(image=icon_import,width="10",height="10")

        '''
        b_m = tk.Button(self.menuFrame, text="M", fg="magenta", highlightbackground="#dfdfdf")#, anchor=tk.N+tk.W)
        b_m.pack(side="left")
        '''
        b_y = tk.Button(self.menuFrame, text="Generate MUD File", fg="gray", highlightbackground="#dfdfdf", wraplength=80)#, anchor=tk.N+tk.W)
        b_y.pack(side="left")

        ### Left (capture) frame ###
        self.capFrame = tk.Frame(self.parent, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        # title
        self.cap_title_var=tk.StringVar()
        self.cap_title_var.set("Captures")
        self.cap_title = tk.Label(self.capFrame, textvariable=self.cap_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.cap_title.pack(side="top", fill=tk.X)

        # capture list
        self.cap_header = ["Date","Capture Name","Activity", "Details","Capture File Location"]
        self.cap_list = MultiColumnListbox(self.capFrame, self.cap_header, list(), keep1st=True)
        #self.cap_list.bind("<<ListboxSelect>>", self.update_dev_list)
        self.cap_list.bind("<<TreeviewSelect>>", self.update_dev_list)
        '''
        self.cap_list.bind("<Double-Button-1>>", (lambda idx=0, hd0=4, hd1=1
                                                  : self.popup_import_capture_devices(
                    CaptureDigest(self.cap_list.get(self.cap_list.selection()[idx])[hd0] + "/" + 
                                  self.cap_list.get(self.cap_list.selection()[idx])[hd1]))))
        '''

        #(lambda d=unknown_dev_list.curselection(): self.popup_import_device(d)))
        b_inspect = tk.Button(self.capFrame, text="Inspect",
                              #command=(lambda c=CaptureDigest((lambda x=None, idx=0, hd0=4, hd1=1
                              #                                 : self.cap_list.selection(x)[idx].get(self.cap_header[hd0]) +
                              #                                   self.cap_list.selection(x)[idx].get(self.cap_header[hd1])))
                              #         : self.popup_import_capture_devices(c)))
                              
                              command=(lambda hd0=4, hd1=1 :
                                           self.popup_import_capture_devices(
                    CaptureDigest(
                        self.cap_list.get_selected_row()[hd0] + "/" +
                        self.cap_list.get_selected_row()[hd1]))))
        '''
                              command=(lambda self, cap=CaptureDigest(
                    self.cap_list.get_selected_row()[4] + "/" +
                    self.cap_list.get_selected_row()[1]) : 
                                       self.popup_import_capture_devices(cap)))
        '''

        '''
                              command=(lambda idx=0, hd0=4, hd1=1
                                       : self.popup_import_capture_devices(
                    CaptureDigest(self.cap_list.get(self.cap_list.selection()[idx])[hd0] + "/" + 
                                  self.cap_list.get(self.cap_list.selection()[idx])[hd1]))))
        '''
        b_inspect.pack(side="right")
        self.cap = None

        '''
        # scrollbar
        self.cap_scrollbar = tk.Scrollbar(self.capFrame)
        self.cap_scrollbar.pack(side="right", fill="both")

        # capture list
        self.cap_list = tk.Listbox(self.capFrame, yscrollcommand = self.cap_scrollbar.set, selectmode="extended", exportselection=0, bd=0)
        self.cap_list.bind("<<ListboxSelect>>", self.update_dev_list)
        '''

        #self.cap_list.pack(side="left", fill="both", expand=True)
        #self.cap_scrollbar.config( command = self.cap_list.yview )

        ### Right Frame ###
        self.rightFrame = tk.Frame(self.parent, width=500, bd=1, bg="#dfdfdf")

        ## Top Right (device) frame ##
        self.devFrame = tk.Frame(self.rightFrame, width=500)#, bd=1, bg="#eeeeee")

        # title
        self.dev_title_var=tk.StringVar()
        self.dev_title_var.set("Devices")
        self.dev_title = tk.Label(self.devFrame, textvariable=self.dev_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.dev_title.pack(fill=tk.X)

        '''
        # scrollbar
        self.dev_scrollbar = tk.Scrollbar(self.devFrame)
        self.dev_scrollbar.pack(side="right", fill="both")
        '''

        # device list
        #self.dev_list = tk.Listbox(self.devFrame, yscrollcommand = self.dev_scrollbar.set, selectmode="extended", exportselection=0, bd=0)
        self.dev_header = ["Manufacturer", "Model", "Internal Name", "MAC", "Category"]
        self.dev_list = MultiColumnListbox(self.devFrame, self.dev_header, list(), keep1st=True)
        self.dev_list.bind("<<ListboxSelect>>", self.update_comm_list)

        '''
        self.dev_list.pack(side="left", fill="both", expand=True)
        self.dev_scrollbar.config( command = self.dev_list.yview )
        '''
        self.devFrame.pack(side="top", fill="both", expand=True)


        ## Bottom Right (communication) frame ##
        self.commFrame = tk.Frame(self.rightFrame, width=500, bd=1, bg="#eeeeee")

        # title
        self.comm_title_var=tk.StringVar()
        self.comm_title_var.set("Communication")
        self.comm_title = tk.Label(self.commFrame, textvariable=self.comm_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.comm_title.pack(fill=tk.X)

        # scrollbar
        self.comm_scrollbar = tk.Scrollbar(self.commFrame)
        self.comm_scrollbar.pack(side="right", fill="both")

        # communication list
        self.comm_list = tk.Listbox(self.commFrame, yscrollcommand = self.comm_scrollbar.set, selectmode="extended", exportselection=0, bd=0)
        # dummy data
        '''
        for line in range(10):
            self.comm_list.insert(tk.END, "This is line number " + str(line))
        '''
        self.comm_list.pack(side="left", fill="both", expand=True)
        self.comm_scrollbar.config( command = self.comm_list.yview )

        self.commFrame.pack(side="top", fill="both", expand=True)


        ### Status Bar ###
        self.statusFrame = tk.Frame(self.parent)
        self.status_var = tk.StringVar()
        self.status_var.set("No database connected...")
        self.status = tk.Label(self.statusFrame, textvariable=self.status_var, bd=1, bg="#eeeeee", relief=tk.SUNKEN, anchor=tk.W, padx=5)
        self.status.pack(fill="both", expand=True)


        ### Grid Placement ###
        self.menuFrame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.capFrame.grid(row=1, column=0, rowspan=2, sticky="nsew")
        self.rightFrame.grid(row=1, column=1, rowspan=2, sticky="nsew")
        self.statusFrame.grid(row=3, column=0, columnspan=2, sticky="ew")

        # Grid configuration #
        self.parent.grid_rowconfigure(1, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_columnconfigure(1, weight=3)


    def yield_focus(self, window = None):
        if len(self.window_stack) == 0:
            if window == None:
                print("Error with yielding focus")
            else:
                self.window_stack.append(window)
                self.yield_focus()
        elif window == None:
            self.window_stack[-1].grab_set()
            self.window_stack[-1].lift()
            self.window_stack[-1].attributes('-topmost',True)
        elif self.window_stack[-1] != window:
            # Previously top window yield status
            self.window_stack[-1].attributes('-topmost',False)

            # Push new window to the top of the stack
            self.window_stack.append(window)
            self.yield_focus()

            # Wait for window to close before yielding focus to next in stack
            self.window_stack[-2].wait_window(self.window_stack[-1])
            self.window_stack.pop()
            self.yield_focus()

    def popup_connect2database(self):
        #self.w_db = tk.Toplevel(self.parent)
        self.w_db = tk.Toplevel()
        self.w_db.wm_title("Connect to Database")

        self.ents = self.make_form_database(dbFields)

        self.bind('<Return>', (lambda event, e=self.ents: self.connect_and_close(e)))   

        self.b_connect = tk.Button(self.w_db, text='Connect',
                                   command=(lambda e=self.ents: self.connect_and_close(e)))
        self.b_cancel = tk.Button(self.w_db, text='Cancel', command=self.w_db.destroy)

        if sys.platform == "win32":
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        #self.parent.wait_window(self.w_db)
        #self.w_db.wait_window(self.w_db)
        self.yield_focus(self.w_db)


    #def make_form_database(self, window, fields):
    def make_form_database(self, fields):
#        self.winfo_toplevel().title("MUD Capture - Connect to Database")
        db_handler_temp = DatabaseHandler()

        entries = []

        for field in fields:
            row = tk.Frame(self.w_db)
            lab = tk.Label(row, width=15, text=field, anchor='w')
            if field == "passwd":
                ent = tk.Entry(row, show="\u2022", width=15)
            else:
                ent = tk.Entry(row)
            ent.insert( 10, db_handler_temp.config.get(field,"none") )

            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            lab.pack(side=tk.LEFT)
            ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
            entries.append((field, ent))

        return entries

    def connect_and_close(self, entries):
        db_handler_temp = DatabaseHandler()

        db_handler_temp.db_connect(entries)

        if db_handler_temp.connected:
            self.db_handler = db_handler_temp
            self.status_var.set("Connected to " + self.db_handler.config.get("database","none"))
            self.populate_capture_list()
            self.w_db.destroy()
            
        else:
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Problem connecting to database")

    def popup_import_capture(self):
        self.w_cap = tk.Toplevel()
        self.w_cap.wm_title("Import Packet Capture")
        #self.parent.wait_window(self.w)
        #self.yield_focus(self.w_cap)
        #self.w_cap.grab_set()

        self.ents = self.make_form_capture(captureFields)

        self.bind('<Return>', (lambda event, e=self.ents: self.import_and_close(e)))

        self.b_import = tk.Button(self.w_cap, text='Import',
                                  command=(lambda e=self.ents: self.import_and_close(e)))

        self.b_cancel = tk.Button(self.w_cap, text='Cancel', command=self.w_cap.destroy)

        if sys.platform == "win32":
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_import.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_import.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_cap)

    def openFileCallBack(self, entry):
        tk.Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing

        #filename = tk.filedialog.askopenfilename() # show an "Open" dialog box and return the path to the selected file
        filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
        entry.delete(0, tk.END)
        entry.insert(0, filename)

    def make_form_capture(self, fields):
        entries = []
        #entries = {}
        for i, field in enumerate(fields):
            row = tk.Frame(self.w_cap)
            lab = tk.Label(row, width=15, text=field, anchor='w')
            ent = tk.Entry(row)

            if i == 0:
                b_open = tk.Button(row, text='...', command=(lambda e=ent: self.openFileCallBack(e)))#openFileCallBack())
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.LEFT, fill=tk.X)
                b_open.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
            else:
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

            entries.append((field, ent))
            #entries[field] = ent

        return entries

    def import_and_close(self, entries):

        #Check if capture is already in database (using md5hash)
        filehash = hashlib.md5(open(entries[0][1].get(),'rb').read()).hexdigest()
        self.db_handler.db.select_unique_captures()

        if any(filehash in hash for hash in self.db_handler.db.cursor):
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Capture file already imported into database")
        else:
            tk.Tk().withdraw()
            messagebox.showinfo("Importing", "Please wait for the capture file to be processed")
            self.cap = CaptureDigest(entries[0][1].get())

            data_capture = {
                "fileName" : self.cap.fname,
                "fileLoc" : self.cap.fdir,
                "fileHash" : self.cap.fileHash,
                
                "capDate" : epoch2datetime(float(self.cap.capTimeStamp)),#epoch2datetime(float(self.cap.capDate)),
                "activity" : entries[1][1].get(),
                "details" : entries[2][1].get()
                }

            # Popup window
            #self.popup_import_capture_devices(self.cap)
            self.popup_import_capture_devices(self.cap)

            self.db_handler.db.insert_capture(data_capture)
            self.populate_capture_list()

            # Import Devices
            #self.popup_import_capture_devices(self.cap)
            #self.popup_import_device()
            '''
            for device in self.cap.uniqueMAC:
                self.db_handler.db.insert_device(device)
            '''
            self.w_cap.destroy()


    #def popup_import_capture_devices(self, cap):
    def popup_import_capture_devices(self, cap):
        self.w_cap_dev = tk.Toplevel()
        if self.cap == None or self.cap != cap:
            self.cap = cap
        #self.w_cap_dev.wm_title(cap.fname)
        self.w_cap_dev.wm_title(self.cap.fname)
        #self.yield_focus(self.w_cap_dev)
        #self.w_cap_dev.grab_set()

        self.topDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        ents = self.make_form_capture_devices(captureInfoFields, self.cap.capDate, self.cap.capTime)

        self.botDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        ## Left (Unknown) Dev Frame
        self.unknownDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.unknown_title_var=tk.StringVar()
        self.unknown_title_var.set("Unknown")
        self.unknown_title = tk.Label(self.unknownDevFrame, textvariable=self.unknown_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.unknown_title.pack(side="top", fill=tk.X)

        self.unknown_dev_header = ["Manufacturer", "MAC", "IPv4", "IPv6"]
        self.unknown_dev_list = MultiColumnListbox(parent=self.unknownDevFrame,
                                                   header=self.unknown_dev_header,
                                                   list=list(), selectmode="browse")
        self.unknown_dev_list.bind("<<TreeviewSelect>>", self.update_unknown_list_selection)

        ## Right (Known) Dev Frame
        self.knownDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.known_title_var=tk.StringVar()
        self.known_title_var.set("Known")
        self.known_title = tk.Label(self.knownDevFrame, textvariable=self.known_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.known_title.pack(side="top", fill=tk.X)

        self.known_dev_header = ["Manufacturer", "Model", "Internal Name", "Category", "MAC", "IPv4", "IPv6"]
        self.known_dev_list = MultiColumnListbox(parent=self.knownDevFrame,
                                                 header=self.known_dev_header,
                                                 list=list(), selectmode="browse")
        self.known_dev_list.bind("<<TreeviewSelect>>", self.update_known_list_selection)


        self.refresh_unknown_known_lists()
        '''
        # Sort devices from Capture into either known or unknown device lists
        self.db_handler.db.select_device_macs()
        macsInDb = self.db_handler.db.cursor.fetchall()
        print(macsInDb)
        print([x for (x,) in macsInDb])
        for mac in cap.uniqueMAC:
            print(mac)
            if mac.upper() in [x.upper() for (x,) in macsInDb]:
                # Get device info
                self.db_handler.db.select_device(mac)
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, bluetooth, G3, G4, G5, zigbee, zwave, other, notes) = self.db_handler.db.cursor.fetchone()

                # Get device state info
                self.db_handler.db.select_device_state(cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                #if ip == None:
                    ip = cap.findIP(mac)
                #if ipv6 == None:
                    ipv6 = cap.findIP(mac, v6=True)
                else:
                    print("ERROR, something went horribly wrong with the database")

                self.known_dev_list.append((mfr, model, internalName, category, mac, ip, ipv6))
            else:
                self.unknown_dev_list.append((lookup_mac(mac), mac, cap.findIP(mac), cap.findIP(mac, v6=True)))
        '''


        # Grid placements #
        self.topDevFrame.grid(row=0, column=0, sticky="new")
        self.botDevFrame.grid(row=1, column=0, sticky="nsew")
        self.cap_dev_title.grid(row=0, column=0, columnspan=2, sticky="new")
        self.unknownDevFrame.grid(row=1, column=0, sticky="nsew")
        self.knownDevFrame.grid(row=1, column=1, sticky="nsew")

        # Grid configuration #
        self.botDevFrame.grid_rowconfigure(1, weight=1)
        self.botDevFrame.grid_columnconfigure(0, weight=1)
        self.botDevFrame.grid_columnconfigure(1, weight=1)

        self.w_cap_dev.grid_rowconfigure(1, weight=1)
        self.w_cap_dev.grid_columnconfigure(0, weight=1)

        # Select first element of each list
        self.unknown_dev_list.focus(0)
        self.unknown_dev_list.selection_set(0)
        self.known_dev_list.focus(0)
        self.known_dev_list.selection_set(0)
        #self.unknown_dev_list.select_set(0)
        #self.unknown_dev_list.event_generate("<<ListboxSelect>>")
        #self.known_dev_list.select_set(0)
        #self.known_dev_list.event_generate("<<ListboxSelect>>")

        # Buttons #
        #b_close = tk.Button(self.unknownDevFrame, text='Close', command=self.w_cap_dev.destroy)
        b_close = tk.Button(self.unknownDevFrame, text='Close', command=(lambda c=self.cap.fname : self.close_w_cap_dev(c)))
        b_import = tk.Button(self.unknownDevFrame, text='Import Device',
                             command=(lambda f={'fileName':self.cap.fname,'fileHash':self.cap.fileHash}:
                                          self.popup_import_device(f)))
                                  #command=(lambda e=0, d={'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                  #                        'mac_addr':self.unknown_dev_list.get_selected_row()[1]}:
                                  #             self.popup_import_device(self.unknown_dev_list.get_selected_row()[e],d)))
                             
        b_modify = tk.Button(self.knownDevFrame, text='Modify State',
                             #command=(lambda d=self.known_dev_list.selection(): self.prep_popup_update_device_state(d)))
                             command=(lambda d=self.known_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))

        b_close.pack(side=tk.LEFT, padx=5, pady=5)
        b_import.pack(side=tk.RIGHT, padx=5, pady=5)
        b_modify.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_cap_dev)

    def update_unknown_list_selection(self, event):
        self.unknown_dev_list_sel = self.unknown_dev_list.get( self.unknown_dev_list.selection() )
        print("self.known_dev_list_sel = ", self.unknown_dev_list_sel)

    def update_known_list_selection(self, event):
        self.known_dev_list_sel = self.known_dev_list.get( self.known_dev_list.selection() )
        print("self.known_dev_list_sel = ", self.known_dev_list_sel)

    def prep_popup_update_device_state(self, d):
        d = self.known_dev_list_sel
        print("d = ",d)
        #mac = self.known_dev_list.get(d)[4]
        mac = d[4]
        self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        print(self.cap.capTimeStamp)
        temp = self.db_handler.db.cursor.fetchone()

        if temp == None:
            fw_ver = ''
        else:
            fw_ver = temp[0]

        device_state_data = {'fileHash'     : self.cap.fileHash,
                             'mac_addr'     : mac.upper(),
                             #'internalName' : self.known_dev_list.get(d)[2],
                             'internalName' : d[2],
                             'fw_ver'       : fw_ver,
                             'ipv4_addr'    : self.cap.findIP(mac),
                             'ipv6_addr'    : self.cap.findIP(mac, v6=True)}

        self.popup_update_device_state(device_state_data)

    def close_w_cap_dev(self, capName):
        self.populate_device_list(capture = capName)
        self.w_cap_dev.destroy()


    def refresh_unknown_known_lists(self):
        # Clear lists
        self.unknown_dev_list.clear()
        self.known_dev_list.clear()

        # Sort devices from Capture into either known or unknown device lists
        self.db_handler.db.select_device_macs()
        macsInDb = self.db_handler.db.cursor.fetchall()
        print("macsInDb: ", macsInDb)
        print()
        self.db_handler.db.select_known_devices_from_cap(self.cap.fileHash)
        knownMacsInDb = self.db_handler.db.cursor.fetchall()
        print("knownMacsInDb: ", knownMacsInDb)
        print()

        #print(macsInDb)
        #print([x for (x,) in macsInDb])
        for mac in self.cap.uniqueMAC:
            print("In for mac in self.cap.uniqueMAC")
            print("\tmac", mac)
            print("\tmfr = ", lookup_mac(mac))
            if mac.upper() in [x.upper() for (x,) in macsInDb]:
                # Get device info
                self.db_handler.db.select_device(mac)
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, bluetooth, G3, G4, G5, zigbee, zwave, other, notes) = self.db_handler.db.cursor.fetchone()

                # Get device state info
                self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                #if ip == None:
                    ip = self.cap.findIP(mac)
                #if ipv6 == None:
                    ipv6 = self.cap.findIP(mac, v6=True)
                else:
                    print("ERROR, something went horribly wrong with the database")

                # Check if the mac address is in the device_in_capture table and update if necessary
                if mac.upper() not in [x.upper() for (x,) in knownMacsInDb]:
                    self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                                                   'mac_addr':mac_addr.upper()})

                self.known_dev_list.append((mfr, model, internalName, category, mac, ip, ipv6))
            else:
                print("Not in macsInDb")
                print("\tmac", mac)
                print("\tmfr = ", lookup_mac(mac))
                self.unknown_dev_list.append((lookup_mac(mac), mac, self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))


    def make_form_capture_devices(self, fields, capDate, capTime):
        entries = []

        for i, field in enumerate(fields):
            row = tk.Frame(self.topDevFrame)#w_cap_dev)
            #row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
            row.pack(side=tk.TOP, fill=tk.X)

            lab = tk.Label(row, width=15, text=field, anchor='w')
            lab.pack(side=tk.LEFT, fill="both")#previously just tk.LEFT
            ent = tk.Entry(row, width=15)
            #ent.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)#previously tk.X
            ent.pack(side=tk.LEFT)#, fill=tk.X)#previously tk.X

            if not i:
                ent.insert( 10, capDate )
            else:
                ent.insert( 10, capTime )

            entries.append((field, ent))
            '''
            if i < len(fields)-1:
                lab = tk.Label(row, width=15, text=field, anchor='w')
                lab.pack(side=tk.LEFT)
                ent = tk.Entry(row)
                ent.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
                entries.append((field, ent))
            else:
                lab = tk.Label(row, width=15, text=field, anchor='s')
                lab.pack(side=tk.BOTTOM)
            '''

    #def popup_import_device(self, mfr, dev_in_cap_data):
    def popup_import_device(self, fname):
        self.w_dev = tk.Toplevel()
        self.w_dev.wm_title("Import Devices")
        #self.yield_focus(self.w_dev)
        #self.w_dev.grab_set()

        mfr = self.unknown_dev_list_sel[0]
        mac = self.unknown_dev_list_sel[1].upper()
        print(mfr)

        #ents = self.make_form_device(deviceFields, deviceOptions, mfr, dev_in_cap_data['mac_addr'])
        ents = self.make_form_device(deviceFields, deviceOptions, mfr, mac)

        dev_in_cap_data = fname
        dev_in_cap_data['mac_addr'] = mac

        #self.w_dev.bind('<Return>', (lambda event, e=ents, d=dev_in_cap_data: self.import_dev_and_close(e,d)))
        
        b_import = tk.Button(self.w_dev, text='Import',
                                  command=(lambda e=ents, d=dev_in_cap_data: self.import_dev_and_close(e,d)))

        b_cancel = tk.Button(self.w_dev, text='Cancel', command=self.w_dev.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_import.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_import.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        b_import.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_dev)


    def make_form_device(self, fields, options, mfr, mac_addr):
        entries = []

        for i, field in enumerate(fields):
            row = tk.Frame(self.w_dev)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            lab = tk.Label(row, width=15, text=field, anchor='w')
            lab.pack(side=tk.LEFT)

            if i < len(fields)-1:
                if field == 'MAC':
                    lab = tk.Label(row, width=15, text=mac_addr, anchor='w', fg='gray')
                    lab.pack(side=tk.LEFT)
                    entries.append((field, mac_addr))
                    continue
                else:
                    ent = tk.Entry(row)
                    ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

            if not i:
                ent.insert(30, mfr)

            entries.append((field, ent))

        for i, option in enumerate(options):
            if i == len(options)-1:
                row = tk.Frame(self.w_dev)
                lab = tk.Label(row, width=10, text=option, anchor='w')
                ent = tk.Entry(row)

                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                
                entries.append((option, ent))
            else:
                if i%4 == 0:
                    row = tk.Frame(self.w_dev)
                    row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

                checkvar = tk.IntVar()
                ckb = tk.Checkbutton(row, text=option, width=15, justify=tk.LEFT, variable=checkvar)
                ckb.pack(side=tk.LEFT, anchor=tk.W)
            
                entries.append((option, checkvar))

        return entries

    def import_dev_and_close(self, entries, dev_in_cap_data):
        device_data = {}
        for entry in entries:
            field = entry[0]
            if field == 'MAC':
                value = dev_in_cap_data['mac_addr']
            else:
                value = entry[1].get()

            try:
                dbfield = field2db[field]
            except:
                pass
            else:
                device_data[dbfield] = value
                print('field: %s value %s -> database field: %s' % (field, value, dbfield))

        #print(device_data)
        self.db_handler.db.insert_device(device_data)
        self.db_handler.db.insert_device_in_capture(dev_in_cap_data)
        self.refresh_unknown_known_lists()

        #mac = device_in_cap_data['mac_addr']
        mac = dev_in_cap_data['mac_addr']
        self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        try:
            (fw_ver,) = self.db_handler.db.cursor.fetchone()
        except TypeError as te:
            fw_ver = ''
            
        #device_state_data = {'fileHash'     : device_in_cap_data['fileHash'],
        device_state_data = {'fileHash'     : dev_in_cap_data['fileHash'],
                             'mac_addr'     : mac,
                             'internalName' : device_data['internalName'],
                             'fw_ver'       : fw_ver,
                             'ipv4_addr'    : self.cap.findIP(mac),
                             'ipv6_addr'    : self.cap.findIP(mac, v6=True)}

        #asdf
        try:
            self.popup_update_device_state(device_state_data)
        except _mysql_connector.MySQLInterfaceError as msqle:
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Please create a unique Internal Name")

        #self.popup_update_device_state(device_in_cap_data['fileHash'], device_in_cap_data['mac_addr'])
        self.w_dev.destroy()

    #def popup_update_device_state(self, fileHash, mac)
    def popup_update_device_state(self, device_state_data):
        self.w_dev_state = tk.Toplevel()
        self.w_dev_state.wm_title(device_state_data['internalName'])
        #self.yield_focus(self.w_dev_state)
        #self.w_dev_state.grab_set()


        ents = self.make_form_device_state(device_state_data)

        self.w_dev_state.bind('<Return>', (lambda event, d=device_state_data, e=ents: self.import_dev_state_and_close(d,e)))
        
        b_update = tk.Button(self.w_dev_state, text='Update',
                                  command=(lambda d=device_state_data, e=ents: self.import_dev_state_and_close(d, e)))

        b_close = tk.Button(self.w_dev_state, text='Close', command=self.w_dev_state.destroy)

        if sys.platform == "win32":
            b_close.pack(side=tk.RIGHT, padx=5, pady=5)
            b_update.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_update.pack(side=tk.RIGHT, padx=5, pady=5)
            b_close.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_dev_state)


    def make_form_device_state(self, device_state_data):
        entries = {}

        for i, (label, value) in enumerate(device_state_data.items()):
            if not i:
                continue
            row = tk.Frame(self.w_dev_state)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            lab = tk.Label(row, width=15, text=str(field2db.inverse[label]).replace('[','').replace(']','').replace("'",''), anchor='w')
            lab.pack(side=tk.LEFT)
            if label == 'fw_ver':
                v = tk.StringVar()
                ent = tk.Entry(row, textvariable=v)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                ent.insert(25, value)
                #entries[label] = ent
                entries[label] = v
            else:
                lab = tk.Label(row, width=25, text=value, anchor='w', fg='gray')
                lab.pack(side=tk.LEFT)
                entries[label] = value

        return entries

    def import_dev_state_and_close(self, device_state_data, entries):
        print("device_state_data: ",device_state_data)
        print("entries: ",entries)
        #device_state_data['fw_ver'] = entries[str(field2db.inverse['fw_ver']).replace('[','').replace(']','').replace("'",'')]
        print(entries['fw_ver'].get())
        device_state_data['fw_ver'] = str(entries['fw_ver'].get())
        
        # Check if there is already an entry for this data:
        self.db_handler.db.select_device_state_exact(device_state_data)
        temp = self.db_handler.db.cursor.fetchone()
        print(temp)
        if temp == None:
            self.db_handler.db.insert_device_state(device_state_data)
        self.w_dev_state.destroy()

    def fetch(self,entries):
        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            print('%s: "%s"' % (field, text)) 

    '''
    # Uses Listview
    def populate_capture_list(self):
        # clear previous list
        self.cap_list.delete(0,tk.END)
        self.cap_list.insert(tk.END, "All...")

        # Get and insert all captures currently added to database
        self.db_handler.db.select_imported_captures()

        
        for (id, fileName, fileLoc, fileHash, capDate, activity,
             details) in self.db_handler.db.cursor:
            #self.cap_list.insert(tk.END, [fileName, fileLoc, capDate, activity])
            self.cap_list.insert(tk.END, fileName) #for early stages

        # Set focus on the first element
        self.cap_list.select_set(0)
        self.cap_list.event_generate("<<ListboxSelect>>")
    '''
    # Uses Treeview
    def populate_capture_list(self):
        # clear previous list
        self.cap_list.clear()
        self.cap_list.append(("All...",))

        # Get and insert all captures currently added to database
        self.db_handler.db.select_imported_captures()

        
        #self.cap_list.populate_unique(self.db_handler.db.cursor)
        
        #["Date","Capture Name","Activity", "Details","Capture File Location"]
        for (id, fileName, fileLoc, fileHash, capDate, activity,
             details) in self.db_handler.db.cursor:
            #(capDate_date, capDate_time) = capDate.split()
            self.cap_list.append((capDate, fileName, activity, details, fileLoc)) #for early stages
            #self.cap_list.insert(tk.END, fileName) #for early stages
        
        # Set focus on the first element
        #self.cap_list.select_set(0)
        #self.cap_list.event_generate("<<ListboxSelect>>")

        #self.cap_list.selection(0)
        self.cap_list.focus(0)
        self.cap_list.selection_set(0)
        #self.cap_list.event_generate("<<TreeviewSelect>>")
        #self.cap_list.focus_set(0)
        #self.cap_list.event_generate("<<TreeviewSelect>>")

    '''
    # Uses Listbox
    def update_dev_list(self, event):
        #print("update_dev_list event = " + str(event))
        first = True

        #for cap in self.cap_list.get(self.cap_list.curselection()):
        #for cap in self.cap_list.get(0,"end"):#self.cap_list.curselection()):
        for cap in self.cap_list.curselection():
            cap_name = self.cap_list.get(cap)
            print("cap = " + cap_name)
            if cap_name == "All...":
                #self.db_handler.db.select_imported_captures()
                self.populate_device_list()
                break
            else:
                self.populate_device_list( capture=cap_name, append=(not first) )
                first=False
    '''
    # Uses Treeview
    def update_dev_list(self, event):
        first = True

        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)
            cap_date = cap_details[0]

            if cap_date == "All...":
                self.populate_device_list()
                break
            else:
                cap_name = cap_details[1]
                self.populate_device_list( capture=cap_name, append=(not first) )
                first=False
        
    # Uses Listbox
    def populate_device_list(self, capture=None, append=False):
        # clear previous list
        if not append:
            self.dev_list.delete(0,tk.END)
            self.dev_list.insert(tk.END, "All...")

        # Get and insert all captures currently added to database
        if capture == None:
            self.db_handler.db.select_devices()
        else:
            self.db_handler.db.select_devices_from_cap(capture)

        #device_list = self.db_handler.db.cursor.fetchall()
        #print(device_list)

        for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, bluetooth,
             G3, G4, G5, zigbee, zwave, otherProtocols, notes) in self.db_handler.db.cursor:
#        for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, bluetooth,
#             G3, G4, G5, zigbee, zwave, otherProtocols, notes) in device_list:
            device_list = self.dev_list.get(0, tk.END)
            #list_item = [mfr + " " + model +, mac_addr, internalName]
            #if list_item not in self.dev_list:
            #if mac_addr not in self.dev_list:
            #if list_item not in device_list:
            self.dev_list.insert(tk.END, [mfr, model, mac_addr, internalName])

        # Set focus on the first element
        #self.dev_list.select_set(0)
        #self.dev_list.event_generate("<<ListboxSelect>>")
        self.dev_list.focus(0)
        self.dev_list.selection_set(0)

        
    # Uses Treeview
    def populate_device_list(self, capture=None, append=False):
        # clear previous list
        if not append:
            self.dev_list.clear()
            self.dev_list.append(("All...",))

        # Get and insert all captures currently added to database
        if capture == None:
            self.db_handler.db.select_devices()
        else:
            self.db_handler.db.select_devices_from_cap(capture)
        

        for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, bluetooth,
             G3, G4, G5, zigbee, zwave, otherProtocols, notes) in self.db_handler.db.cursor:
            self.dev_list.append_unique((mfr, model, internalName, mac_addr, deviceCategory)) #for early stages

        self.dev_list.focus(0)
        self.dev_list.selection_set(0)



    def update_comm_list(self, event):
        #print("update_comm_list event = " + str(event))
        first = True
        #print("update_comm_list will do something eventually")

        for dev in self.dev_list.curselection():
            dev_name = self.dev_list.get(dev)

            # To simplify debugging
            break

            if type(dev_name) is str:
                print("dev = " + dev_name)
            else:
                print("dev = " + str(dev_name(0)))
            if dev_name == "All...":
                #self.db_handler.db.select_imported_captures()
                print("Processing \'All...\'")
                #for device in self.dev_list()
                self.populate_comm_list(dev_name)
                break
            else:
                self.populate_comm_list(dev_name, not first)
                first=False


    def populate_comm_list(self, device, append=False):
        # clear previous list
        if not append:
            self.comm_list.delete(0,tk.END)

        # Get and insert all captures currently added to database
        self.db_handler.db.select_device_communication(device)
        
        for (id, fileHash, mac_addr, protocol, src_port, dst_ip_addr, ipv6, dst_url,
             dst_port, notes) in self.db_handler.db.cursor:
            self.comm_list.insert(tk.END, [protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes])

        # Set focus on the first element
        self.comm_list.select_set(0)
        self.comm_list.event_generate("<<ListboxSelect>>")

    # Not yet implemented
    '''
    def populate_string_list(self, device, append=False):
        # clear previous list
        if not append:
            self.string_list.delete(0,tk.END)

        # Get and insert all captures currently added to database
        self.db_handler.db.select_device_communication(device)

        for (id, ...) in self.db_handler.db.cursor:
            self.string_list.insert(tk.END, [protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes])

    def update_string_list(self):
        print("update_comm_list will do something eventually")

    '''    

    '''
    def database_connect(self, entries):
        db_config = {}

        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            db_config[field] = text
            print('%s: "%s"' % (field, text)) 

        self.db = CaptureDatabase(db_config)
    '''

    def popup_about(self):
        w_about = tk.Toplevel()
        w_about.wm_title("About")
        #self.parent.wait_window(self.w)
        #self.yield_focus(self.w_about)
        #self.w_about.grab_set()

        summaryFrame = tk.Frame(w_about)
        summary = tk.Message(summaryFrame,
                           text="This is a proof of concept for evaluating network traffic " +
                           "for use in auditing the network, generating MUD files, and " +
                           "identifying various privacy concerns.\n\n" +
                           "This is a work in progress.", width=500)

        summaryFrame.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        summary.pack(side="left")

        srcFrame = tk.Frame(w_about)
        sources = tk.Message(srcFrame, text="Icons used under Creative Commons BY 3.0 License:\n" +
                           "CC 3.0 BY Flaticon: www.flaticon.com is licensed by " +
                           "http://creativecommons.org/licenses/by/3.0/ " +
                           "Icons made by https://www.flaticon.com/authors/smashicons\n" +
                           "Icons made by Kirill Kazachek", width=500)
        srcFrame.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        sources.pack(side="left")

        closeFrame = tk.Frame(w_about)
        b_close = tk.Button(closeFrame, text="Close", command=w_about.destroy)
        closeFrame.pack(side="top", fill="x", padx=5, pady=2, expand=True)
        b_close.pack(side="bottom", padx=5, pady=5)

        self.yield_focus(self.w_about)

    def __exit__(self):
        try:
            #self.db.__exit__()
            #self.db_handler.db.__exit__()
            self.db_handler.__exit__()
            print("Cleaned up on exit")
        except:
            print("Problem with cleanup")

        self.parent.quit()


import time
def epoch2datetime(epochtime):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epochtime))

from configparser import ConfigParser


class DatabaseHandler:


    def __init__(self, filename='config.ini', section='mysql'):

        #read_db_config(filename, section)
        try:
            self.config = self.read_db_config(filename, section)
        except:
            self.config = {"host": "", "database" : "", "user" : "", "passwd" : ""}
        self.connected = False

    def read_db_config(self, filename='config.ini', section='mysql'):
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

    def save_db_config(self, filename='config.ini', section='mysql'):
        f = open(filename, "w")
        f.write("[{%s}]", section)
        for key,val in self.db_config:
            f.write("\n{%s} = {%s}", key, val)
        f.close()
        
    def db_connect(self, entries):
        db_config = {}

        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            db_config[field] = text
            #print('%s: "%s"' % (field, text)) 

        try:
            self.db = CaptureDatabase(db_config)
        except:
            self.connected = False
        else:
            self.connected = True

 #   def load_capture(self, fpath):
 #       self.cap = CaptureDigest(fpath)

#    def insert_capture_from_file(self, fpath="none"):
#        if fpath == "none":
            

    def __exit__(self):
        self.db.__exit__()



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


if __name__ == '__main__':
    root = tk.Tk()
    gui = MudCaptureApplication(root)
    root.mainloop()

