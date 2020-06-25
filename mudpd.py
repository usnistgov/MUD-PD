#!/usr/bin/python3

# Local Modules
# import _mysql_connector

from src.bidict import BiDict
from src.capture_database import CaptureDatabase
# from capture_database import DatabaseHandler
from src.capture_database import CaptureDigest
from src.lookup import lookup_mac, lookup_hostname
from src.generate_mudfile import MUDgeeWrapper
from src.generate_report import ReportGenerator
from src.multicolumn_listbox import MultiColumnListbox

# External Modules
import concurrent
from datetime import datetime
from datetime import timedelta
import hashlib
import math
import multiprocessing
# from multiprocessing import Process, Queue
import mysql.connector
import pyshark
import subprocess
import sys
import time
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
from configparser import ConfigParser

field2db = BiDict({'File': 'fileName', 'Activity': 'activity', 'Notes (optional)': 'details',
                   'Lifecycle Phase': 'lifecyclePhase', 'Setup': 'setup', 'Normal Operation': 'normalOperation',
                   'Removal': 'removal',
                   'Internet': 'internet', 'Human Interaction': 'humanInteraction',
                   'Preferred DNS Enabled': 'preferredDNS', 'Isolated': 'isolated',
                   'Duration-based': 'durationBased', 'Duration': 'duration', 'Action-based': 'actionBased',
                   'Action': 'deviceAction',
                   'Date of Capture': 'capDate', 'Time of Capture': 'capTime',
                   'Manufacturer': 'mfr', 'MAC': 'mac_addr', 'Model': 'model', 'Internal Name': 'internalName',
                   'Category': 'deviceCategory', 'Notes': 'notes',
                   # 'MUD':'mudCapable', 'WiFi':'wifi', 'Bluetooth':'bluetooth', 'Zigbee':'zigbee',
                   'MUD': 'mudCapable', 'WiFi': 'wifi', 'Ethernet': 'ethernet', 'Bluetooth': 'bluetooth',
                   'Zigbee': 'zigbee',
                   'ZWave': 'zwave', '3G': 'G3', '4G': 'G4', '5G': 'G5', 'Other': 'otherProtocols',
                   'Firmware Version': 'fw_ver', 'IP Address': 'ipv4_addr', 'IPv6 Address': 'ipv6_addr'})
dbFields = 'host', 'database', 'user', 'passwd'
dbNewFields = 'host', 'user', 'passwd', 'new database'
APIFields = 'api_key'
# dbField2Var = {'Host' : 'host', 'Database' : 'database', 'Username' : 'user', 'Password' : 'passwd'}
# captureFields = 'File', 'Activity', 'Notes (optional)'
captureFields = 'File', 'Notes (optional)'
lifecyclePhaseFields = 'Setup', 'Normal Operation', 'Removal'
captureEnvFields = 'Internet', 'Human Interaction', 'Preferred DNS Enabled', 'Isolated'
captureTypeFields = 'Duration-based', 'Duration', 'Action-based', 'Action'
# captureField2Var = {'File' : 'fileLoc', 'Activity' : 'activity', 'Details' : 'details'}
captureInfoFields = 'Date of Capture', 'Time of Capture'  # , 'Devices'
# deviceFields = 'Model', 'Internal Name', 'Device Category', 'Communication Standards', 'Notes'
deviceFields = 'Manufacturer', 'Model', 'MAC', 'Internal Name', 'Category', 'Notes', 'Capabilities'
# deviceField2Var = {'Model' : 'model', 'Internal Name' : 'internalName', 'Device Category' : 'deviceCategory', 'Communication Standards', 'Notes': 'notes'}
# deviceOptions = 'WiFi', 'Bluetooth', 'Zigbee', 'ZWave', '4G', '5G', 'Other'
deviceOptions = 'MUD', 'WiFi', 'Ethernet', 'Bluetooth', 'Zigbee', 'ZWave', '3G', '4G', '5G', 'Other'
# deviceOptions2Var = {'WiFi' : 'wifi', 'Bluetooth' : 'bluetooth', 'Zigbee' : 'zigbee', 'ZWave' : 'zwave', '4G' : '4G', '5G' : '5G', 'Other', 'other'}
# deviceStateFields = 'Firmware Version' #maybe include this with device fields entry and note that it will be associated with the capture only


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
        self.parent.title("MUD-PD") #MUDdy Airwaves

        self.window_stack = []
        self.yield_focus(self.parent)

        # Main menu bar
        self.fileMenu = tk.Menu(self.parent)
        self.parent.config(menu=self.fileMenu)
        self.fileSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="File", menu=self.fileSubMenu)
        self.fileSubMenu.add_command(label="Connect to Database...", command=self.popup_connect2database)
        self.fileSubMenu.add_command(label="Create New Database...", command=self.popup_createNewDatabase)
        self.fileSubMenu.add_command(label="Import Capture File...", command=self.popup_import_capture)
        self.fileSubMenu.add_separator()
        self.fileSubMenu.add_command(label="Quit", command=self.__exit__)
        
        self.helpSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="Help", menu=self.helpSubMenu)
        self.helpSubMenu.add_command(label="About", command=self.popup_about)


        #### Main Window ####
        # Menu top
        self.menuFrame = tk.Frame(self.parent, bd=1, bg="#dfdfdf") #, bg="#dfdfdf"

        icon_db_connect = tk.PhotoImage(file="data/icons/database_connect40px.png")
        self.b_main_db_connect = tk.Button(self.menuFrame, compound="top", image=icon_db_connect, width="40", height="40", command=self.popup_connect2database, highlightthickness=0, activebackground="black", bd=0)
        self.b_main_db_connect.image = icon_db_connect
        self.b_main_db_connect.pack(side="left")

        icon_db_new = tk.PhotoImage(file="data/icons/database_new40px.png")
        self.b_main_db_new = tk.Button(self.menuFrame, compound="top", image=icon_db_new, width="40", height="40", command=self.popup_createNewDatabase, highlightthickness=0, activebackground="black", bd=0)
        self.b_main_db_new.image = icon_db_new
        self.b_main_db_new.pack(side="left")

        icon_import = tk.PhotoImage(file="data/icons/import40px.png")
        #self.b_main_import = tk.Button(self.menuFrame, compound="top", image=icon_import, width="40", height="40", command=self.popup_import_capture, highlightthickness=0, activebackground="black", bd=0)
        self.b_main_import = tk.Button(self.menuFrame, compound="top", state='disabled', image=icon_import, width="40", height="40", command=self.popup_import_capture, highlightthickness=0, activebackground="black", bd=0)
        self.b_main_import.image = icon_import
        self.b_main_import.pack(side="left")

        #b_y = tk.Button(self.menuFrame, state="disabled", text="Generate MUD File", highlightbackground="#dfdfdf", wraplength=80)#, anchor=tk.N+tk.W)
        #b_generate_MUD = tk.Button(self.menuFrame, text="Generate MUD File", wraplength=80, command=self.generate_MUD_wizard)#, anchor=tk.N+tk.W)
        #self.b_main_generate_MUD = tk.Button(self.menuFrame, text="Generate MUD File", wraplength=80, command=self.popup_generate_mud_wizard)#, anchor=tk.N+tk.W)
        self.b_main_generate_MUD = tk.Button(self.menuFrame, text="Generate MUD File", state='disabled', wraplength=80, command=self.popup_generate_mud_wizard)#, anchor=tk.N+tk.W)
        #b_generate_MUD = tk.Button(self.menuFrame, state="disabled", text="Generate MUD File", wraplength=80, command=self.generate_MUD_wizard)#, anchor=tk.N+tk.W)
        self.b_main_generate_MUD.pack(side="left")

        self.b_main_generate_report = tk.Button(self.menuFrame, state="disabled", text="Generate Report", wraplength=80, command=self.generate_report_wizard)#, anchor=tk.N+tk.W)
        self.b_main_generate_report.pack(side="left")

        ### Left (capture) frame ###
        self.capFrame = tk.Frame(self.parent, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        # title
        self.cap_title_var=tk.StringVar()
        self.cap_title_var.set("Captures")
        self.cap_title = tk.Label(self.capFrame, textvariable=self.cap_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.cap_title.pack(side="top", fill=tk.X)

        # capture list
        self.cap_header = ["id", "Date", "Capture Name", "Activity", "Duration", "Details", "Capture File Location"]
        #self.cap_header = ["Date","Capture Name","Activity", "Details","Capture File Location"]
        self.cap_list = MultiColumnListbox(self.capFrame, self.cap_header, list(), keep1st=True, exclusionList=["id"])
        #self.cap_list.bind("<<ListboxSelect>>", self.update_dev_list)
        self.cap_list.bind("<<TreeviewSelect>>", self.update_dev_list)
        '''
        self.cap_list.bind("<Double-Button-1>>", (lambda idx=0, hd0=4, hd1=1
                                                  : self.popup_import_capture_devices(
                    CaptureDigest(self.cap_list.get(self.cap_list.selection()[idx])[hd0] + "/" + 
                                  self.cap_list.get(self.cap_list.selection()[idx])[hd1]))))
        '''

        #(lambda d=unknown_dev_list.curselection(): self.popup_import_device(d)))
        self.b_main_inspect = tk.Button(self.capFrame, text="Inspect",
                              #command=(lambda c=CaptureDigest((lambda x=None, idx=0, hd0=4, hd1=1
                              #                                 : self.cap_list.selection(x)[idx].get(self.cap_header[hd0]) +
                              #                                   self.cap_list.selection(x)[idx].get(self.cap_header[hd1])))
                              #         : self.popup_import_capture_devices(c)))
                              command=self.pre_popup_import_capture_devices)
        '''
                              command=(lambda hd0=4, hd1=1 :
                                           self.popup_import_capture_devices(
                    CaptureDigest(
                        self.cap_list.get_selected_row()[hd0] + "/" +
                        self.cap_list.get_selected_row()[hd1]))))
        '''
        self.b_main_inspect.pack(side="right")
        self.b_main_inspect.config(state="disabled")
        self.cap = None


        ### Right Frame ###
        self.rightFrame = tk.Frame(self.parent, width=500, bd=1, bg="#dfdfdf")

        ## Top Right (device) frame ##
        self.devFrame = tk.Frame(self.rightFrame, width=500)#, bd=1, bg="#eeeeee")

        # title
        self.dev_title_var=tk.StringVar()
        self.dev_title_var.set("Devices")
        self.dev_title = tk.Label(self.devFrame, textvariable=self.dev_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.dev_title.pack(fill=tk.X)


        # device list
        self.dev_header = ["id", "Manufacturer", "Model", "Internal Name", "MAC", "Category"]
        self.dev_list = MultiColumnListbox(self.devFrame, self.dev_header, list(), keep1st=True, exclusionList=["id"])
        #self.dev_list.bind("<<ListboxSelect>>", self.update_comm_list)
        self.dev_list.bind("<<TreeviewSelect>>", self.update_comm_list)

        self.devFrame.pack(side="top", fill="both", expand=True)


        ## Bottom Right (communication) frame ##
        self.commFrame = tk.Frame(self.rightFrame, width=500, bd=1, bg="#eeeeee")

        # title
        self.comm_title_var=tk.StringVar()
        self.comm_title_var.set("Communication")
        self.comm_title = tk.Label(self.commFrame, textvariable=self.comm_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.comm_title.pack(fill=tk.X)

        # scrollbar
        '''
        self.comm_scrollbar = tk.Scrollbar(self.commFrame)
        self.comm_scrollbar.pack(side="right", fill="both")
        '''

        # communication list
        self.comm_header = ["id", "fileID", "Time", "MAC", "IPver", "Source", "Destination", "E/W",
                            "Protocol", "Transport Protocol", "Source Port",
                            #"Destination Port", "Length", "Direction", "Raw"] #Direction being NS or EW
                            #"Destination Port", "Length", "Raw"] #Direction being NS or EW
                            "Destination Port", "Length"] #Direction being NS or EW
        self.comm_list = MultiColumnListbox(self.commFrame, self.comm_header, list(), exclusionList=["id", "fileID"])#, keep1st=True)
        #self.comm_list.bind("<<ListboxSelect>>", self.update_comm_list)

        '''
        self.comm_list = tk.Listbox(self.commFrame, yscrollcommand = self.comm_scrollbar.set, selectmode="extended", exportselection=0, bd=0)

        self.comm_list.pack(side="left", fill="both", expand=True)
        self.comm_scrollbar.config( command = self.comm_list.yview )
        '''

        #:LKJ To be added once packets have been added to the table
        self.comm_state = "any"
        self.b_ns = tk.Button(self.commFrame, text="N/S", command=(lambda s="ns" : self.modify_comm_state(s)))
        self.b_ew = tk.Button(self.commFrame, text="E/W", command=(lambda s="ew" : self.modify_comm_state(s)))

        self.comm_dev_restriction = "none"
        self.b_between = tk.Button(self.commFrame, text="Between", command=(lambda r="between" : self.modify_comm_dev_restriction(r)))
        self.b_either = tk.Button(self.commFrame, text="Either", command=(lambda r="either" : self.modify_comm_dev_restriction(r)))

        self.b_pkt10    = tk.Button(self.commFrame, text="10",    command=(lambda n=10    : self.modify_comm_num_pkts(n)))
        self.b_pkt100   = tk.Button(self.commFrame, text="100",   command=(lambda n=100   : self.modify_comm_num_pkts(n)))
        self.b_pkt1000  = tk.Button(self.commFrame, text="1000",  command=(lambda n=1000  : self.modify_comm_num_pkts(n)))
        self.b_pkt10000 = tk.Button(self.commFrame, text="10000", command=(lambda n=10000 : self.modify_comm_num_pkts(n)))
        #self.b_internal = tk.Button(self.commFrame, text="Subnets", command=self.popup_internal_addr_list)

        self.b_ns.pack(side="left")
        self.b_ew.pack(side="left")
        self.b_between.pack(side="left")
        self.b_either.pack(side="left")

        self.b_pkt10000.pack(side="right")
        self.b_pkt1000.pack(side="right")
        self.b_pkt100.pack(side="right")
        self.b_pkt10.pack(side="right")

        self.comm_list_num_pkts = 100
        #self.b_pkt100.config(state='disabled')


        self.b_ns.config(state='disabled')
        self.b_ew.config(state='disabled')
        self.b_between.config(state='disabled')
        self.b_either.config(state='disabled')
        self.b_pkt10.config(state='disabled')
        self.b_pkt100.config(state='disabled')
        self.b_pkt1000.config(state='disabled')
        self.b_pkt10000.config(state='disabled')


        self.comm_list_all_pkts = []

        #self.b_internal.pack(side="right")

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
            self.window_stack[-1].focus_set()
            self.window_stack[-1].grab_set()
            if self.window_stack[-1] != self.parent:
                self.window_stack[-1].transient(self.parent)
            self.window_stack[-1].lift()
            self.window_stack[-1].attributes('-topmost',True)
            self.window_stack[-1].attributes('-topmost',False)
        elif self.window_stack[-1] != window:
            # Previously top window yield status
            self.window_stack[-1].attributes('-topmost',False)
            #self.window_stack[-1].focus_release()
            self.window_stack[-1].grab_release()

            # Push new window to the top of the stack
            self.window_stack.append(window)
            self.yield_focus()

            # Wait for window to close before yielding focus to next in stack
            self.window_stack[-2].wait_window(self.window_stack[-1])
            #self.window_stack[-1].focus_release()
            self.window_stack[-1].grab_release()
            self.window_stack.pop()
            self.yield_focus()
        #else:
            # Remove the current top window from the stack and destroy
            '''
            self.window_stack[-1].attributes('-topmost',False)
            w = self.window_stack.pop()
            w.destroy()
            self.yield_focus()
            '''
        #    self.window_stack[-1].destroy()



    def popup_connect2database(self):
        self.w_db = tk.Toplevel()
        self.w_db.wm_title("Connect to Database")

        ents = self.make_form_database(dbFields)

        self.bind('<Return>', (lambda event, e=ents: self.connect_and_close(e)))   

        b_connect = tk.Button(self.w_db, text='Connect',
                                   command=(lambda e=ents: self.connect_and_close(e)))
        b_cancel = tk.Button(self.w_db, text='Cancel', command=self.w_db.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_connect.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        # Save checkbutton
        checkvar = tk.IntVar()
        ckb_save = tk.Checkbutton(self.w_db, text="Save", width=7, justify=tk.LEFT, variable=checkvar)
        ckb_save.pack(side=tk.LEFT, anchor=tk.W, padx=5)
        ents.append(("Save", checkvar))

        self.yield_focus(self.w_db)


    def make_form_database(self, fields):
        db_handler_temp = DatabaseHandler()
        entries = []

        for field in fields:
            row = tk.Frame(self.w_db)
            lab = tk.Label(row, width=12, text=field, anchor='w')
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

    def popup_createNewDatabase(self):
        self.w_db_new = tk.Toplevel()
        self.w_db_new.wm_title("Create New Database")

        ents = self.make_form_new_database(dbNewFields)

        self.bind('<Return>', (lambda event, e=ents, c=True: self.connect_and_close(e, create=c)))   

        b_create = tk.Button(self.w_db_new, text='Create',
                                   command=(lambda e=ents, c=True: self.connect_and_close(e, create=c)))
        b_cancel = tk.Button(self.w_db_new, text='Cancel', command=self.w_db_new.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_create.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_create.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        # Save checkbutton
        checkvar = tk.IntVar()
        ckb_save = tk.Checkbutton(self.w_db_new, text="Save", width=7, justify=tk.LEFT, variable=checkvar)
        ckb_save.pack(side=tk.LEFT, anchor=tk.W, padx=5)
        ents.append(("Save", checkvar))

        messagebox.showinfo("CREATING a New Database",
                            "You are CREATING a new database.\n\nYou will need to use the existing mysql server password.")

        self.yield_focus(self.w_db_new)


    def make_form_new_database(self, fields):
        db_handler_temp = DatabaseHandler()
        entries = []

        for field in fields:
            row = tk.Frame(self.w_db_new)
            lab = tk.Label(row, width=12, text=field, anchor='w')
            if field == "passwd":
                ent = tk.Entry(row, show="\u2022", width=15)
                skip_line = True
            else:
                ent = tk.Entry(row)
                skip_line = False
            ent.insert( 10, db_handler_temp.config.get(field,"none") )

            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            lab.pack(side=tk.LEFT)
            ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
            entries.append((field, ent))

            if skip_line:
                xtra_row = tk.Frame(self.w_db_new)
                xtra_lab = tk.Label(xtra_row, width=12, text=' ', anchor='w')
                xtra_row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
                xtra_lab.pack(side=tk.LEFT)
                skip_line = False

        return entries

    def connect_and_close(self, entries, create=False):
        db_handler_temp = DatabaseHandler()
        (save_name, save_var) = entries.pop()
        save_val = save_var.get()
        #print(save_name, " = ", save_var, " = ", save_val)

        if create:
            (db_label, db_name) = entries.pop()
            db_name = db_name.get()
            db_handler_temp.db_connect(entries)

            if not db_handler_temp.connected:
                tk.messagebox.showerror("Error Connecting to Database",
                                        "There was some error while connecting to the database.\n" +
                                        "Please check all the data fields and try again.")
                return
                    
            try:
                db_handler_temp.db.init_new_database(db_name)
            except mysql.connector.Error as err:
                if err.errno == mysql.connector.errorcode.ER_DB_CREATE_EXISTS: # 1007
                    print("Database already exists")

                    reinit = tk.messagebox.askyesno("Database Creation Error",
                                                    "Cannot create database '%s' because it already exists.\n\n" % db_name +
                                                    "Re-initialize the existing database?",
                                                    default='no')
                    
                    if reinit:
                        confirm = tk.messagebox.askyesno("Overwrite Existing Database",
                                                         "Are you sure you want to overwrite the database '%s'?\n\n" % db_name +
                                                         "This action is IRREVERSIBLE and all existing data will be LOST!",
                                                         default='no')
                        if confirm:
                            db_handler_temp.db.reinit_database(db_name);
                        else:
                            tk.messagebox.showinfo("Create New Database Name",
                                                   "Please choose a new database name")
                            return
                    else:
                        tk.messagebox.showinfo("Create New Database Name",
                                               "Please choose a new database name")
                        return
                else:
                    tk.messagebox.showerror("Error Creating Database",
                                            "There was some error in creating the database.\n" +
                                            "Please try again using a different name")
                    return

            db_handler_temp.db_config['database'] = db_name
            #entries.append(('database', db_name))
        else:
            db_handler_temp.db_connect(entries)
        #db_handler_temp.db_connect(entries)

        if db_handler_temp.connected:
            self.db_handler = db_handler_temp
            #self.status_var.set("Connected to " + self.db_handler.config.get("database", "none"))
            self.status_var.set("Connected to " + self.db_handler.db_config.get("database", "none"))
            self.populate_capture_list()
            if save_val:
                self.popup_confirm_save()

            if create:
                #messagebox.showinfo("Success!","Successfully created and connected to the new database '%s'" % db_name)
                self.w_db_new.destroy()
            else:
                #messagebox.showinfo("Success!","Successfully connected to the database")
                self.w_db.destroy()


            #Enable main menu buttons
            self.b_main_import.config(state='normal')
            self.b_main_generate_MUD.config(state='normal')
            self.b_main_generate_report.config(state='normal')
            self.b_main_inspect.config(state="disabled")
            self.b_ns.config(state='normal')
            self.b_ew.config(state='normal')
            self.b_between.config(state='normal')
            self.b_either.config(state='normal')
            self.b_pkt10.config(state='normal')
            self.b_pkt100.config(state='disabled')
            self.b_pkt1000.config(state='normal')
            self.b_pkt10000.config(state='normal')



        else:
            tk.messagebox.showerror("Error", "Problem connecting to database")
            entries.append((save_name, save_var))
            '''
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Problem connecting to database")
            '''

    def popup_confirm_save(self):
        confirm = tk.messagebox.askyesno("MUD-PD: MUD Profiling Database",
                                         "Are you sure you want to save this configuration?\n\n" +
                                         "Any existing configuration will be OVERWRITTEN.",
                                         default='no')
        save_pwd = tk.messagebox.askyesno("WARNING",
                                          "Password will be saved in plaintext.\n\nSave password anyway?",
                                          default='no')
        #print(confirm)
        if confirm:
            self.db_handler.save_db_config(save_pwd=save_pwd)
        return

    def popup_import_capture(self):
        self.w_cap = tk.Toplevel()
        self.w_cap.wm_title("Import Packet Capture")


        #self.ents = self.make_form_capture(captureFields)
        self.ents = self.make_form_capture(captureFields, lifecyclePhaseFields, captureEnvFields, captureTypeFields)

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


    '''
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
    '''

    def make_form_capture(self, generalFields, phaseFields, envFields, typeFields):
        entries = []
        #entries = {}
        for i, field in enumerate(generalFields):
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

        # Device Phase (Setup, Normal Operation, Removal)
        # lifecyclePhaseFields = 'Setup', 'Normal Operation', 'Removal'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=15, text="Lifecycle Phase", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)

        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_phz = tk.IntVar(None,1)
        for i, field in enumerate(phaseFields):
            b_phz = tk.Radiobutton(row, text=field, variable=v_phz, value=i)
            b_phz.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)

        entries.append((lab, v_phz))


        # Environment Variables (Internet, Human Interaction, Preferred DNS Enabled, Isolated
        # captureEnvFields = 'Internet', 'Human Interaction', 'Preferred DNS Enabled','Isolated'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=20, text="Environmental Variables", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)
        for i, field in enumerate(envFields):
            if i % 2 == 0:
                row = tk.Frame(self.w_cap)
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                v_env = tk.IntVar(None, 1)
            else:
                v_env = tk.IntVar()

            #v_env = tk.IntVar()
            b_env = tk.Checkbutton(row, text=field, variable=v_env)
            b_env.pack(side=tk.LEFT, padx=20, anchor=tk.W)

            entries.append((field, v_env))
            #entries.append((b_env, v_env))


        # Capture Type (Duration-based, Duration, Action-based, Action)
        # captureTypeFields = 'Duration-based', 'Duration', 'Action-based', 'Action'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=15, text="Capture Type", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)


        def activateCheckDur():
            if v_dur.get() == 1:          #whenever checked
                e_dur.config(state='normal')
            elif v_dur.get() == 0:        #whenever unchecked
                e_dur.config(state='disabled')

        i = 0
        # Duration-based
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_dur = tk.IntVar()
        b_dur = tk.Checkbutton(row, text=typeFields[i], variable=v_dur, command=activateCheckDur)
        b_dur.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)
        entries.append((typeFields[i], v_dur))
        
        # Duration
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab = tk.Label(row, padx=5, width=9, text=typeFields[i], anchor='w')
        lab.pack(side=tk.LEFT)
        e_dur = tk.Entry(row)
        e_dur.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        e_dur.config(state='disabled')
        entries.append((typeFields[i], e_dur))


        def activateCheckAct():
            if v_act.get() == 1:          #whenever checked
                e_act.config(state='normal')
            elif v_act.get() == 0:        #whenever unchecked
                e_act.config(state='disabled')

        # Action-based
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_act = tk.IntVar()
        b_act = tk.Checkbutton(row, text=typeFields[i], variable=v_act, command=activateCheckAct)
        b_act.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)
        entries.append((typeFields[i], v_act))

        # Action
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab = tk.Label(row, padx=5, width=9, text=typeFields[i], anchor='w')
        lab.pack(side=tk.LEFT)
        e_act = tk.Entry(row)
        e_act.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        e_act.config(state='disabled')
        entries.append((typeFields[i], e_act))

        '''
        for i, field in typeFields:
            row = tk.Frame(self.w_cap)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            if i % 2 == 0:
                typ = tk.intVar()
                b_typ = tk.Checkbutton(row, text=field, variable=typ, command=activateCheck)
                b_typ.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)
                entries.append((field, typ))
            else:
                lab = tk.Label(row, width=15, text=field, anchor='w')
                lab.pack(side=tk.LEFT)
                ent = tk.Entry(row)
                typ.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
                entries.append((field, ent))
        '''
        return entries

    def import_with_progbar(self, cap=None):
        # tk.Tk().withdraw()
        self.w_import_progress = tk.Toplevel()
        self.w_import_progress.wm_title("Capture Import")
        self.w_import_progress.geometry("200x50")
        if cap != None:
            self.cap = cap
        # self.cap = cap

        tk.Label(self.w_import_progress, text="Import progress", width=20).grid(row=0, column=0)

        progress_var = tk.IntVar()
        progress_bar = ttk.Progressbar(self.w_import_progress, variable=progress_var, maximum=self.cap.fsize)
        progress_bar.grid(row=1, column=0)
        # self.w_import_progress.pack_()

        progress_var.set(self.cap.progress)
        self.w_import_progress.update()

        # start = datetime.now()
        def update_progress():
            for i, pkt in enumerate(self.cap.cap):
                if i % 4095 == 0:
                    progress_var.set(self.cap.progress)
                    self.w_import_progress.update()
                self.cap.append_pkt(pkt)

            progress_var.set(self.cap.progress)
            self.w_import_progress.update()
            self.w_import_progress.destroy()

            self.cap.id_unique_addrs()

        def try_multiple_operations(pkt):
            try:
                self.cap.append_pkt(pkt)
            except:
                print("error with item")

        def digest_segment(file, results, status, proc):
            print(file, results, status, proc)
            cap = pyshark.FileCapture(file)
            for pkt in cap:
                results[proc].append(pkt)
                #status += 1

            print("number of packets", len(results[proc]))
            '''
            if proc:
                for pkt in pyshark.FileCapture(file):
                    results.append(pkt)
                    status += 1
            else:
                for i, pkt in enumerate(pyshark.FileCapture(file)):
                    results.append(pkt)
                    status += 1
                    if i % 1024 == 0:
                        progress_var.set(sum(self.stat))
                        self.w_import_progress.update()
                        
                progress_var.set(sum(self.stat))
                self.w_import_progress.update()
                self.w_import_progress.destroy()
            ''' 

        #executor = concurrent.futures.ProcessPoolExecutor(10)
        #futures = [executor.submit(try_multiple_operations, group) for group in grouper(5, self.cap.cap)]
        #self.w_import_progress.after(0, futures = [executor.submit(try_multiple_operations, pkt) for pkt in self.cap.cap])
        #self.w_import_progress.after(0, concurrent.futures.wait(futures))

        #num_pkts = int(cln.sub('', str(subprocess.check_output("capinfos -c " + fname, stderr=subprocess.STDOUT, shell=True).split()[-1])))
        start = datetime.now()

        try:
            #num_pkts = subprocess.check_output("capinfos -c -M " + self.cap.fpath, stderr=subprocess.STDOUT, shell=True).decode('ascii').split()[-1].replace(',', '')
            #num_pkts = int(subprocess.check_output("capinfos -c -M " + self.cap.fpath, stderr=subprocess.STDOUT, shell=True).decode('ascii').split()[-1])
            num_pkts = int(subprocess.check_output("capinfos -c -M " + self.cap.fpath, stderr=subprocess.PIPE, shell=True).decode('ascii').split()[-1])
        except Exception as e:
            output = e.output
            print(str(output))
            num_pkts = int(output.decode('ascii').split()[-1])

        print("num_pkts", num_pkts)
        num_threads = multiprocessing.cpu_count()
        num_threads = 2
        temp = "./.temp/"
        #;lkj
        # Packets per process
        ppp = math.ceil(num_pkts / num_threads)
        print("packets per process =", ppp)
        #subprocess.call("rm -f ./.temp/*", stderr=subprocess.STDOUT, shell=True))
        #subprocess.call(["rm", temp+"*"], stderr=subprocess.STDOUT, shell=True)
        subprocess.call("rm " + temp+"*", stderr=subprocess.PIPE, shell=True)
        
        #subprocess.call(["editcap", "-c", str(ppp), fname, " ./.temp/split.pcap"], stderr=subprocess.STDOUT, shell=True) 
        #subprocess.call(["editcap", "-c", str(ppp), self.cap.fpath, temp+"split.pcap"], stderr=subprocess.STDOUT, shell=True) 
        subprocess.call(["editcap", "-c", str(ppp), self.cap.fpath, temp+"split.pcap"], stderr=subprocess.PIPE, shell=True) 

        files = subprocess.check_output(["ls", temp]).decode('ascii').split()
        jobs = []
        self.res = [[]]*num_threads
        self.stat = [0]*num_threads

        for i, f in enumerate(files):
            proc = multiprocessing.Process(target=digest_segment, args=(temp+f, self.res, self.stat[i], i))
            jobs.append(proc)

        for j in jobs:
            #j.start()
            self.w_import_progress.after(0, j.start)

        for i,j in enumerate(jobs):
            j.join()
            print("job", i, "complete")
            print(len(self.res[i]))

        #self.w_import_progress.after(0, update_progress)

        self.cap.pkt = [y for x in self.res for y in x]

        stop = datetime.now()
        print("time to process = ", (stop-start).total_seconds())

        print("number of packets = ", len(self.cap.pkt))
        #self.w_import_progress.after(10, self.cap.import_pkts())

        self.yield_focus(self.w_import_progress)
        #print("yielded focus")

        '''
        #while self.cap.progress < self.cap.fsize:
        for pkt in self.cap.cap:
            progress_var.set(self.cap.progress)
            self.w_import_progress.update()
            self.cap.append_pkt(pkt)
            #time.sleep(5)
        #p.join()
        '''
        #stop = datetime.now()
        #print("time to import = ", (stop-start).total_seconds())
        #return
        #self.w_import_progress.destroy()

    def import_and_close(self, entries):

        #Check if capture is already in database (using sha256)
        filehash = hashlib.sha256(open(entries[0][1].get(),'rb').read()).hexdigest()
        self.db_handler.db.select_unique_captures()

        captures = self.db_handler.db.cursor.fetchall()
        #print(type(captures))
        #print(captures)

        #if any(filehash in hash for hash in self.db_handler.db.cursor):
        if any(filehash in hash for hash in captures):
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Capture file already imported into database")
        else:
            #tk.Tk().withdraw()
            #self.cap = CaptureDigest(entries[0][1].get())
            #self.import_progress()
            #self.cap.import_pkts()

            self.cap = CaptureDigest(entries[0][1].get())
            #:LKJ
            '''
            if self.cap.fsize > 512000:
                self.import_with_progbar()
            else:
                self.import_with_progbar()
            '''
                #self.cap.import_pkts()
            #:LKJ
            # TODO: Make sure MP functions before permanent removal
            # self.cap.import_pkts()

            #self.import_with_progbar(CaptureDigest(entries[0][1].get()))
            
            print("finished importing")
            #messagebox.showinfo("Importing", "Please wait for the capture file to be processed")

            data_capture = {
                "fileName" : self.cap.fname,
                "fileLoc" : self.cap.fdir,
                "fileHash" : self.cap.fileHash,
                #;lkj;lkj
                "capDate" : epoch2datetime(float(self.cap.capTimeStamp)),#epoch2datetime(float(self.cap.capDate)),
                #"duration" : self.cap.capDuration.seconds,
                "capDuration" : self.cap.capDuration,
                #"activity" : entries[1][1].get(),
                #"details" : entries[2][1].get()
                "details" : entries[1][1].get(),
                field2db[ entries[2][0].cget('text') ] : field2db[ lifecyclePhaseFields[ entries[2][1].get() ] ]
                #"Internet" : entries[3][1].get(),
                #"Human Interaction" : entries[4][1].get(),
                #"Preferred DNS Enabled" : entries[5][1].get(),
                #"Isolated" : entries[6][1].get(),
                #"Duration-based" : entries[7][1].get(),
                #"Duration" : entries[8][1].get(),
                #"Action-based" : entries[9][1].get(),
                #"Action" : entries[10][1].get()
                }

            for i in range(3,11):
                data_capture[ field2db[ entries[i][0] ] ] = entries[i][1].get()
                print(i, entries[i][1].get())

            print('data_capture:', data_capture)

            print("(A) inserting capture file into database")
            self.db_handler.db.insert_capture(data_capture)
            self.db_handler.db.select_last_insert_id()
            temp_fileID = self.db_handler.db.cursor.fetchone()
            self.cap.id = temp_fileID[0]



            #Potentially threadable code

            # Popup window
            #self.yield_focus(self.w_cap)
            #print("(A) popup_import_capture_devices")
            print("(B) popup_import_capture_devices")
            self.popup_import_capture_devices(self.cap)

            #print("(B) db_handler.db.insert_capture")

            ##self.db_handler.db.insert_capture(data_capture)

            ##self.db_handler.db.select_capID_where_capName(self.cap.fname)
            ##self.cap.id = self.db_handler.db.cursor

            print("(C) populate_capture_list")
            self.populate_capture_list()

            print("(D) import_packets")
            self.import_packets(self.cap)

            print("(E) destroying import capture window")
            self.w_cap.destroy()


    def pre_popup_import_capture_devices(self):
        #sel_cap_path = self.cap_list.get_selected_row()[5] + "/" + self.cap_list.get_selected_row()[2]
        sel_cap_path = self.cap_list.get_selected_row()[6] + "/" + self.cap_list.get_selected_row()[2]

        start = datetime.now()

        if self.cap == None or (self.cap.fdir + "/" + self.cap.fname) != sel_cap_path:
            #self.popup_import_capture_devices( CaptureDigest(sel_cap_path, gui=True) )
            #start = datetime.now()
            self.cap = CaptureDigest(sel_cap_path)

            self.cap.id = self.cap_list.get_selected_row()[0]
            #populate as much data from the database as possible


            #:LKJ
            '''
            if self.cap.fsize > 512000:
                self.import_with_progbar()
            else:
                self.import_with_progbar()
                #self.cap.import_pkts()
            '''
            #:LKJ
            self.cap.import_pkts()

            #self.import_with_progbar( CaptureDigest(sel_cap_path) )
            stop = datetime.now()
            print("time to import = ", (stop-start).total_seconds())
            #self.popup_import_capture_devices( cap=self.cap )
            self.popup_import_capture_devices()
            #self.popup_import_capture_devices( CaptureDigest(sel_cap_path) )
        else:
            self.popup_import_capture_devices()

            #self.import_with_progbar( CaptureDigest(sel_cap_path) )
            stop = datetime.now()
            print("time to import = ", (stop-start).total_seconds())
            '''
            #self.popup_import_capture_devices( cap=self.cap )
            self.popup_import_capture_devices()
            #self.popup_import_capture_devices( CaptureDigest(sel_cap_path) )
        else:
            self.popup_import_capture_devices()
            '''

    #def popup_import_capture_devices(self, cap):
    def popup_import_capture_devices(self, cap=None):
        self.w_cap_dev = tk.Toplevel()

        if cap == None:
            if self.cap == None:# or self.cap != cap:
                print("Error: If no previous capture imported, a capture file must be provided.")
        elif self.cap == None:
            self.cap = cap

        self.w_cap_dev.wm_title(self.cap.fname)

        self.topDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        ents = self.make_form_capture_devices(captureInfoFields, self.cap.capDate, self.cap.capTime)

        self.botDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        ## Left (Unidentified) Dev Frame
        #self.unidentifiedDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")
        self.unlabeledDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.unlabeled_title_var=tk.StringVar()
        self.unlabeled_title_var.set("Unlabeled")
        #self.unidentified_title_var=tk.StringVar()
        #self.unidentified_title_var.set("Unlabeled")
        #self.unidentified_title = tk.Label(self.unidentifiedDevFrame, textvariable=self.unidentified_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.unlabeled_title = tk.Label(self.unlabeledDevFrame, textvariable=self.unlabeled_title_var, bg="#eeeeee", bd=1, relief="flat")
        #self.unidentified_title.pack(side="top", fill=tk.X)
        self.unlabeled_title.pack(side="top", fill=tk.X)

        #self.unidentified_dev_header = ["id","Manufacturer", "MAC", "IPv4", "IPv6"]
        self.unlabeled_dev_header = ["id","Manufacturer", "MAC", "IPv4", "IPv6"]
        #self.unidentified_dev_list = MultiColumnListbox(parent=self.unidentifiedDevFrame,
        self.unlabeled_dev_list = MultiColumnListbox(parent=self.unlabeledDevFrame,
                                                   #header=self.unidentified_dev_header,
                                                   header=self.unlabeled_dev_header,
                                                   list=list(), selectmode="browse",
                                                   exclusionList=["id"])
        #self.unidentified_dev_list.bind("<<TreeviewSelect>>", self.update_unidentified_list_selection)
        self.unlabeled_dev_list.bind("<<TreeviewSelect>>", self.update_unlabeled_list_selection)

        ## Right (Identified) Dev Frame
        #self.identifiedDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")
        self.labeledDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.labeled_title_var=tk.StringVar()
        self.labeled_title_var.set("Labeled")
        #self.identified_title = tk.Label(self.identifiedDevFrame, textvariable=self.identified_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.labeled_title = tk.Label(self.labeledDevFrame, textvariable=self.labeled_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.labeled_title.pack(side="top", fill=tk.X)

        self.labeled_dev_header = ["id", "Manufacturer", "Model", "Internal Name", "Category", "MAC", "IPv4", "IPv6"]
        #self.identified_dev_list = MultiColumnListbox(parent=self.identifiedDevFrame,
        #self.identified_dev_list = MultiColumnListbox(parent=self.labeledDevFrame,
        self.labeled_dev_list = MultiColumnListbox(parent=self.labeledDevFrame,
                                                 header=self.labeled_dev_header,
                                                 list=list(), selectmode="browse",
                                                 exclusionList=["id"])
        #self.identified_dev_list.bind("<<TreeviewSelect>>", self.update_identified_list_selection)
        self.labeled_dev_list.bind("<<TreeviewSelect>>", self.update_identified_list_selection)


        # Grid placements #
        self.topDevFrame.grid(row=0, column=0, sticky="new")
        self.botDevFrame.grid(row=1, column=0, sticky="nsew")
        self.cap_dev_title.grid(row=0, column=0, columnspan=2, sticky="new")
        #self.unidentifiedDevFrame.grid(row=1, column=0, sticky="nsew")
        self.unlabeledDevFrame.grid(row=1, column=0, sticky="nsew")
        #self.identifiedDevFrame.grid(row=1, column=1, sticky="nsew")
        self.labeledDevFrame.grid(row=1, column=1, sticky="nsew")

        # Grid configuration #
        self.botDevFrame.grid_rowconfigure(1, weight=1)
        self.botDevFrame.grid_columnconfigure(0, weight=1)
        self.botDevFrame.grid_columnconfigure(1, weight=1)

        self.w_cap_dev.grid_rowconfigure(1, weight=1)
        self.w_cap_dev.grid_columnconfigure(0, weight=1)

        '''
        # Select first element of each list
        # Try because the list might be empty
        self.unidentified_dev_list.focus(0)
        self.unidentified_dev_list.selection_set(0)
        self.identified_dev_list.focus(0)
        self.identified_dev_list.selection_set(0)

        try:
            self.unidentified_dev_list.focus(0)
            self.unidentified_dev_list.selection_set(0)
        except:
            pass

        try:
            self.identified_dev_list.focus(0)
            self.identified_dev_list.selection_set(0)
        except:
            pass
        '''

        # Buttons #
        #self.b_cap_dev_close = tk.Button(self.unidentifiedDevFrame, text='Close', command=(lambda c=self.cap.fname : self.close_w_cap_dev(c)))
        #self.b_cap_dev_close = tk.Button(self.unidentifiedDevFrame, text='Close', command=(lambda c=self.cap.id : self.close_w_cap_dev(c)))
        self.b_cap_dev_close = tk.Button(self.unlabeledDevFrame, text='Close', command=(lambda c=self.cap.id : self.close_w_cap_dev(c)))
        #self.b_cap_dev_import = tk.Button(self.unidentifiedDevFrame, text='Import Device', state='disabled',
        self.b_cap_dev_import = tk.Button(self.unlabeledDevFrame, text='Import Device', state='disabled',
                             command=(lambda f={'fileName':self.cap.fname,'fileHash':self.cap.fileHash}:
                                          self.popup_import_device(f)))
                                  #command=(lambda e=0, d={'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                  #                        'mac_addr':self.unidentified_dev_list.get_selected_row()[1]}:
                                  #             self.popup_import_device(self.unidentified_dev_list.get_selected_row()[e],d)))
                             
        #self.b_cap_dev_modify = tk.Button(self.identifiedDevFrame, text='Modify State', state='disabled',
        self.b_cap_dev_modify = tk.Button(self.labeledDevFrame, text='Modify State', state='disabled',
                             #command=(lambda d=self.identified_dev_list.selection(): self.prep_popup_update_device_state(d)))
                             #command=(lambda d=self.identified_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))
                             command=(lambda d=self.labeled_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))

        self.b_cap_dev_close.pack(side=tk.LEFT, padx=5, pady=5)
        self.b_cap_dev_import.pack(side=tk.RIGHT, padx=5, pady=5)
        self.b_cap_dev_modify.pack(side=tk.RIGHT, padx=5, pady=5)

        # Update unidentified, identified lists and try to select the first element
        #self.refresh_unidentified_identified_lists()
        self.refresh_unlabeled_labeled_lists()
        # Select first element of each list
        # Try becuase the list might be empty
        #self.unidentified_dev_list.focus(0)
        #self.unidentified_dev_list.selection_set(0)
        self.unlabeled_dev_list.focus(0)
        self.unlabeled_dev_list.selection_set(0)
        #self.identified_dev_list.focus(0)
        #self.identified_dev_list.selection_set(0)
        self.labeled_dev_list.focus(0)
        self.labeled_dev_list.selection_set(0)

        self.yield_focus(self.w_cap_dev)

    #def update_unidentified_list_selection(self, event):
    def update_unlabeled_list_selection(self, event):
        #self.unidentified_dev_list_sel = self.unidentified_dev_list.get( self.unidentified_dev_list.selection() )
        #print("self.unidentified_dev_list_sel = ", self.unidentified_dev_list_sel)
        self.unlabeled_dev_list_sel = self.unlabeled_dev_list.get( self.unlabeled_dev_list.selection() )
        print("self.unlabeled_dev_list_sel = ", self.unlabeled_dev_list_sel)

    def update_identified_list_selection(self, event):
        #self.identified_dev_list_sel = self.identified_dev_list.get( self.identified_dev_list.selection() )
        #print("self.identified_dev_list_sel = ", self.identified_dev_list_sel)
        self.labeled_dev_list_sel = self.labeled_dev_list.get( self.labeled_dev_list.selection() )
        print("self.labeled_dev_list_sel = ", self.labeled_dev_list_sel)

    def prep_popup_update_device_state(self, d):
        # Need to update d in call to "prep_popup_update_device_state"
        #d = self.identified_dev_list_sel
        d = self.labeled_dev_list_sel
        print("d = ",d)
        #mac = d[4]
        mac = d[5]
        deviceID = d[0]
        #self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
        self.db_handler.db.select_most_recent_fw_ver({'deviceID' : deviceID,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        print(self.cap.capTimeStamp)
        temp = self.db_handler.db.cursor.fetchone()
        print("temp: ", temp)

        if temp == None:
            fw_ver = ''
        else:
            fw_ver = temp[0]

        #device_state_data = {'fileHash'     : self.cap.fileHash,
        device_state_data = {'fileID'     : self.cap.id, #self.cap.fileID,
                             'mac_addr'     : mac.upper(),
                             'deviceID'     : deviceID,
                             #need to comment out the next line
                             'internalName' : d[2],
                             'fw_ver'       : fw_ver,
                             #'ipv4_addr'    : self.cap.findIP(mac),
                             #'ipv6_addr'    : self.cap.findIP(mac, v6=True)}
                             #'ipv4_addr': d[5],
                             #'ipv6_addr': d[6]}
                             'ipv4_addr': d[6],
                             'ipv6_addr': d[7]}

        print("ipv4:",device_state_data['ipv4_addr'])
        print("ipv6:",device_state_data['ipv6_addr'])
        
        self.popup_update_device_state(device_state_data)

    #def close_w_cap_dev(self, capName):
    def close_w_cap_dev(self, cap_id):

        #Check if any of the devices seen have been added to the device_state table already and add if not
        #for dev in self.identified

        #self.populate_device_list(capture = capName)
        self.populate_device_list(captureIDs = [cap_id])
        #self.populate_device_list(capture = capName)
        self.w_cap_dev.destroy()


    #def refresh_unidentified_identified_lists(self):
    def refresh_unlabeled_labeled_lists(self):
        # Clear lists
        #self.unlabeled_dev_list.clear()
        #self.labeled_dev_list.clear()

        # Sort devices from Capture into either labeled or unlabeled device lists
        self.db_handler.db.select_device_macs()
        macsInDevTbl = self.db_handler.db.cursor.fetchall() #may be a good idea to make a class variable so queries don't have to be repeated
        #self.db_handler.db.select_labeled_devices_from_cap(self.cap.fileHash)

        #self.db_handler.db.select_labeled_devices_from_cap(self.cap.id)
        #devFromCapTbl = self.db_handler.db.cursor.fetchall()

        print("num uniqueMacs:", len(self.cap.uniqueMAC))

        ## Sort devices found in the capture file into two lists: labeled, and unlabeled
        # Check if the devices in the capture file have been sorted yet
        if self.cap.newDevicesImported is not True:
            #self.unlabeled_dev_list.clear()
            #self.labeled_dev_list.clear()

            importedDevices = []

            # Loop through the uniqueMAC addresses found in the capture file
            for mac in self.cap.uniqueMAC:
                print("mac", mac)

                # Check for a matching MAC address in the "Device" table
                match = [(deviceID, mac_addr, unlabeled) for deviceID, mac_addr, unlabeled in macsInDevTbl if mac==mac_addr]
                if (not match) or match[0][2]:

                    # Check if an entry for the prefix exists in the mac_to_mfr table
                    self.db_handler.db.select_mac_to_mfr()
                    mac2mfr = self.db_handler.db.cursor.fetchall()
                    #mac_prefix = mac.upper()[0:8]
                    mac_prefix = mac[0:8]
                    # Need to address this statement
                    #mfr_match = [(mac2mfrID, x, mfr) for mac2mfrID, x, mfr in mac2mfr if mac_prefix==x]
                    mfr_match = [mfr for _, x, mfr in mac2mfr if mac_prefix==x]
                    if mfr_match:
                    #if mac_prefix in [x for (id, x, mfr) in mac2mfr]:
                        mfr = mfr_match[0]
                        if mfr == "**company not found**" or mfr == "None" or mfr == None:
                          mfr = lookup_mac(mac)
                    else:
                        mfr = lookup_mac(mac)

                    if mfr != "**company not found**" and mfr != "None" and mfr != None:
                        self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_prefix, 'mfr':mfr})

                    #device_data = {'mac_addr' : mac.upper(), 'mfr': mfr}
                    device_data = {'mac_addr' : mac, 'mfr': mfr}

                    #self.db_handler.db.insert_device_unidentified(device_data)
                    self.db_handler.db.insert_device_unlabeled(device_data)

                    self.db_handler.db.select_last_insert_id()
                    deviceID = self.db_handler.db.cursor.fetchone()[0]

                    # TODO COMPLETE THE REPLACEMENT OF THE OLD findIP and findIPs functions
                    (ip_set, ipv6_set, hasMultiple) = self.cap.findIPs(mac)
                    if hasMultiple:
                        print("Warning: multiple IPv4 or IPv6 addresses found, providing the first one only")
                    ip = list(ip_set)[0]
                    ipv6 = list(ipv6_set)[0]
                    #(ip, ipv6) = self.cap.findIPs(mac)

                    # Insert device_state info into device_state table
                    self.db_handler.db.insert_device_state_unlabeled(
                        {"fileID":self.cap.id,#temporary, needs to be updated later
                         "deviceID":deviceID,
                         "ipv4_addr":ip,
                         "ipv6_addr":ipv6})
                    #newDevices.append(mac)

                    #self.cap.labeledDev.append(deviceID)
                    self.cap.unlabeledDev.append(deviceID)
                    importedDevices.append((deviceID, mac))

                    # Insert device into unlabeled listbox
                    #self.unlabeled_dev_list.append((deviceID, lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                    self.unlabeled_dev_list.append((deviceID, mfr, mac, ip, ipv6))

                else:
                    deviceID = match[0][0]
                    #self.cap.unlabeledDev.append(deviceID)
                    self.cap.labeledDev.append(deviceID)
                    #self.cap.unlabeledDev.append(match[0])
                    importedDevices += match
                    #self.cap.unlabeledDev += match
                    print(deviceID, type(deviceID))
                    self.db_handler.db.select_device(deviceID)

                    (_, mfr, model, _, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                    # Get device state info
                    #self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                    self.db_handler.db.select_device_state(self.cap.id, deviceID)
                    if self.db_handler.db.cursor.rowcount == 1:
                        #(id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                    elif self.db_handler.db.cursor.rowcount == 0:
                        #ip = self.cap.findIP(mac)
                        #ipv6 = self.cap.findIP(mac, v6=True)
                        # TODO COMPLETE THE REPLACEMENT OF THE OLD findIP and findIPs functions
                        (ip_set, ipv6_set, hasMultiple) = self.cap.findIPs(mac)
                        if hasMultiple:
                            print("Warning: multiple IPv4 or IPv6 addresses found, providing the first one only")
                        ip = list(ip_set)[0]
                        ipv6 = list(ipv6_set)[0]
                        # (ip, ipv6) = self.cap.findIPs(mac)

                        # May want to modify this not to take the previous fw_version
                        #self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                        self.db_handler.db.select_most_recent_fw_ver({'deviceID' : deviceID,
                                                                      #'capDate'  : self.cap.capTimeStamp})
                                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                        try:
                            (fw_ver,) = self.db_handler.db.cursor.fetchone()
                        except TypeError as te:
                            fw_ver = ''

                        #self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                        self.db_handler.db.insert_device_state({"fileID":self.cap.id,
                                                                #"mac_addr":mac.upper(),
                                                                "deviceID":deviceID,
                                                                #"internalName":internalName,
                                                                #"fw_ver":prev_fw_ver,
                                                                "fw_ver":fw_ver,
                                                                "ipv4_addr":ip,
                                                                "ipv6_addr":ipv6})
                    else:
                        print("ERROR, something went horribly wrong with the database")

                    # Insert device into labeled listbox
                    self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac.upper(), ip, ipv6))

                # Insert device into device_in_capture table
                self.db_handler.db.insert_device_in_capture_unique({'fileID'   : self.cap.id,
                                                                    'deviceID' : deviceID})

            self.cap.newDevicesImported = True

            '''
            # Loop through the now fully imported list of devices
            for (deviceID, mac_addr) in importedDevices:
                self.db_handler.db.select_device(deviceID)

                (_, mfr, model, _, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                #if unlabeled:
                #    self.cap.unlabeledDev.append(deviceID)
                #else:
                #    self.cap.labeledDev.append(deviceID)

                # Get device state info
                #self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                self.db_handler.db.select_device_state(self.cap.id, deviceID)
                if self.db_handler.db.cursor.rowcount == 1:
                    #(id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                    (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                    #ip = self.cap.findIP(mac)
                    #ipv6 = self.cap.findIP(mac, v6=True)
                    (ip, ipv6) = self.cap.findIPs(mac)

                    # May want to modify this not to take the previous fw_version
                    self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                                  #'capDate'  : self.cap.capTimeStamp})
                                                                  'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                    try:
                        (fw_ver,) = self.db_handler.db.cursor.fetchone()
                    except TypeError as te:
                        fw_ver = ''

                    #self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                    self.db_handler.db.insert_device_state({"fileID":self.cap.id,
                                                            #"mac_addr":mac.upper(),
                                                            "deviceID":deviceID,
                                                            #"internalName":internalName,
                                                            #"fw_ver":prev_fw_ver,
                                                            "fw_ver":fw_ver,
                                                            "ipv4_addr":ip,
                                                            "ipv6_addr":ipv6})
                else:
                    print("ERROR, something went horribly wrong with the database")


                #unlabeled = True
            '''

        else:
            # Loop through lists of self.cap.labeledDev and self.cap.unlabeledDev and
            #   check if the device is no longer in the respective listboxes and
            #     move check that it's in the correct one
            # Check if unlabeled_dev_list is unpopulated and populate if not
            if self.unlabeled_dev_list.num_nodes > 0:

                for unlabeledDevice in self.unlabeled_dev_list.get_list():
                    deviceID = unlabeledDevice[0]
                    if deviceID not in self.cap.unlabeledDev:
                        #self.unlabeled_dev_list.delete_by_val(deviceID, 0)
                        self.unlabeled_dev_list.remove_by_value(deviceID, 0)

                        # Collect necessary information about device and move it into the labeled_dev_list listbox
                        self.db_handler.db.select_device(deviceID)
                        (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                        self.db_handler.db.select_device_state(self.cap.id, deviceID)
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()

                        #self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))
                        self.labeled_dev_list.append_unique((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))

                        self.cap.labeledDev.append(deviceID)
            else:
                for deviceID in self.cap.unlabeledDev:

                    # Collect necessary information about device and place it into unlabeled_dev_list listbox
                    self.db_handler.db.select_device(deviceID)
                    print("deviceID",deviceID)
                    #(_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()
                    (_, mfr, _, mac_addr, _, _, _, _, _, _, _, _, _, _, _, _, _, unlabeled) = self.db_handler.db.cursor.fetchone()

                    self.db_handler.db.select_device_state(self.cap.id, deviceID)
                    #(deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                    (deviceStateID, _, _, _, ip, ipv6) = self.db_handler.db.cursor.fetchone()

                    #self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))
                    #self.labeled_dev_list.append_unique((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))
                    if not unlabeled:
                        print("ERROR with populating unlabeled device list (device is labeled)")
                        return
                    self.unlabeled_dev_list.append_unique((deviceID, mfr, mac_addr, ip, ipv6))

            # check if labeled_dev_list is empty and populate if it is
            if self.labeled_dev_list.num_nodes > 0:
                labeledDeviceIDs = []
                #labeledDeviceIDs = self.labeled_dev_list.get_list()
                for labeled_dev in self.labeled_dev_list.get_list():
                    labeledDeviceIDs.append(labeled_dev[0])
                for deviceID in self.cap.labeledDev:
                    if deviceID not in labeledDeviceIDs:
                        # Collect necessary information about device and move it into the labeled_dev_list listbox
                        self.db_handler.db.select_device(deviceID)
                        (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                        self.db_handler.db.select_device_state(self.cap.id, deviceID)
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()

                        #self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))
                        self.labeled_dev_list.append_unique((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))

                        #self.cap.labeledDev.append(deviceID)
            else:
                for deviceID in self.cap.labeledDev:

                    # Collect necessary information about device and place it into labeled_dev_list listbox
                    self.db_handler.db.select_device(deviceID)
                    #(_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()
                    (_, mfr, model, mac_addr, internalName, category, _, _, _, _, _, _, _, _, _, _, _, unlabeled) = self.db_handler.db.cursor.fetchone()

                    self.db_handler.db.select_device_state(self.cap.id, deviceID)
                    (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()

                    if unlabeled:
                        print("ERROR with populating labeled device list (device is unlabeled)")
                        return
                    #self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))
                    self.labeled_dev_list.append_unique((deviceID, mfr, model, internalName, category, mac_addr, ip, ipv6))




            #if unlabeled:
            #    #self.unlabeled_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
            #    self.unlabeled_dev_list.append((deviceID, lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
            #else: #May want to include firmware version here
                #self.labeled_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
            #    self.labeled_dev_list.append((deviceID, mfr, model, internalName, category, mac.upper(), ip, ipv6))


            # Check if the mac address is in the device_in_capture table and update if necessary
            #if mac.upper() not in [x.upper() for (_,_,_,x) in devFromCapTbl]:
            #if (self.cap.id, deviceID) not in [fileID, devID for (_,fileID,devID) in devFromCapTbl]:
            #    #print("mac not found in table for this capture")
            #    #self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,
            #    self.db_handler.db.insert_device_in_capture({'fileID':self.cap.id,
            #                                                 #'fileHash':self.cap.fileHash,
            #                                                 #'mac_addr':mac.upper()})
            #                                                 'deviceID':deviceID})




        '''
        for mac in self.cap.uniqueMAC:
            #unidentified = True
            unlabeled = True
            #if mac.upper() in [x.upper() for (x,) in macsInDevTbl]:
            if mac.upper() in [x.upper() for (_,x) in macsInDevTbl]:
                # Get device info
                self.db_handler.db.select_device(mac)
                #(id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unidentified) = self.db_handler.db.cursor.fetchone()
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                # Get device state info
                self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                    #ip = self.cap.findIP(mac)
                    #ipv6 = self.cap.findIP(mac, v6=True)
                    (ip, ipv6) = self.cap.findIPs(mac)

                    # May want to modify this not to take the previous fw_version
                    self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                                  #'capDate'  : self.cap.capTimeStamp})
                                                                  'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                    try:
                        (fw_ver,) = self.db_handler.db.cursor.fetchone()
                    except TypeError as te:
                        fw_ver = ''

                    self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                                                            "mac_addr":mac.upper(),
                                                            "internalName":internalName,
                                                            #"fw_ver":prev_fw_ver,
                                                            "fw_ver":fw_ver,
                                                            "ipv4_addr":ip,
                                                            "ipv6_addr":ipv6})
                else:
                    print("ERROR, something went horribly wrong with the database")
                    

            else:
                # Insert device info into device table
                #device_data = {'mfr' : , 'mac_addr' : mac.upper()}

                #device_data = {'mac_addr' : mac.upper()}

        '''        


        # Enable / Disable buttons as deemed necessary
        #if self.unidentified_dev_list.num_nodes > 0:
        if self.unlabeled_dev_list.num_nodes > 0:
            self.b_cap_dev_import.config(state="normal")
        else:
            self.b_cap_dev_import.config(state="disabled")

        #if self.identified_dev_list.num_nodes > 0:
        if self.labeled_dev_list.num_nodes > 0:
            self.b_cap_dev_modify.config(state="normal")
        else:
            self.b_cap_dev_modify.config(state="disabled")

        """
        print("num uniqueMacs:", len(self.cap.uniqueMAC))
        for mac in self.cap.uniqueMAC:
            #unidentified = True
            unlabeled = True
            #if mac.upper() in [x.upper() for (x,) in macsInDevTbl]:
            if mac.upper() in [x.upper() for (_,x) in macsInDevTbl]:
                # Get device info
                self.db_handler.db.select_device(mac)
                #(id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unidentified) = self.db_handler.db.cursor.fetchone()
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()

                # Get device state info
                self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                    #ip = self.cap.findIP(mac)
                    #ipv6 = self.cap.findIP(mac, v6=True)
                    (ip, ipv6) = self.cap.findIPs(mac)

                    # May want to modify this not to take the previous fw_version
                    self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                                  #'capDate'  : self.cap.capTimeStamp})
                                                                  'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                    try:
                        (fw_ver,) = self.db_handler.db.cursor.fetchone()
                    except TypeError as te:
                        fw_ver = ''

                    self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                                                            "mac_addr":mac.upper(),
                                                            "internalName":internalName,
                                                            #"fw_ver":prev_fw_ver,
                                                            "fw_ver":fw_ver,
                                                            "ipv4_addr":ip,
                                                            "ipv6_addr":ipv6})
                else:
                    print("ERROR, something went horribly wrong with the database")
                    
                '''
                if unidentified:
                    self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                else: #May want to include firmware version here
                    self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
                '''

            else:
                # Insert device info into device table
                #device_data = {'mfr' : , 'mac_addr' : mac.upper()}

                #device_data = {'mac_addr' : mac.upper()}

                # Check if MAC to Mfr entry exists
                self.db_handler.db.select_mac_to_mfr()
                mac2mfr = self.db_handler.db.cursor.fetchall()
                mac_prefix = mac.upper()[0:8]
                if mac_prefix in [x for (id, x, mfr) in mac2mfr]:
                    if mfr == "**company not found**" or mfr == "None" or mfr == None:
                        mfr = lookup_mac(mac)
                else:
                    mfr = lookup_mac(mac)

                if mfr != "**company not found**" and mfr != "None" and mfr != None:
                    self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_prefix, 'mfr':mfr})

                device_data = {'mac_addr' : mac.upper(), 'mfr': mfr}

                #self.db_handler.db.insert_device_unidentified(device_data)
                self.db_handler.db.insert_device_unlabeled(device_data)


                # Insert device_state info into device_state table
                #ip = self.cap.findIP(mac)
                #ipv6 = self.cap.findIP(mac, v6=True)
                (ip, ipv6) = self.cap.findIPs(mac)

                #self.db_handler.db.insert_device_state_unidentified(
                self.db_handler.db.insert_device_state_unlabeled(
                    {"fileHash":self.cap.fileHash,
                     "mac_addr":mac.upper(),
                     "ipv4_addr":ip,
                     "ipv6_addr":ipv6})
                
                '''
                # Insert device_state info into device_state table
                # THIS SHOULD BE UNNECESSARY BECAUSE IT SHOULD NEVER BE IN THE device_state table without being in the device_table, but no reason not to safety check
                self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                    print("ERROR: Instance that shouldn't exist\n\tSomething went horribly wrong with the database")
                elif self.db_handler.db.cursor.rowcount == 0:
                    ip = self.cap.findIP(mac)
                    ipv6 = self.cap.findIP(mac, v6=True)

                    # May want to modify this not to take the previous fw_version
                    self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                                  #'capDate'  : self.cap.capTimeStamp})
                                                                  'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                    try:
                        (fw_ver,) = self.db_handler.db.cursor.fetchone()
                    except TypeError as te:
                        fw_ver = ''

                    self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                                                            "mac_addr":mac.upper(),
                                                            "internalName":internalName,
                                                            #"fw_ver":prev_fw_ver,
                                                            "fw_ver":fw_ver,
                                                            "ipv4_addr":ip,
                                                            "ipv6_addr":ipv6})
                else:
                    print("ERROR: Multiple Instances:\n\tSomething went horribly wrong with the database")
                '''
                '''
                # Put device into unidentified_dev_list
                self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                '''

            #if unidentified:
            #if unidentified:
            if unlabeled:
                #self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                self.unlabeled_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
            else: #May want to include firmware version here
                #self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
                self.labeled_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))


            '''
            # Get device state info
            self.db_handler.db.select_device_state(self.cap.fileHash, mac)
            if self.db_handler.db.cursor.rowcount == 1:
                (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
            elif self.db_handler.db.cursor.rowcount == 0:
                ip = self.cap.findIP(mac)


                # May want to modify this not to take the previous fw_version
                self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                              #'capDate'  : self.cap.capTimeStamp})
                                                              'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                try:
                    (fw_ver,) = self.db_handler.db.cursor.fetchone()
                except TypeError as te:
                    fw_ver = ''

                self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                                                        "mac_addr":mac.upper(),
                                                        "internalName":internalName,
                                                        #"fw_ver":prev_fw_ver,
                                                        "fw_ver":fw_ver,
                                                        "ipv4_addr":ip,
                                                        "ipv6_addr":ipv6})
            else:
                print("ERROR, something went horribly wrong with the database")
            '''

            '''
            if unidentified:
                self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
            else:
                self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
            '''
            # Check if the mac address is in the device_in_capture table and update if necessary
            if mac.upper() not in [x.upper() for (_,_,_,x) in devFromCapTbl]:
                #print("mac not found in table for this capture")
                self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,
                                                             'fileHash':self.cap.fileHash,
                                                             'mac_addr':mac.upper()})
        """
        """
        print("num uniqueMacs:", len(self.cap.uniqueMAC))
        for mac in self.cap.uniqueMAC:
            #print("In for mac in self.cap.uniqueMAC")
            #print("\tmac", mac)
            #print("\tmfr = ", lookup_mac(mac))
            if mac.upper() in [x.upper() for (x,) in macsInDevTbl]:
                # Get device info
                self.db_handler.db.select_device(mac)
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unidentified) = self.db_handler.db.cursor.fetchone()

                # Get device state info
                self.db_handler.db.select_device_state(self.cap.fileHash, mac)
                if self.db_handler.db.cursor.rowcount == 1:
                    (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                elif self.db_handler.db.cursor.rowcount == 0:
                #if ip == None:
                    ip = self.cap.findIP(mac)
                #if ipv6 == None:
                    ipv6 = self.cap.findIP(mac, v6=True)

                    # May want to modify this not to take the previous fw_version
                    self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                                  #'capDate'  : self.cap.capTimeStamp})
                                                                  'capDate'  : self.cap.capDate + " " + self.cap.capTime})
                    try:
                        (fw_ver,) = self.db_handler.db.cursor.fetchone()
                    except TypeError as te:
                        fw_ver = ''

                    self.db_handler.db.insert_device_state({"fileHash":self.cap.fileHash,
                                                            "mac_addr":mac.upper(),
                                                            "internalName":internalName,
                                                            #"fw_ver":prev_fw_ver,
                                                            "fw_ver":fw_ver,
                                                            "ipv4_addr":ip,
                                                            "ipv6_addr":ipv6})
                else:
                    print("ERROR, something went horribly wrong with the database")
                    
                '''
                # Check if the mac address is in the device_in_capture table and update if necessary
                if mac.upper() not in [x.upper() for (id,x) in identifiedMacsInDb]:
                    print("mac not found in db")
                    self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                                                 'mac_addr':mac_addr.upper(), 'imported':True})
                    #self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_addr.upper()[0:8], 'mfr':mfr})
                # Update the entry
                else:
                    print("mac found in db")
                    output = [item for item in identifiedMacsInDb if item[1] == mac_addr.upper() and not item[2]]
                    print(output)
                    id = output[0][0]
                    imported = output[0][2]
                    if not imported:
                        print("Id =", id)
                        print("mac_addr =", mac_addr)
                        print("imported =", imported)
                        self.db_handler.db.update_device_in_capture({'id':id, 'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                                                     'mac_addr':mac_addr.upper(), 'imported':True})
                    #self.db_handler.db.select_mac_to_mfr()
                    #mac2mfr = self.db_handler.db.cursor.fetchall()
                    #self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_addr.upper()[0:8], 'mfr':mfr})
                '''
                if unidentified:
                    self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                else:
                    self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
            else:
                #Insert device into Device Table

                if unidentified:
                    self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                else:
                    self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))
                #print("Not in macsInDevTbl")
                #print("\tmac", mac)
                #print("\tmfr = ", lookup_mac(mac))


                #self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
                '''
                self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                                             #'mac_addr':mac_addr.upper(), 'imported':False})
                                                             'mac_addr':mac.upper(), 'imported':False})
                '''
            # Check if the mac address is in the device_in_capture table and update if necessary
            if mac.upper() not in [x.upper() for (_,_,_,x) in devFromCapTbl]:
                #print("mac not found in table for this capture")
                self.db_handler.db.insert_device_in_capture({'fileName':self.cap.fname,
                                                             'fileHash':self.cap.fileHash,
                                                             'mac_addr':mac.upper()})


        """
        '''
        # Enable / Disable buttons as deemed necessary
        #if self.unidentified_dev_list.num_nodes > 0:
        if self.unlabeled_dev_list.num_nodes > 0:
            self.b_cap_dev_import.config(state="normal")
        else:
            self.b_cap_dev_import.config(state="disabled")

        #if self.identified_dev_list.num_nodes > 0:
        if self.labeled_dev_list.num_nodes > 0:
            self.b_cap_dev_modify.config(state="normal")
        else:
            self.b_cap_dev_modify.config(state="disabled")

        '''    

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

    def popup_import_device(self, fname):
        self.w_dev = tk.Toplevel()
        self.w_dev.wm_title("Import Devices")

        #mfr = self.unidentified_dev_list_sel[0]
        #mac = self.unidentified_dev_list_sel[1].upper()
        #ipv4 = self.unidentified_dev_list_sel[2]
        #ipv6 = self.unidentified_dev_list_sel[3]
        deviceID = self.unlabeled_dev_list_sel[0]
        mfr = self.unlabeled_dev_list_sel[1]
        mac = self.unlabeled_dev_list_sel[2].upper()
        ipv4 = self.unlabeled_dev_list_sel[3]
        ipv6 = self.unlabeled_dev_list_sel[4]
        #print("ipv4",ipv4)
        #print("ipv6",ipv6)
        #print(mfr)

        ents = self.make_form_device(deviceFields, deviceOptions, mfr, mac)

        #dev_in_cap_data = fname
        #dev_in_cap_data['mac_addr'] = mac
        dev_in_cap_data = {'mac_addr': mac,
                           'fileID'  : self.cap.id,
                           'deviceID': deviceID}

        #dev_in_cap_data['imported'] = True

        b_import = tk.Button(self.w_dev, text='Import',
                                  command=(lambda e=ents, d=dev_in_cap_data, i=(ipv4, ipv6): self.import_dev_and_close(e,d,i)))

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
                    if field == 'Model':
                        try:
                            ent.insert(30, self.cap.modellookup[mac_addr])
                        except KeyError as ke:
                            print("Model not found for: ", str(ke))

            if not i:
                ent.insert(30, mfr)

            entries.append((field, ent))

        for i, option in enumerate(options):
            if i == len(options)-1:
                row = tk.Frame(self.w_dev)
                lab = tk.Label(row, width=10, text=option, anchor='w')
                ent = tk.Entry(row)

                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                #lab.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                
                entries.append((option, ent))
            else:
                if i%5 == 0:
                    row = tk.Frame(self.w_dev)
                    row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

                checkvar = tk.IntVar()
                ckb = tk.Checkbutton(row, text=option, width=10, justify=tk.LEFT, variable=checkvar)
                ckb.pack(side=tk.LEFT, anchor="w")
                
                if option == "wifi" or option == "WiFi":
                    checkvar.set(True)

                entries.append((option, checkvar))

        return entries

    def import_dev_and_close(self, entries, dev_in_cap_data, ips):
        #device_data = {"unidentified":False}
        device_data = {"unlabeled":False}
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

        self.db_handler.db.insert_device(device_data)
        self.db_handler.db.insert_device_in_capture(dev_in_cap_data)

        mac = dev_in_cap_data['mac_addr']
        deviceID = dev_in_cap_data['deviceID']
        #print("mac:", mac)

        '''
        # Check if MAC to Mfr entry exists ;lkj
        self.db_handler.db.select_mac_to_mfr()
        mac2mfr = self.db_handler.db.cursor.fetchall()
        #mac_prefix = dev_in_cap_data['mac_addr'].upper()[0:8]
        mac_prefix = mac.upper()[0:8]
        if mac_prefix not in [x for (id, x, mfr) in mac2mfr]:
            #print(entries[0])
            self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_prefix, 'mfr':entries[0][1].get()})
        '''

        #self.refresh_unidentified_identified_lists()
        self.cap.unlabeledDev.remove(deviceID)
        self.cap.labeledDev.append(deviceID)
        self.refresh_unlabeled_labeled_lists()

        #mac = dev_in_cap_data['mac_addr']

        #self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
        self.db_handler.db.select_most_recent_fw_ver({'deviceID' : deviceID,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        try:
            (fw_ver,) = self.db_handler.db.cursor.fetchone()
        except TypeError as te:
            fw_ver = ''
            
        device_state_data = {#'fileHash'     : dev_in_cap_data['fileHash'],
                             'fileID'       : dev_in_cap_data['fileID'],
                             'mac_addr'     : mac,
                             #'deviceID'     : dev_in_cap_data['deviceID'],
                             'deviceID'     : deviceID,
                             'internalName' : device_data['internalName'],
                             'fw_ver'       : fw_ver,
                             #'ipv4_addr'    : self.cap.findIP(mac),
                             #'ipv6_addr'    : self.cap.findIP(mac, v6=True)}
                             'ipv4_addr'    : ips[0],
                             'ipv6_addr'    : ips[1]}

        try:
            self.popup_update_device_state(device_state_data)
        except mysql.connector.MySQLInterfaceError as msqle:
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Please create a unique Internal Name")

        self.w_dev.destroy()

    def popup_update_device_state(self, device_state_data):
        self.w_dev_state = tk.Toplevel()
        self.w_dev_state.wm_title(device_state_data['internalName'])

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
            # if not i:
            if (label=='fileID') or (label=='deviceID'):
                continue
            if (value == None):
                value = ''
            row = tk.Frame(self.w_dev_state)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            lab = tk.Label(row, width=15, text=str(field2db.inverse[label]).replace('[','').replace(']','').replace("'",''), anchor='w')
            lab.pack(side=tk.LEFT)
            if label == 'fw_ver':
                v = tk.StringVar()
                ent = tk.Entry(row, textvariable=v)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                ent.insert(25, value)

                entries[label] = v
            else:
                lab = tk.Label(row, width=25, text=value, anchor='w', fg='gray')
                lab.pack(side=tk.LEFT)
                entries[label] = value

        return entries


    def import_dev_state_and_close(self, device_state_data, entries):
        print("device_state_data: ",device_state_data)
        print("entries: ",entries)

        print(entries['fw_ver'].get())
        device_state_data['fw_ver'] = str(entries['fw_ver'].get())
        
        # Check if there is already an entry for this data:
        #self.db_handler.db.select_device_state_exact(device_state_data)
        #self.db_handler.db.select_device_state(device_state_data["fileHash"], device_state_data["mac_addr"])
        self.db_handler.db.select_device_state(device_state_data["fileID"], device_state_data["deviceID"])
        temp = self.db_handler.db.cursor.fetchone()
        print(temp)
        if temp == None:
            self.db_handler.db.insert_device_state(device_state_data)
        else:
            device_state_data["id"] = temp[0]
            self.db_handler.db.update_device_state(device_state_data)

        self.w_dev_state.destroy()


    def fetch(self,entries):
        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            print('%s: "%s"' % (field, text)) 


    # Uses Treeview
    def populate_capture_list(self):
        # clear previous list
        self.cap_list.clear()
        #self.cap_list.append((0,"All...",))
        self.cap_list.append((0,"All..."))

        # Get and insert all captures currently added to database
        self.db_handler.db.select_imported_captures()

        for (id, fileName, fileLoc, fileHash, capDate, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in self.db_handler.db.cursor:
            self.cap_list.append((id, capDate, fileName, deviceAction, capDuration, details, fileLoc))
        #for (id, fileName, fileLoc, fileHash, capDate, activity,
             #duration, details) in self.db_handler.db.cursor:
            #self.cap_list.append((capDate, fileName, activity, duration, details, fileLoc)) #for early stages
            #self.cap_list.append((capDate, fileName, activity, details, fileLoc)) #for early stages
        
        # Set focus on the first element
        self.cap_list.focus(0)
        self.cap_list.selection_set(0)


    # Uses Treeview
    def update_dev_list(self, event):
        first = True

        cap_ids=[]

        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)
            #cap_date = cap_details[0]
            cap_date = cap_details[1]

            if cap_date == "All...":
                self.populate_device_list()
                self.b_main_inspect.config(state="disabled")
                #break
                return
            else:
                #cap_name = cap_details[1]
                #cap_name = cap_details[2]

                #captureID = cap_details[0]
                #self.populate_device_list( capture=captureID, append=(not first) )
                #first=False

                cap_ids.append(cap_details[0])

                #self.b_main_inspect.config(state="normal")
        self.populate_device_list(captureIDs=cap_ids)
        self.b_main_inspect.config(state="normal")
        
        #;lkj
        #self.update_comm_list(None)

    '''#;lkj somehow this was here uncommented before
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

        for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, bluetooth,
             G3, G4, G5, zigbee, zwave, otherProtocols, notes) in self.db_handler.db.cursor:
            device_list = self.dev_list.get(0, tk.END)

            self.dev_list.insert(tk.END, [mfr, model, mac_addr, internalName])

        # Set focus on the first element
        self.dev_list.focus(0)
        self.dev_list.selection_set(0)
    '''
        
    # Uses Treeview
    #def populate_device_list(self, capture=None, append=False):
    #def populate_device_list(self, captureID=None, append=False):
    #    if not append:
    #        self.dev_list.clear()
    #        self.dev_list.append(("All...",))

        # Get and insert all captures currently added to database
        #if capture == None:
    #    if captureID == None:
    #        self.db_handler.db.select_devices()
    #    else:
            #self.db_handler.db.select_devices_from_cap(capture)
    #        self.db_handler.db.select_devices_from_cap(captureID)
        

    #    for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, ethernet, bluetooth,
    #         G3, G4, G5, zigbee, zwave, otherProtocols, notes, unidentified) in self.db_handler.db.cursor:
    #        self.dev_list.append_unique((mfr, model, internalName, mac_addr, deviceCategory)) #for early stages

    #    self.dev_list.focus(0)
    #    self.dev_list.selection_set(0)

    def populate_device_list(self, captureIDs=None):#, append=False):
        # clear previous list
        self.dev_list.clear()
        self.dev_list.append((0, "All..."))

        # Get and insert all captures currently added to database
        #if capture == None:
        if captureIDs == None:
            self.db_handler.db.select_devices()
        else:
            #self.db_handler.db.select_devices_from_cap(capture)
            self.db_handler.db.select_devices_from_caplist(captureIDs)
        

        for (id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, ethernet, bluetooth,
             #G3, G4, G5, zigbee, zwave, otherProtocols, notes, unidentified) in self.db_handler.db.cursor:
             G3, G4, G5, zigbee, zwave, otherProtocols, notes, unlabeled) in self.db_handler.db.cursor:
            #self.dev_list.append_unique((mfr, model, internalName, mac_addr, deviceCategory)) #for early stages
            self.dev_list.append((id, mfr, model, internalName, mac_addr, deviceCategory)) #for early stages

        self.dev_list.focus(0)
        self.dev_list.selection_set(0)
        
        #:LKJ
        #self.populate_comm_list(None)


    def update_comm_list(self, event):
        first = True


        self.populate_comm_list()
        return



        '''
        #for dev in self.dev_list.curselection():
        for dev in self.dev_list.selection():
            ##cap_details = self.cap_list.get(cap)
            #cap_date = cap_details[0]
            ##cap_date = cap_details[1]
            dev_name = self.dev_list.get(dev)

            # To simplify debugging
            print("\nin update_comm_list")

            if type(dev_name) is str:
                print("dev = " + dev_name)
            else:
                print("dev = " + str(dev_name[0]))
            if dev_name == "All...":
                print("Processing \'All...\'")
                #self.populate_comm_list(dev_name)
                #self.populate_comm_list("*")
                self.populate_comm_list(append=(not first))
                break
            else:
                #self.populate_comm_list(dev_name, not first)
                self.populate_comm_list(append=(not first))
                first=False
        '''

    def import_packets(self, cap):
        '''
        for p in cap.pkt:
            pkt_data = {"fileHash":cap.fileHash,
                        "mac":a,
                        "src":b,
                        "dest":c,
                        "protocol":d,
                        "length":e,
                        "direction":f,
                        "raw":p}
            self.db_handler.db.insert_packets(pkt_data)

        '''
        print("In import_packets")
        #h = {"fileHash" : cap.fileHash}
        h = {"fileID" : cap.id}
        batch = []

        start = datetime.now()

        i = 0
        for p in cap.pkt_info:
            p.update(h)

            #self.db_handler.db.insert_packet( p )
            batch.append(p)

            # packet components: INT*5 + Char(64) + Datetime + Double + VARCHAR(17) + TEXT (4-8B) + TEXT*2 (IPv4 or IPv6) + BOOL + TEXT
            # packet size = 20B + 64B + 5B + 8B + 17B + (4-8)B + (8/32)B + 1B + (3B)
            # packet size w/o ID = 16 + 64 + 5 + 8 + 17 + 4-8 + 8-32 + 1 + 3B
            # min packet size = 126B
            # max packet size = 154B (161) (172)

            #if i < 1023:
            if i < 511:
              i += 1
            else:
            #if len(batch) >= 1024:
              self.db_handler.db.insert_packet_batch( batch )
              batch.clear()
              i = 0

        # Insert the stragglers 
        self.db_handler.db.insert_packet_batch( batch )

        stop = datetime.now()
        print("time to import = ", (stop-start).total_seconds())

        self.populate_comm_list()

    #;lkj
    #def populate_comm_list(self, device, append=False):
    def populate_comm_list(self, append=False):
        # Clear previous list
        if not append:
            #self.comm_list.delete(0,tk.END)
            self.comm_list.clear()
            self.db_handler.db.drop_cap_toi()
            self.db_handler.db.drop_dev_toi()
            self.db_handler.db.drop_pkt_toi()
            first = True
        else:
            first = False

        print("\nPopulate Comm List")
            
        # Selecting based on cap list
        #first = True # probably unnecessary
        self.db_handler.db.captureID_list.clear()
        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)

            print("cap_details",cap_details)

            #cap_date = cap_details[0]
            cap_date = cap_details[1]

            if cap_date == "All...":
                #self.populate_device_list()
                print("All Captures") #probably unnecessary
                #self.db_handler.db.create_cap_toi() #probably unnecessary

                for cap_data in self.cap_list.get_list()[1:]:
                    self.db_handler.db.captureID_list.append(cap_data[0])
                break
            else:
                self.db_handler.db.captureID_list.append(cap_details[0])
                #cap_name = cap_details[1] #{'fileName':cap_name}
                '''
                cap_name = cap_details[2] #{'fileName':cap_name}
                print(cap_name)
                capture = {'fileName':cap_name}
                if first:
                    # Create packet table of interest
                    self.db_handler.db.create_pkt_toi(capture)

                    self.db_handler.db.create_cap_toi(capture)
                    first=False
                else:
                    # Update packet table of interest
                    self.db_handler.db.update_pkt_toi(capture)

                    self.db_handler.db.update_cap_toi(capture)
                '''
        print("captureID_list", self.db_handler.db.captureID_list)
        # Check if the list is empty and return if it is
        if not self.db_handler.db.captureID_list:
            return
        self.db_handler.db.create_pkt_toi_from_captureID_list()


        # Selecting based on dev list
        '''
        first = True
        for dev in self.dev_list.selection():
            dev_details = self.dev_list.get(dev)

            print(dev_details)

            print("dev =", dev_details[0])
            dev_name = dev_details[0]

            if dev_name == "All...":
                print("No device restrictions")
                # Create dev_toi
                self.db_handler.db.create_dev_toi()
                break
            else:
                print("mac =", dev_details[3])
                dev_mac = dev_details[3]
                mac = {'mac_addr':dev_mac}
                if first:
                    self.db_handler.db.create_dev_toi(mac)
                else:
                    self.db_handler.db.update_dev_toi(mac)

                # Update dev_toi
                #self.populate_comm_list(dev_name, not first)
                #self.populate_comm_list(append=(not first))
                first=False
        '''
        self.db_handler.db.deviceID_list.clear()
        for dev in self.dev_list.selection():
            dev_details = self.dev_list.get(dev)

            print("dev_details",dev_details)

            dev_name = dev_details[1]
            print("dev =", dev_name)

            if dev_name == "All...":
                #print("No device restrictions")
                # Create dev_toi

                for dev_data in self.dev_list.get_list()[1:]:
                    #print(dev_data)
                    self.db_handler.db.deviceID_list.append(dev_data[0])
                #self.db_handler.db.create_dev_toi()
                #print("breaking out")
                break
            else:
                self.db_handler.db.deviceID_list.append(dev_details[0])

        print("deviceID_list", self.db_handler.db.deviceID_list)
        #self.db_handler.db.drop_dev_toi()
        #self.db_handler.db.create_dev_toi_from_deviceID_list()
        self.db_handler.db.create_dev_toi_from_fileID_list()



        # Selecting based on E/W or N/S
        if self.comm_state == "any":
            #ew = {"ew":[0, 1]}
            ew = [0, 1]
        elif self.comm_state == "ns":
            #ew = {"ew":[0]}
            ew = [0]
        elif self.comm_state == "ew":
            #ew = {"ew":[1]}
            ew = [1]
        '''
        if self.comm_state == "any":
            pass
        elif self.comm_state == "ns":
            pass
        elif self.comm_state == "ew":
            pass
        '''
        # Selecting based on restriction
        '''
        if self.comm_dev_restriction == "none":
            pass
        elif self.comm_dev_restriction == "between":
            pass
        elif self.comm_dev_restriction == "either":
            pass
        '''

        # Get files from tables of interest
        #self.db_handler.db.select_pkt_toi(ew)
        self.db_handler.db.select_pkt_toi(ew, self.comm_list_num_pkts)


        # Get and insert all captures currently added to database
        #######self.db_handler.db.select_packets()

        # might be interesting to include destination URL and NOTES
        # Limiting version for debugging at least
        #self.comm_list_num_pkts = 100
        self.comm_list_all_pkts = self.db_handler.db.cursor


        #for (i, (id, fileHash, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
        #     ew, tlp, tlp_srcport, tlp_dstport, pkt_length)) in enumerate(self.db_handler.db.cursor): 



        #for (i, (id, fileHash, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
        #    ew, tlp, tlp_srcport, tlp_dstport, pkt_length)) in enumerate(self.comm_list_all_pkts): 



        #i = 0
        #for (id, fileHash, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
        for (id, fileID, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
            ew, tlp, tlp_srcport, tlp_dstport, pkt_length) in self.comm_list_all_pkts: 
            #self.comm_list.insert(tk.END, [pkt_time, mac_addr, ip_ver, ip_src, ip_dst, ew, 
            #                               protocol, tlp, tlp_srcport, tlp_dstport, pkt_length])

            # Handle instances where data is NULL/None
            if ip_ver == None:
                ip_ver = ''
                ip_src = ''
                ip_dst = ''
            if tlp == None:
                tlp = ''
                tlp_srcport = ''
                tlp_dstport = ''
                
            #self.comm_list.append_unique((id, fileID, pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
            #                              protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
            self.comm_list.append((id, fileID, pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                   protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
            
            #i+=1

            '''
            # Temporary solution: ********************
            if self.comm_state == "any":
                self.comm_list.append_unique((pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                              protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
                i += 1
            elif self.comm_state == "ew":
                if ew:
                    self.comm_list.append_unique((pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                                  protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
                    i += 1
            elif self.comm_state == "ns":
                if not ew:
                    self.comm_list.append_unique((pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                                  protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
                    i += 1
            '''
            #if i >= self.comm_list_num_pkts: 
            #    break

        '''
        for (id, fileHash, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
             ew, tlp, tlp_srcport, tlp_dstport, pkt_length) in self.db_handler.db.cursor: 
            #self.comm_list.insert(tk.END, [pkt_time, mac_addr, ip_ver, ip_src, ip_dst, ew, 
            #                               protocol, tlp, tlp_srcport, tlp_dstport, pkt_length])
            self.comm_list.append_unique((pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                          protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
        '''
        '''
        self.db_handler.db.select_device_communication(device)
        
        for (id, fileHash, pkt_time, mac_addr, protocol, ip_ver, ip_src, ip_dst,
             tlp, tlp_srcport, tlp_dstport, pkt_length, raw) in self.db_handler.db.cursor: # might be interesting to include destination URL and NOTES
            self.comm_list.insert(tk.END, [pkt_time, mac_addr, ip_ver, ip_src, ip_dst, protocol, tlp, tlp_srcport, tlp_dstport, pkt_length, raw])
        '''
        '''
        for (id, fileHash, mac_addr, protocol, src_port, dst_ip_addr, ipv6, dst_url,
             dst_port, notes) in self.db_handler.db.cursor:
            self.comm_list.insert(tk.END, [protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes])
        '''
        # Set focus on the first element
        #self.comm_list.select_set(0)
        #self.comm_list.event_generate("<<ListboxSelect>>")
        self.comm_list.focus(0)
        self.comm_list.selection_set(0)


    def modify_comm_state(self, button):
        print("button:",button)
        # Check current filter
        if self.comm_state == "any":
            if button == "ns":
                self.comm_state = "ns"
            elif button == "ew":
                self.comm_state = "ew"
            else:
                print("Something went wrong with modifying the communication state")
        elif self.comm_state == "ns":
            if button == "ns":
                self.comm_state = "any"
            elif button == "ew":
                self.comm_state = "ew"
            else:
                print("Something went wrong with modifying the communication state")
        elif self.comm_state == "ew":
            if button == "ns":
                self.comm_state = "ns"
            elif button == "ew":
                self.comm_state = "any"
            else:
                print("Something went wrong with modifying the communication state")
        else:
            print("Something went wrong with modifying the communication state")

        # Update the filter
        if self.comm_state == "any":
            self.b_ns.config(fg = "black")
            self.b_ew.config(fg = "black")
            #update communication table view
        elif self.comm_state == "ns":
            self.b_ns.config(fg = "green")
            self.b_ew.config(fg = "red")
            #update communication table view
        elif self.comm_state == "ew":
            self.b_ns.config(fg = "red")
            self.b_ew.config(fg = "green")
            #update communication table view
        else:
            print("Something went wrong with modifying the communication state")

        print("comm_state:", self.comm_state)
        self.populate_comm_list()


    def modify_comm_num_pkts(self, num_pkts):
        print("number of packets:", num_pkts)
        self.comm_list_num_pkts = num_pkts

        if num_pkts == 10:
            self.b_pkt10.config(state='disabled')
            self.b_pkt100.config(state='normal')
            self.b_pkt1000.config(state='normal')
            self.b_pkt10000.config(state='normal')
        elif num_pkts == 100:
            self.b_pkt10.config(state='normal')
            self.b_pkt100.config(state='disabled')
            self.b_pkt1000.config(state='normal')
            self.b_pkt10000.config(state='normal')
            pass
        elif num_pkts == 1000:
            self.b_pkt10.config(state='normal')
            self.b_pkt100.config(state='normal')
            self.b_pkt1000.config(state='disabled')
            self.b_pkt10000.config(state='normal')
        elif num_pkts == 10000:
            self.b_pkt10.config(state='normal')
            self.b_pkt100.config(state='normal')
            self.b_pkt1000.config(state='normal')
            self.b_pkt10000.config(state='disabled')
        else:
            print("unidentified value for modify_comm_num_pkts")
        
        self.populate_comm_list()


    def modify_comm_dev_restriction(self, r_button):
        print("comm_dev_restriction: ",self.comm_dev_restriction)
        print("communication device restriction:", r_button)

        if self.comm_dev_restriction == "none":
            if r_button == "between":
                self.comm_dev_restriction = "between"
            elif r_button == "either":
                self.comm_dev_restriction = "either"
            else:
                print("Something went wrong with modifying the communication device restriction")
        elif self.comm_dev_restriction == "between":
            if r_button == "between":
                self.comm_dev_restriction = "none"
            elif r_button == "either":
                self.comm_dev_restriction = "either"
            else:
                print("Something went wrong with modifying the communication device restriction")
        elif self.comm_dev_restriction == "either":
            if r_button == "between":
                self.comm_dev_restriction = "between"
            elif r_button == "either":
                self.comm_dev_restriction = "none"
            else:
                print("Something went wrong with modifying the communication device restriction")
        else:
            print("Something went wrong with modifying the communication device restriction")

        # Update the filter
        if self.comm_dev_restriction == "none":
            self.b_between.config(fg = "black")
            self.b_either.config(fg = "black")
            #update communication table view
        elif self.comm_dev_restriction == "between":
            self.b_between.config(fg = "green")
            self.b_either.config(fg = "red")
            #update communication table view
        elif self.comm_dev_restriction == "either":
            self.b_between.config(fg = "red")
            self.b_either.config(fg = "green")
            #update communication table view
        else:
            print("Something went wrong with modifying the communication device restriction")

            
        print("comm_dev_restriction:", self.comm_dev_restriction)
        self.populate_comm_list()

    def popup_internal_addr_list(self):
        # Currently not functional... Needs to be worked out
        pass
    
        self.w_internal_addr = tk.Toplevel()

        self.w_internal_addr.wm_title("Internal Address Ranges")

        topFrame = tk.Frame(self.w_internal_addr, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        subtitle = tk.Label(topFrame, text="Current Address Ranges", bg="#eeeeee", bd=1, relief="flat")
        subtitle.pack(side="top", fill=tk.X)

        botFrame = tk.Frame(self.w_internal_addr, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        addr_range_list_header = ["Lower Bound", "Upper Bound", "IP Version"]
        addr_range_list = MultiColumnListbox(parent=botFrame,
                                                   header=addr_range_list_header,
                                                   list=list(), selectmode="browse")
        # To be aded later
        # self.unidentified_dev_list.bind("<<TreeviewSelect>>", self.update_unidentified_list_selection)


        # Grid placements #
        # self.topDevFrame.grid(row=0, column=0, sticky="new")
        # self.botDevFrame.grid(row=1, column=0, sticky="nsew")
        topFrame.grid(row=0, column=0, sticky="new")
        botFrame.grid(row=1, column=0, sticky="nsew")

        # Grid configuration #
        '''
        self.topFrame.grid_columnconfigure(0, weight=0)
        self.botDevFrame.grid_rowconfigure(1, weight=1)
        self.botDevFrame.grid_columnconfigure(0, weight=1)
        self.botDevFrame.grid_columnconfigure(1, weight=1)

        self.w_cap_dev.grid_rowconfigure(1, weight=1)
        self.w_cap_dev.grid_columnconfigure(0, weight=1)
        '''

        # Buttons #
        self.b_internal_addr_close = tk.Button(botFrame, text='Close', command=self.w_internal_addr.destroy)
        self.b_internal_addr_new = tk.Button(botFrame, text='+', command=self.popup_internal_addr)
        #TO BE COMPLETED
        self.b_internal_addr_modify = tk.Button(botFrame, text='Modify', state='disabled',
                                                #command=(lambda d=self.identified_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))
                                                command=(lambda d=self.labeled_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))

        self.b_internal_addr_close.pack(side=tk.LEFT, padx=5, pady=5)
        self.b_internal_addr_new.pack(side=tk.RIGHT, padx=5, pady=5)
        self.b_internal_addr_modify.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_internal_addr)






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
    def generate_MUD_wizard(self):
        #print("You shouldn't have gotten to the generate MUD wizard yet")

        self.w_gen_mud = tk.Toplevel()
        self.w_gen_mud.wm_title('Generate MUD File Wizard')

        # Prompt for selecting the device
        prompt_row = tk.Frame(self.w_gen_mud)
        prompt_row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        dev_select_label = tk.Label(prompt_row, width=45, text="Please select the device you would like to profile:", anchor='w')
        dev_select_label.pack(side=tk.LEFT)


        list_row = tk.Frame(self.w_gen_mud)
        list_row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.mud_dev_header = ["Manufacturer", "Model", "Internal Name", "Category", "MAC"]#, "IPv4", "IPv6"]
        #self.mud_dev_list = MultiColumnListbox(parent=self.mudDevFrame,
        self.mud_dev_list = MultiColumnListbox(parent=list_row,
                                                   header=self.mud_dev_header,
                                                   list=list(), selectmode="browse")
        self.mud_dev_list.bind("<<TreeviewSelect>>", self.update_mud_device_selection)

        #self.w_gen_mud.bind('<Return>', (lambda event, n=internalName, m=mac: self.select_mud_dev(n, m)))
        self.w_gen_mud.bind('<Return>', (lambda event : self.select_mud_dev()))
        
        b_select = tk.Button(self.w_gen_mud, text='select',
                             #command=(lambda n=internalName, m=mac: self.select_mud_dev(n, m)))
                             command=(self.select_mud_dev()))

        b_cancel = tk.Button(self.w_gen_mud, text='Cancel', command=self.w_gen_mud.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_select.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_select.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        self.populate_mud_dev_list()

        self.yield_focus(self.w_gen_mud)
        
    '''

    def select_mud_dev(self):
        pass








    def popup_generate_mud_wizard(self):
        self.w_gen_mud = tk.Toplevel()
        self.w_gen_mud.wm_title('Generate MUD File Wizard')


        #Frames for Device, Gateway, and PCAPs
        self.topMudDevFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        self.midMudGateFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        self.botMudPCAPFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        ## Top Device Frame
        #dev_select_label = tk.Label(self.topDevFrame, width=20, text="Select the device to profile:", anchor='w')
        #dev_select_label.pack(side=tk.LEFT)

        #self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.mud_dev_title_var=tk.StringVar()
        self.mud_dev_title_var.set("Device to Profile:")
        self.mud_dev_title = tk.Label(self.topMudDevFrame, textvariable=self.mud_dev_title_var,
                                      bg="#eeeeee", bd=1, relief="flat")
        self.mud_dev_title.pack(side="top", fill=tk.X)

        #self.mud_dev_header = ["Manufacturer", "Model", "MAC Address", "Internal Name", "Category"]
        self.mud_dev_header = ["id", "Internal Name", "Manufacturer", "Model", "MAC Address", "Category"]
        self.mud_dev_list = MultiColumnListbox(parent=self.topMudDevFrame,
                                               header=self.mud_dev_header,
                                               list=list(), selectmode="browse",
                                               exclusionList=["id"])
        #unidentified_list_selection
        #self.mud_dev_list.bind("<<TreeviewSelect>>", self.update_gateway_list_selection)
        self.mud_dev_list.bind("<<TreeviewSelect>>", self.populate_mud_gate_list)



        ## Middle Gateway Frame
        self.mud_gate_title_var=tk.StringVar()
        self.mud_gate_title_var.set("Network Gateway:")
        self.mud_gate_title = tk.Label(self.midMudGateFrame, textvariable=self.mud_gate_title_var,
                                       bg="#eeeeee", bd=1, relief="flat")
        self.mud_gate_title.pack(side="top", fill=tk.X)

        self.mud_gate_header = ["id", "Internal Name", "Manufacturer", "Model", "Category",
                                "MAC Address", "IPv4", "IPv6"]
        self.mud_gate_list = MultiColumnListbox(parent=self.midMudGateFrame,
                                                header=self.mud_gate_header,
                                                list=list(), selectmode="browse",
                                                exclusionList=["id"])
        #identified_list_selection
        #self.mud_gate_list.bind("<<TreeviewSelect>>", self.update_pcap_list_selection)
        self.mud_gate_list.bind("<<TreeviewSelect>>", self.populate_mud_pcap_list)



        ## Bot PCAP Frame
        self.mud_pcap_title_var=tk.StringVar()
        self.mud_pcap_title_var.set("Select Packet Captures (PCAPs):")
        self.mud_pcap_title = tk.Label(self.botMudPCAPFrame, textvariable=self.mud_pcap_title_var,
                                       bg="#eeeeee", bd=1, relief="flat")
        self.mud_pcap_title.pack(side="top", fill=tk.X)


        self.mud_pcap_header = ["id", "Date", "Capture Name", "Activity", "Duration (seconds)", "Details",
                                "Capture File Location"]
        #self.mud_pcap_header = ["Date","Capture Name","Activity", "Details","Capture File Location"]
        self.mud_pcap_list = MultiColumnListbox(parent=self.botMudPCAPFrame,
                                                header=self.mud_pcap_header,
                                                list=list(), keep1st=True,
                                                exclusionList=["id"])
        #identified_list_selection
        self.mud_pcap_list.bind("<<TreeviewSelect>>", self.select_mud_pcaps)



        # Grid placements #
        self.topMudDevFrame.grid(row=0, column=0, sticky="nsew") #new
        self.midMudGateFrame.grid(row=1, column=0, sticky="nsew")
        self.botMudPCAPFrame.grid(row=2, column=0, sticky="nsew")


        # Grid configuration #
        #self.topMudDevFrame.grid_rowconfigure(0, weight=1)
        #self.midMudGateFrame.grid_rowconfigure(1, weight=1)
        #self.botMudPCAPFrame.grid_rowconfigure(2, weight=1)


        self.w_gen_mud.grid_rowconfigure(0, weight=1)
        self.w_gen_mud.grid_rowconfigure(1, weight=1)
        self.w_gen_mud.grid_rowconfigure(2, weight=1)


        self.b_mud_generate = tk.Button(self.botMudPCAPFrame, text='Generate', state='disabled',
                             #command=(lambda n=internalName, m=mac: self.select_mud_dev(n, m)))
                                        #command=(self.select_mud_dev()))
                                        command=(self.generate_mud_file))

        self.b_mud_cancel = tk.Button(self.botMudPCAPFrame, text='Cancel', command=self.w_gen_mud.destroy)

        if sys.platform == "win32":
            self.b_mud_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_mud_generate.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_mud_generate.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_mud_cancel.pack(side=tk.RIGHT, padx=5, pady=5)





        # Update unidentified, identified lists and try to select the first element
        #self.refresh_mud_lists()
        self.populate_mud_dev_list()


        # Select first element of each list
        # Try becuase the list might be empty
        self.mud_dev_list.focus(0)
        self.mud_dev_list.selection_set(0)
        self.mud_gate_list.focus(0)
        self.mud_gate_list.selection_set(0)
        self.mud_pcap_list.focus(0)
        self.mud_pcap_list.selection_set(0)

        self.yield_focus(self.w_gen_mud)



    def select_mud_pcaps(self, event):
        print("Select MUD pcaps")
        self.mud_pcap_sel = []

        print("mud_pcap_list.selection():",self.mud_pcap_list.selection())

        #print("self.mud_pcap_list.get( self.mud_pcap_list.selection() ):", self.mud_pcap_list.get( self.mud_pcap_list.selection() ))

        for pcap_item in self.mud_pcap_list.selection():
            pcap = self.mud_pcap_list.get( pcap_item )
            print("pcap:",pcap)

            if pcap[1] == "All...":
                #self.db_handler.db.select_imported_captures_with({"dev_mac":self.dev_mac, "gateway_mac":self.gateway_mac})
                self.db_handler.db.select_imported_captures_with({"deviceID":self.deviceID, "gatewayID":self.gatewayID})
                #for (id, fileName, fileLoc, fileHash, capDate, activity, details) in self.db_handler.db.cursor:

                for (id, fileName, fileLoc, fileHash, capDate, capDuration, lifecyclePhase,
                     internet, humanInteraction, preferredDNS, isolated, durationBased,
                     duration, actionBased, deviceAction, details) in self.db_handler.db.cursor:
                    self.mud_pcap_sel.append(fileLoc + "/" + fileName)
                #for (id, fileName, fileLoc, fileHash, capDate, duration, activity, details) in self.db_handler.db.cursor:
                #    self.mud_pcap_sel.append(fileLoc + "/" + fileName)
                break
            else:
                self.mud_pcap_sel.append(pcap[4] + pcap[1])

        #for pcap in self.mud_pcap_list.get( self.mud_pcap_list.selection() ):
        #    print("pcap:",pcap)
        #    self.mud_pcap_sel.append(pcap[4] + pcap[1])

        self.b_mud_generate.config(state='normal')


    def generate_mud_file(self):#, event):
        print("Preparing to generate mud file")
        self.mud_gen_obj = MUDgeeWrapper()

        
        #self.mud_gen_obj.set_device(mac=self.mud_device[3], name=self.mud_device[2])
        self.mud_gen_obj.set_device(mac=self.mud_device[4], name=self.mud_device[3])
        #self.mud_config = MUDgeeWrapper({'device_config':{'device':mac, 'deviceName':internalName}})


        self.db_handler.db.select_gateway_ips({'gateway_mac':self.gateway_mac})

        ip = None
        ipv6 = None

        for (ipv4_addr, ipv6_addr) in self.db_handler.db.cursor:
            print("ipv4_addr:", ipv4_addr)
            print("ipv4:",ip)
            print("ipv6_addr:", ipv6_addr)
            print("ipv6:",ipv6)

            if (ip != None and ip != ipv4_addr):
                if ip == "Not found" or ip == "0.0.0.0":
                    if ipv4_addr != "Not found" and ipv4_addr != "0.0.0.0":
                        ip = ipv4_addr
                else:
                    messagebox.showerror("MUD Gateway Selection Error",
                                         "The selected gateway appears to have either multiple IPv4 addresses or IPv6 addresses!")
                    return
            else:
                ip = ipv4_addr
                
            if (ipv6 != None and ipv6 != ipv6_addr):
                if ipv6 == "Not found" or ipv6 == "::":
                    if ipv6_addr != "Not found" and ipv6_addr != "::":
                        ipv6 = ipv6_addr
                else:
                    messagebox.showerror("MUD Gateway Selection Error",
                                         "The selected gateway appears to have either multiple IPv4 addresses or IPv6 addresses!")
                    return
            else:
                ipv6 = ipv6_addr

        if (ip == "Not found" or ip == "0.0.0.0"):
            if (ipv6 == "Not found" or ipv6 == "::"):
                messagebox.showwarning("MUD Gateway Selection Warning",
                                       "The selected gateway does not have valid IPv4 or IPV6 addresses.")
            else:
                messagebox.showwarning("MUD Gateway Selection Warning",
                                       "The selected gateway does not have a valid IPv4 address.")
                #return
        elif (ipv6 == "Not found" or ipv6 == "::"):
            messagebox.showwarning("Problem with MUD Gateway Selection",
                                   "The selected gateway does not have a valid IPv6 address.")
            #return


        #self.mud_gate_list.append((mfr, model, internalName, category, mac))


        #self.mud_gen_obj.set_gateway(mac=self.mud_gateway[4], ip=ip, ipv6=ipv6)
        self.mud_gen_obj.set_gateway(mac=self.mud_gateway[5], ip=ip, ipv6=ipv6)

        #pcap_list = self.mud_pcap_sel

        #self.mud_gen_obj.gen_mudfile(pcap_list)
        print("Generating MUD file")
        self.mud_gen_obj.gen_mudfile(self.mud_pcap_sel)
        messagebox.showinfo("MUD File Generation Complete", "The generated MUD file is in the 'mudfiles' directory.")



    def populate_mud_dev_list(self):
        # Get and insert all captures currently added to database
        self.mud_dev_list.clear()
        print("Populating MUD Device List")
        self.db_handler.db.select_devices_imported()

        for (id, mfr, model, mac, internalName, category) in self.db_handler.db.cursor:
            self.mud_dev_list.append((id, internalName, mfr, model, mac, category))
            #self.mud_dev_list.append(internalName + ' | ' + mac)

        #self.gate_select_list = tk.OptionMenu(self.row_gate, self.mud_gate_var, *self.mud_gate_list)
        #self.gate_select_list.pack(side=tk.LEFT)

    def populate_mud_gate_list(self, event=None):#, ignored_dev = None):
        print("Populating MUD Gateway list")
        self.mud_gate_list.clear()
        #self.mud_gate_list.append(('--',))
        
        #device = self.mud_dev_list.get_selected_row()
        self.mud_device = self.mud_dev_list.get( self.mud_dev_list.selection() )
        print("device:",self.mud_device)
        #ignored_dev = self.mud_device[4]
        #self.dev_mac = self.mud_device[3]
        self.dev_mac = self.mud_device[4]
        self.deviceID = self.mud_device[0]
        print("self.dev_mac:")
        print("\t",self.dev_mac)
        print("self.deviceID:")
        print("\t",self.deviceID)

        

        #if (ignored_dev == '--'):
        if self.dev_mac == None or self.deviceID==None or self.deviceID==0:
            print("Returning from gate selection early")
            return

        # Get and insert all captures currently added to database
        #self.db_handler.db.select_devices_imported_ignore({'ignored_dev':self.dev_mac})
        self.db_handler.db.select_devices_imported_ignore({'ignored_deviceID':self.deviceID})

        for (id, mfr, model, mac, internalName, category, ipv4, ipv6) in self.db_handler.db.cursor:
            self.mud_gate_list.append((id, internalName, mfr, model, category, mac, ipv4, ipv6))
            #self.mud_gate_list.append(internalName + ' | ' + mac)
            #print("\t" + internalName + ' | ' + mac)
        # Set focus on the first element

        self.mud_gate_list.focus(0)
        self.mud_gate_list.selection_set(0)

        self.populate_mud_pcap_list()#'--','--')



    def populate_mud_pcap_list(self, event=None):#, device=None, gateway=None):
        print("Populating MUD PCAP list")

        # clear previous list
        self.mud_pcap_list.clear()
        

        self.mud_device = self.mud_dev_list.get( self.mud_dev_list.selection() )
        #self.dev_mac = self.mud_device[3]
        self.dev_mac = self.mud_device[4]
        self.deviceID = self.mud_device[0]

        self.mud_gateway = self.mud_gate_list.get( self.mud_gate_list.selection() )
        #self.gateway_mac = self.mud_gateway[4]
        self.gateway_mac = self.mud_gateway[5]
        self.gatewayID = self.mud_gateway[0]

        print("device:",self.dev_mac)
        print("deviceID:",self.deviceID)
        print("gateway:",self.gateway_mac)
        print("gatewayID:",self.gatewayID)

        #if self.dev_mac == None or self.gateway_mac == None:
        if self.deviceID == None or self.deviceID == 0 or self.gatewayID == None or self.gatewayID == 0:
            print("Returning from mud pcap selection early")
            return
        self.mud_pcap_list.append((0, "All..."))

        # Get and insert all captures currently added to database
        #self.db_handler.db.select_imported_captures_with(dev='', gate='')
        #self.db_handler.db.select_imported_captures_with({"dev_mac":self.dev_mac, "gateway_mac":self.gateway_mac})
        self.db_handler.db.select_imported_captures_with({"deviceID":self.deviceID, "gatewayID":self.gatewayID})

        for (id, fileName, fileLoc, fileHash, capDate, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in self.db_handler.db.cursor:
            self.mud_pcap_list.append((id, capDate, fileName, deviceAction, duration, details, fileLoc)) #for early stages

        #for (id, fileName, fileLoc, fileHash, capDate, duration, activity, details) in self.db_handler.db.cursor:
        #    self.mud_pcap_list.append((capDate, fileName, activity, duration, details, fileLoc)) #for early stages
        
        # Set focus on the first element
        self.mud_pcap_list.focus(0)
        self.mud_pcap_list.selection_set(0)







    ## OLD ATTEMPT ##
    '''
    def generate_MUD_wizard_dropdown(self):
        #print("You shouldn't have gotten to the generate MUD wizard yet")

        self.w_gen_mud = tk.Toplevel()
        self.w_gen_mud.wm_title('Generate MUD File Wizard')

        # Prompt for selecting the device
        self.row_dev = tk.Frame(self.w_gen_mud)
        self.row_dev.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        dev_select_label = tk.Label(self.row_dev, width=20, text="Select the device to profile:", anchor='w')
        dev_select_label.pack(side=tk.LEFT)

        # Prompt for selecting the gateway
        self.row_gate = tk.Frame(self.w_gen_mud)
        self.row_gate.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        gate_select_label = tk.Label(self.row_gate, width=20, text="Select the network gateway:", anchor='w')
        gate_select_label.pack(side=tk.LEFT)

        

        self.mud_gate_list = ['--']
        self.mud_gate_var = tk.StringVar(self.w_gen_mud)
        self.mud_gate_var.set(self.mud_gate_list[0])


        #Device
        self.populate_mud_dev_list()

        self.mud_dev_var = tk.StringVar(self.w_gen_mud)
        self.mud_dev_var.set(self.mud_dev_list[0])

        #row_dropdown_device = tk.Frame(self.w_gen_mud)
        #row_dropdown_device.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)


        #dev_select_dropdown = tk.OptionMenu(row_dropdown_device, mud_dev_var, *self.mud_dev_list)
        self.dev_select_dropdown = tk.OptionMenu(self.row_dev, self.mud_dev_var, *self.mud_dev_list)
        self.dev_select_dropdown.pack(side=tk.LEFT)



        #Gateway

        #self.populate_mud_gate_list()

        #self.mud_gate_var = tk.StringVar(self.w_gen_mud)
        #self.mud_gate_var.set(self.mud_gate_list[0])

        #gate_select_dropdown = tk.OptionMenu(row_gate, mud_gate_var, *self.mud_gate_list)
        #gate_select_dropdown.pack(side=tk.LEFT)


        def change_dev(*args):
            print("Device Changed")
            print(self.mud_dev_var.get())
            self.populate_mud_gate_list(ignored_dev=self.mud_dev_var.get().split(' | ')[-1])
            print("Mac =", self.mud_dev_var.get().split(' | ')[-1])

            #mud_gate_var = tk.StringVar(self.w_gen_mud)
            #mud_gate_var.set(self.mud_dev_list[0])

            #gate_select_dropdown = tk.OptionMenu(row_gate, mud_gate_var, *self.mud_gate_list)
            #gate_select_dropdown.pack(side=tk.LEFT)

        self.mud_dev_var.trace('w', change_dev)

        def change_gate(*args):
            print(self.mud_gate_var.get())
            self.populate_mud_pcap_list(self.mud_dev_var.get().split(' | ')[-1],
                                        self.mud_gate_var.get().split(' | ')[-1])

        self.mud_gate_var.trace('w', change_gate)

    '''

    '''
        list_row = tk.Frame(self.w_gen_mud)
        list_row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.mud_dev_header = ["Manufacturer", "Model", "Internal Name", "Category", "MAC"]#, "IPv4", "IPv6"]
        #self.mud_dev_list = MultiColumnListbox(parent=self.mudDevFrame,
        self.mud_dev_list = MultiColumnListbox(parent=list_row,
                                                   header=self.mud_dev_header,
                                                   list=list(), selectmode="browse")
        self.mud_dev_list.bind("<<TreeviewSelect>>", self.update_mud_device_selection)

        #self.w_gen_mud.bind('<Return>', (lambda event, n=internalName, m=mac: self.select_mud_dev(n, m)))
        self.w_gen_mud.bind('<Return>', (lambda event : self.select_mud_dev()))
        
    '''

    '''
        b_select = tk.Button(self.w_gen_mud, text='Select',
                             #command=(lambda n=internalName, m=mac: self.select_mud_dev(n, m)))
                             command=(self.select_mud_dev()))

        b_cancel = tk.Button(self.w_gen_mud, text='Cancel', command=self.w_gen_mud.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_select.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_select.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        #self.populate_mud_dev_list()

        self.yield_focus(self.w_gen_mud)






    def update_mud_device_selection():
        print("update_mud_device_selection")
        self.mud_dev = {name:"internalName", mac:"mac"}
    '''
    '''
    def populate_mud_dev_list(self):
        # clear previous list
        self.mud_dev_list.clear()

        # Get and insert all captures currently added to database
        self.db_handler.db.select_devices_imported()

        for (id, mfr, model, mac, internalName, category) in self.db_handler.db.cursor:
            self.mud_dev_list.append((mfr, model, internalName, category, mac))
        
        # Set focus on the first element
        #self.mud_dev_list.focus(0)
        #self.mud_dev_list.selection_set(0)
    '''
    '''
    def populate_mud_dev_list_dropdown(self):
        self.mud_dev_list = ['--']

        # Get and insert all captures currently added to database
        self.db_handler.db.select_devices_imported()

        for (id, mfr, model, mac, internalName, category) in self.db_handler.db.cursor:
            #self.mud_dev_list.append((mfr, model, internalName, category, mac))
            self.mud_dev_list.append(internalName + ' | ' + mac)

        self.gate_select_dropdown = tk.OptionMenu(self.row_gate, self.mud_gate_var, *self.mud_gate_list)
        self.gate_select_dropdown.pack(side=tk.LEFT)
    '''

    '''
    def populate_mud_gateway_list(self):
        # clear previous list
        self.mud_gateway_list.clear()

        # Get and insert all captures currently added to database
        self.db_handler.db.select_all_local_devices(ignore='')

        for (id, mfr, model, internalName, category, mac) in self.db_handler.db.cursor:
            self.mud_gateway_list.append((mfr, model, internalName, category, mac))
        
        # Set focus on the first element
        self.mud_gateway_list.focus(0)
        self.mud_gateway_list.selection_set(0)

    '''
    '''
    def populate_mud_gate_list_dropdown(self, ignored_dev = '--'):
        print("Populating mud gate list")
        self.mud_gate_list = ['--']
        
        if (ignored_dev == '--'):
            print("Ignored device:", ignored_dev)
            print("Returning")
            return

        # Get and insert all captures currently added to database
        self.db_handler.db.select_devices_imported_ignore({'ignored_dev':ignored_dev})

        for (id, mfr, model, internalName, category, mac) in self.db_handler.db.cursor:
            #self.mud_gateway_list.append((mfr, model, internalName, category, mac))
            self.mud_gate_list.append(internalName + ' | ' + mac)
            print("\t" + internalName + ' | ' + mac)


    def populate_mud_pcap_list_dropdown(self, device, gateway):
        # clear previous list
        self.mud_pcap_list.clear()
        self.mud_dev_list.append(("All...",))

        # Get and insert all captures currently added to database
        self.db_handler.db.select_imported_captures_with(dev='', gateway='')

        for (id, fileName, fileLoc, fileHash, capDate, activity, details) in self.db_handler.db.cursor:
            self.cap_list.append((capDate, fileName, activity, details, fileLoc)) #for early stages
        
        # Set focus on the first element
        self.cap_list.focus(0)
        self.cap_list.selection_set(0)
    '''

        

    def generate_report_wizard(self):
        self.w_gen_report = tk.Toplevel()
        self.w_gen_report.wm_title('Generate Device Report Wizard')


        #Frames for Device, Gateway, and PCAPs
        self.topReportDevFrame = tk.Frame(self.w_gen_report, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        self.botReportPCAPFrame = tk.Frame(self.w_gen_report, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")


        ## Top Device Frame
        # Title
        self.report_dev_title_var=tk.StringVar()
        self.report_dev_title_var.set("Device to Profile:")
        self.report_dev_title = tk.Label(self.topReportDevFrame, textvariable=self.report_dev_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.report_dev_title.pack(side="top", fill=tk.X)

        # Listbox
        self.report_dev_header = ["id","Internal Name", "Manufacturer", "Model", "MAC Address", "Category"]
        self.report_dev_list = MultiColumnListbox(parent=self.topReportDevFrame,
                                               header=self.report_dev_header,
                                               list=list(), keep1st=True,
                                               exclusionList=["id"])
        self.report_dev_list.bind("<<TreeviewSelect>>", self.populate_report_pcap_list)



        ## Bot PCAP Frame
        # Title
        self.report_pcap_title_var=tk.StringVar()
        self.report_pcap_title_var.set("Select Packet Captures (PCAPs):")
        self.report_pcap_title = tk.Label(self.botReportPCAPFrame, textvariable=self.report_pcap_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.report_pcap_title.pack(side="top", fill=tk.X)

        # Listbox
        self.report_pcap_header = ["id","Date","Capture Name","Activity", "Duration (seconds)", "Details", "Capture File Location", "ID"]
        #self.report_pcap_header = ["Date","Capture Name","Activity", "Details", "Capture File Location", "ID"]
        self.report_pcap_list = MultiColumnListbox(parent=self.botReportPCAPFrame,
                                                header=self.report_pcap_header,
                                                list=list(), keep1st=True,
                                                exclusionList=["id"])
        self.report_pcap_list.bind("<<TreeviewSelect>>", self.select_report_pcaps)



        # Grid placements #
        self.topReportDevFrame.grid(row=0, column=0, sticky="nsew")
        self.botReportPCAPFrame.grid(row=1, column=0, sticky="nsew")

        self.w_gen_report.grid_rowconfigure(0, weight=1)
        self.w_gen_report.grid_rowconfigure(1, weight=1)


        ## Buttons
        self.b_report_generate = tk.Button(self.botReportPCAPFrame, text='Generate', state='disabled',
                                        command=(self.generate_report))

        self.b_report_close = tk.Button(self.botReportPCAPFrame, text='Close', command=self.w_gen_report.destroy)

        if sys.platform == "win32":
            self.b_report_close.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_report_generate.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_report_generate.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_report_close.pack(side=tk.RIGHT, padx=5, pady=5)


        self.populate_report_dev_list()


        # Select first element of each list
        # Try because the list might be empty
        self.report_dev_list.focus(0)
        self.report_dev_list.selection_set(0)
        self.report_pcap_list.focus(0)
        self.report_pcap_list.selection_set(0)

        self.yield_focus(self.w_gen_report)


    def populate_report_dev_list(self):
        # Get and insert all captures currently added to database
        self.report_dev_list.clear()
        self.report_dev_list.append((0, "All..."))

        print("Populating Report Device List")

        self.db_handler.db.select_devices_imported()
        for (id, mfr, model, mac, internalName, category) in self.db_handler.db.cursor:
            self.report_dev_list.append((id, internalName, mfr, model, mac, category))


    def populate_report_pcap_list(self, event=None): #unknown if need "event"
        print("Populating Report PCAP list")

        # clear previous list
        self.report_pcap_list.clear()
        

        self.report_device = self.report_dev_list.get( self.report_dev_list.selection() )
        try:
            #self.dev_mac = self.report_device[3]
            self.dev_mac = self.report_device[4]
            self.deviceID = self.report_device[0]
        except:
            self.dev_mac = None
            self.deviceID = None

        print("device:",self.dev_mac)
        print("deviceID:",self.deviceID)

        #if self.dev_mac == None:
        #    print("Returning from report pcap selection early")
        #    return
        self.report_pcap_list.append(("All...",))

        # Get and insert all captures currently added to database
        #print("self.report_device[0] == 'All...':", self.report_device[0] == "All...")

        #if self.report_device[0] == "All...":
        if self.report_device[1] == "All...":
            print("all devices selected")
            self.db_handler.db.select_imported_captures()
        else:
            #self.db_handler.db.select_imported_captures_with_device({"dev_mac":self.dev_mac})
            self.db_handler.db.select_imported_captures_with_device({"deviceID":self.deviceID})

        for (id, fileName, fileLoc, fileHash, capDate, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in self.db_handler.db.cursor:
            #self.report_pcap_list.append((capDate, fileName, activity, duration, details, fileLoc, id)) #for early stages
            self.report_pcap_list.append((id, capDate, fileName, deviceAction, duration, details, fileLoc, id)) #for early stages
        #for (id, fileName, fileLoc, fileHash, capDate, duration, activity, details) in self.db_handler.db.cursor:
        #    self.report_pcap_list.append((capDate, fileName, activity, duration, details, fileLoc, id)) #for early stages


        #for (id, fileName, fileLoc, fileHash, capDate, activity, details) in self.db_handler.db.cursor:
        #    self.report_pcap_list.append((capDate, fileName, activity, details, fileLoc, id)) #for early stages
        
        # Set focus on the first element
        self.report_pcap_list.focus(0)
        self.report_pcap_list.selection_set(0)


    def select_report_pcaps(self, event):
        print("Select Report pcaps")
        #self.report_pcap_sel = []
        self.report_pcap_where = ' '

        print("report_pcap_list.selection():",self.report_pcap_list.selection())

        first = True

        for pcap_item in self.report_pcap_list.selection():
            pcap = self.report_pcap_list.get( pcap_item )
            print("pcap:",pcap)

            if pcap[0] != "All...":
                if first:
                    self.report_pcap_where = " WHERE c.id = %s" % pcap[6]
                    first = False
                else:
                    self.report_pcap_where += " OR c.id = %s" % pcap[6]
                    
        self.report_pcap_where += ';'

        print("self.report_pcap_where:",self.report_pcap_where)

        self.b_report_generate.config(state='normal')


    def generate_report(self):
        print("Preparing to generate report file")
        #self.report_gen_obj = ReportGenerator()


        for dev_item in self.report_dev_list.selection():
            dev = self.report_dev_list.get( dev_item )
            
            #if dev[0] == "All...":
            if dev[1] == "All...":
                print("All selected")
                self.db_handler.db.select_devices_imported()
                devs_imported = self.db_handler.db.cursor.fetchall()
                #for (id, mfr, model, mac, internalName, category) in self.db_handler.db.cursor:
                for (deviceID, mfr, model, mac, internalName, category) in devs_imported:
                    self.report_gen_obj = ReportGenerator({'name':internalName, 'mac':mac})

                    # Write to file
                    self.report_gen_obj.write_header()

                    #self.db_handler.db.select_caps_with_device_where({'mac_addr':mac}, conditions=self.report_pcap_where)
                    self.db_handler.db.select_caps_with_device_where({'deviceID':deviceID}, conditions=self.report_pcap_where)
                    pcap_info = self.db_handler.db.cursor.fetchall()
                    print("len(pcap_info)",len(pcap_info))

                    capture_info = {} #;lkj;lkj;lkj
                    #Need to add end_time and duration information to database
                    #for (cap_id, filename, sha256, activity, start_time, duration, details) in pcap_info:
                    for (captureID, fileName, fileLoc, fileHash, start_time, capDuration, lifecyclePhase,
                         internet, humanInteraction, preferredDNS, isolated, durationBased,
                         duration, actionBased, deviceAction, details) in pcap_info:
                        capture_info = {'filename'         : fileName,
                                        'sha256'           : fileHash,
                                        #'activity'         : activity,
                                        #'modifiers' : modifiers,
                                        'phase'            : field2db.inverse[lifecyclePhase][0],
                                        'internet'         : internet,
                                        'humanInteraction' : humanInteraction,
                                        'preferredDNS'     : preferredDNS,
                                        'isolated'         : isolated,
                                        'actionBased'      : actionBased,
                                        'deviceAction'     : deviceAction,
                                        'durationBased'    : durationBased, 
                                        'duration'         : duration,
                                        'capDuration'      : capDuration,
                                        'start_time'       : start_time,
                                        'end_time'         : start_time + timedelta(seconds=int(capDuration)),
                                        'details'          : details}

                        capture_info['other_devices'] = []
                        #self.db_handler.db.select_devices_in_caps_except({"cap_id":cap_id, "mac_addr":mac})
                        self.db_handler.db.select_devices_in_caps_except({"captureID":captureID, "deviceID":deviceID})
                        for (id, internalName, mac) in self.db_handler.db.cursor:
                            capture_info['other_devices'].append({'name': internalName, 'mac' : mac})

                        # Append capture information
                        self.report_gen_obj.write_capture_info(capture_info)
                break

            else:
                #print("Generating report for one device:\t%s" % dev[0])
                #self.report_gen_obj = ReportGenerator({'name':dev[0], 'mac':dev[3]})
                print("Generating report for one device:\t%s" % dev[1])
                self.report_gen_obj = ReportGenerator({'name':dev[1], 'mac':dev[4]})

                # Write header to file
                self.report_gen_obj.write_header()

                #self.db_handler.db.select_caps_with_device_where({'mac_addr':dev[3]}, conditions=self.report_pcap_where)
                #self.db_handler.db.select_caps_with_device_where({'mac_addr':dev[4]}, conditions=self.report_pcap_where)
                self.db_handler.db.select_caps_with_device_where({'deviceID':dev[0]}, conditions=self.report_pcap_where)
                pcap_info = self.db_handler.db.cursor.fetchall()
                
                capture_info = {}
                #for (cap_id, filename, sha256, activity, start_time, duration, details) in pcap_info:
                for (captureID, fileName, fileLoc, fileHash, start_time, capDuration, lifecyclePhase,
                     internet, humanInteraction, preferredDNS, isolated, durationBased,
                     duration, actionBased, deviceAction, details) in pcap_info:

                    capture_info = {'filename'         : fileName,
                                    'sha256'           : fileHash,
                                    #'activity'         : activity,
                                    #'modifiers' : modifiers,
                                    'phase'            : field2db.inverse[lifecyclePhase][0],
                                    'internet'         : internet,
                                    'humanInteraction' : humanInteraction,
                                    'preferredDNS'     : preferredDNS,
                                    'isolated'         : isolated,
                                    'actionBased'      : actionBased,
                                    'deviceAction'     : deviceAction,
                                    'durationBased'    : durationBased, 
                                    'duration'         : duration,
                                    'capDuration'      : capDuration,
                                    'start_time'       : start_time,
                                    'end_time'         : start_time + timedelta(seconds=int(capDuration)),
                                    'details'          : details}
                    '''
                    capture_info = {'filename'  : filename,
                                    'sha256'    : sha256,
                                    'activity'  : activity,
                                    #'modifiers' : modifiers,
                                    'start_time': start_time,
                                    'end_time'  : start_time + timedelta(seconds=int(duration)),
                                    'capDuration'  : duration,
                                    'details'   : details}
                    '''
                    capture_info['other_devices'] = []
                    #self.db_handler.db.select_devices_in_caps_except({"cap_id":cap_id, "mac_addr":dev[3]})
                    #self.db_handler.db.select_devices_in_caps_except({"cap_id":cap_id, "mac_addr":dev[4]})
                    self.db_handler.db.select_devices_in_caps_except({"captureID":captureID, "deviceID":dev[0]})
                    for (id, internalName, mac) in self.db_handler.db.cursor:
                        capture_info['other_devices'].append({'name': internalName, 'mac' : mac})

                    # Append capture information
                    self.report_gen_obj.write_capture_info(capture_info)

        messagebox.showinfo("Report Generation Complete", "The generated reports are in the 'reports' directory.")
















    def popup_about(self):
        self.w_about = tk.Toplevel()
        self.w_about.wm_title("About")

        summaryFrame = tk.Frame(self.w_about)
        summary = tk.Message(summaryFrame,
                           text="This is a proof of concept for evaluating network traffic " +
                           "for use in auditing the network, generating MUD files, and " +
                           "identifying various privacy concerns.\n\n" +
                           "This is a work in progress.", width=500)

        summaryFrame.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        summary.pack(side="left")

        srcFrame = tk.Frame(self.w_about)
        sources = tk.Message(srcFrame, text="Icons used under Creative Commons BY 3.0 License:\n" +
                           "CC 3.0 BY Flaticon: www.flaticon.com is licensed by " +
                           "http://creativecommons.org/licenses/by/3.0/ " +
                           "Icons made by https://www.flaticon.com/authors/smashicons\n" +
                           "Icons made by Kirill Kazachek", width=500)
        srcFrame.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        sources.pack(side="left")

        closeFrame = tk.Frame(self.w_about)
        b_close = tk.Button(closeFrame, text="Close", command=self.w_about.destroy)
        closeFrame.pack(side="top", fill="x", padx=5, pady=2, expand=True)
        b_close.pack(side="bottom", padx=5, pady=5)

        self.yield_focus(self.w_about)

    def __exit__(self):
        try:
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

    def save_db_config(self, filename='config.ini', section='mysql', save_pwd=False):
        f = open(filename, "w")
        f.write("[%s]" % section)

        for key in self.db_config:
            if save_pwd or key != "passwd":
                f.write("\n%s = %s" % (key, self.db_config[key]))
            else:
                f.write("\n%s = " % key)

        f.write("\n")
        f.close()
        
    def db_connect(self, entries):
        self.db_config = {}

        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            #print(field, " = ", text)
            self.db_config[field] = text

        try:
            self.db = CaptureDatabase(self.db_config)
        except:
            self.connected = False
        else:
            self.connected = True

    def __exit__(self):
        self.db.__exit__()


'''
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
'''

if __name__ == '__main__':
    root = tk.Tk()
    gui = MudCaptureApplication(root)
    root.mainloop()

