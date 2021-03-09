#!/usr/bin/python3

# Local Modules
# import _mysql_connector

from src.bidict import BiDict
from src.capture_database import CaptureDatabase
# from capture_database import DatabaseHandler
from src.capture_database import CaptureDigest
from src.lookup import lookup_mac  # , lookup_hostname
from src.generate_mudfile import MUDgeeWrapper
from src.generate_report import ReportGenerator
from src.multicolumn_listbox import MultiColumnListbox
from src.scrollable_frame import ScrollableFrame
import src.pcapng_comment as capMeta

from muddy.muddy.maker import make_mud, make_acl_names, make_policy, make_ace, make_acls, make_support_info
from muddy.muddy.models import Direction, IPVersion, Protocol, MatchType

import os
import random
from IPy import IP
import socket
import json

# External Modules
# import concurrent
from datetime import datetime
from datetime import timedelta
import hashlib
from functools import partial
# import math
import multiprocessing as mp
# from multiprocessing import Process, Queue
import mysql.connector
from mysql.connector import errorcode
# import pyshark
# import subprocess
import re
import sys
import time
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
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
# deviceField2Var = {'Model' : 'model', 'Internal Name' : 'internalName',
# 'Device Category' : 'deviceCategory', 'Communication Standards', 'Notes': 'notes'}
# deviceOptions = 'WiFi', 'Bluetooth', 'Zigbee', 'ZWave', '4G', '5G', 'Other'
deviceOptions = 'MUD', 'WiFi', 'Ethernet', 'Bluetooth', 'Zigbee', 'ZWave', '3G', '4G', '5G', 'Other'
# deviceOptions2Var = {'WiFi' : 'wifi', 'Bluetooth' : 'bluetooth', 'Zigbee' : 'zigbee',
# 'ZWave' : 'zwave', '4G' : '4G', '5G' : '5G', 'Other', 'other'}


# GUI Class for the MUD Capture Analysis
class MudCaptureApplication(tk.Frame):

    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.parent.title("MUD-PD")
        self.api_key = self.read_api_config()
        if self.api_key != "":
            #self.api_key = self.api_key['api_key']
            print("Fingerbank API Key: ", self.api_key)
        self.window_stack = []
        self.yield_focus(self.parent)

        self.test = "testing"

        # Multiprocessing
        self.p_file = None
        #self.p_list = list()
        #nself.p_count = 0
        self.m = mp.Manager()
        self.q = self.m.Queue()
        #self.event = self.Event()
        self.filename_prev = ""

        # ** Initialize class variables ** #
        # TODO: Handle these variables better
        # Future windows (i.e. set self.w_XXXX objects to None
        self.w_about = None
        self.w_cap = None
        self.w_cap_dev = None
        self.w_db = None
        self.w_db_new = None
        self.w_dev = None
        self.w_dev_state = None
        self.w_gen_mud = None
        self.w_gen_report = None

        # Buttons for future windows
        self.b_cap_dev_close = None
        self.b_cap_dev_import = None
        self.b_cap_dev_modify = None
        self.b_import = None
        self.b_cancel = None
        self.b_mud_generate = None
        self.b_mud_cancel = None
        self.b_report_generate = None
        self.b_report_close = None

        # General Variables
        # TODO: Turn all XXXX_entries into dictionary types rather than lists
        self.db_handler = None
        self.db_cnx_entries = None
        self.api_key_entries = None
        self.capture_entries = None
        self.cap_envi_metadata = None
        self.device_entries = None
        self.device_state_entries = None
        self.capture_devices_entries = None
        self.dev_in_cap_data = None
        self.dev_mac = None
        self.labeled_title = None
        self.labeled_title_var = None
        self.labeled_dev_header = None
        self.labeled_dev_list = None
        self.labeled_dev_list_sel = None
        self.labeledDevFrame = None
        self.unlabeled_title = None
        self.unlabeled_title_var = None
        self.unlabeled_dev_header = None
        self.unlabeled_dev_list = None
        self.unlabeled_dev_list_sel = None
        self.unlabeledDevFrame = None
        self.cap_dev_title = None
        self.topDevFrame = None
        self.botDevFrame = None
        self.device_id = None
        self.gatewayID = None
        self.gateway_mac = None
        self.topMudDevFrame = None
        self.midMudGateFrame = None
        self.botMudPCAPFrame = None
        self.mud_gateway = None
        self.mud_device = None
        self.mud_dev_title_var = None
        self.mud_dev_title = None
        self.mud_dev_header = None
        self.mud_dev_list = None
        self.mud_gate_title_var = None
        self.mud_gate_title = None
        self.mud_gate_header = None
        self.mud_gate_list = None
        self.mud_pcap_title_var = None
        self.mud_pcap_title = None
        self.mud_pcap_header = None
        self.mud_pcap_list = None
        self.mud_pcap_sel = None
        self.mud_gen_obj = None
        self.topReportDevFrame = None
        self.botReportPCAPFrame = None
        self.report_device = None
        self.report_dev_title_var = None
        self.report_dev_title = None
        self.report_dev_header = None
        self.report_dev_list = None
        self.report_pcap_title_var = None
        self.report_pcap_title = None
        self.report_pcap_header = None
        self.report_pcap_list = None
        self.report_gen_obj = None
        self.report_pcap_where = None

        # Main menu bar
        self.fileMenu = tk.Menu(self.parent)
        self.parent.config(menu=self.fileMenu)
        self.fileSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="File", menu=self.fileSubMenu)
        self.fileSubMenu.add_command(label="Connect to Database...", command=self.popup_connect2database)
        self.fileSubMenu.add_command(label="Create New Database...", command=self.popup_create_new_database)
        self.fileSubMenu.add_command(label="Import Capture File...", command=self.popup_import_capture)
        self.fileSubMenu.add_command(label="Add Fingerbank API Key", command=self.popup_update_api_key)
        self.fileSubMenu.add_command(label="Update Labeled Device Info", command=self.popup_update_labeled_device_info)
        self.fileSubMenu.add_separator()
        self.fileSubMenu.add_command(label="Quit", command=self.__exit__)

        self.helpSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="Help", menu=self.helpSubMenu)
        self.helpSubMenu.add_command(label="About", command=self.popup_about)

        # *** Main Window *** #
        # Menu top
        self.menuFrame = tk.Frame(self.parent, bd=1, bg="#dfdfdf")  # , bg="#dfdfdf"

        icon_db_connect = tk.PhotoImage(file="data/icons/database_connect40px.png")
        self.b_main_db_connect = tk.Button(self.menuFrame, compound="top", image=icon_db_connect, width="40",
                                           height="40", command=self.popup_connect2database, highlightthickness=0,
                                           activebackground="black", bd=0)
        self.b_main_db_connect.image = icon_db_connect
        self.b_main_db_connect.pack(side="left")

        icon_db_new = tk.PhotoImage(file="data/icons/database_new40px.png")
        self.b_main_db_new = tk.Button(self.menuFrame, compound="top", image=icon_db_new, width="40", height="40",
                                       command=self.popup_create_new_database, highlightthickness=0,
                                       activebackground="black", bd=0)
        self.b_main_db_new.image = icon_db_new
        self.b_main_db_new.pack(side="left")

        icon_import = tk.PhotoImage(file="data/icons/import40px.png")
        self.b_main_import = tk.Button(self.menuFrame, compound="top", state='disabled', image=icon_import, width="40",
                                       height="40", command=self.popup_import_capture, highlightthickness=0,
                                       activebackground="black", bd=0)
        self.b_main_import.image = icon_import
        self.b_main_import.pack(side="left")

        self.b_main_generate_MUD = tk.Button(self.menuFrame,
                                             text="Generate MUD File",
                                             wraplength=80,
                                             state='disabled',
                                             command=self.popup_generate_mud_wizard)  # , anchor=tk.N+tk.W)
        self.b_main_generate_MUD.pack(side="left")

        self.b_main_generate_report = tk.Button(self.menuFrame,
                                                text="Generate Report",
                                                wraplength=80,
                                                state="disabled",
                                                command=self.generate_report_wizard)  # , anchor=tk.N+tk.W)
        self.b_main_generate_report.pack(side="left")

        #start_muddy = MUDWizard()

        #self.b_MUDdy = tk.Button(self.menuFrame, text="MUDdy", command=lambda: start_muddy.mainloop())
        self.b_MUDdy = tk.Button(self.menuFrame,
                                 text="MUDdy",
                                 state="disabled",
                                 command=lambda p=self: MUDWizard(parent=p))
        self.b_MUDdy.pack(side="left")

        # *** Left (capture) frame *** #
        self.capFrame = tk.Frame(self.parent, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        # title
        self.cap_title_var = tk.StringVar()
        self.cap_title_var.set("Captures")
        self.cap_title = tk.Label(self.capFrame, textvariable=self.cap_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.cap_title.pack(side="top", fill=tk.X)

        # capture list
        self.cap_header = ["id", "Date", "Capture Name", "Activity", "Duration", "Details", "Capture File Location"]
        # self.cap_header = ["Date","Capture Name","Activity", "Details","Capture File Location"]
        self.cap_list = MultiColumnListbox(parent=self.capFrame, header=self.cap_header, input_list=list(),
                                           keep_first=True, exclusion_list=["id"])
        # self.cap_list.bind("<<ListboxSelect>>", self.update_dev_list)
        self.cap_list.bind("<<TreeviewSelect>>", self.update_dev_list)
        '''
        self.cap_list.bind("<Double-Button-1>>", (lambda idx=0, hd0=4, hd1=1
                                                  : self.popup_import_capture_devices(
                    CaptureDigest(self.cap_list.get(self.cap_list.selection()[idx])[hd0] + "/" + 
                                  self.cap_list.get(self.cap_list.selection()[idx])[hd1]))))
        '''

        # (lambda d=unknown_dev_list.curselection(): self.popup_import_device(d)))
        self.b_main_inspect = tk.Button(self.capFrame, text="Inspect",
                                        # command=(lambda c=CaptureDigest((lambda x=None, idx=0, hd0=4, hd1=1
                                        # : self.cap_list.selection(x)[idx].get(self.cap_header[hd0]) +
                                        # self.cap_list.selection(x)[idx].get(self.cap_header[hd1])))
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

        # *** Right Frame *** #
        self.rightFrame = tk.Frame(self.parent, width=500, bd=1, bg="#dfdfdf")

        # ** Top Right (device) frame  ** #
        self.devFrame = tk.Frame(self.rightFrame, width=500)  # , bd=1, bg="#eeeeee")

        # title
        self.dev_title_var = tk.StringVar()
        self.dev_title_var.set("Devices")
        self.dev_title = tk.Label(self.devFrame, textvariable=self.dev_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.dev_title.pack(fill=tk.X)

        # device list
        self.dev_header = ["id", "Manufacturer", "Model", "Internal Name", "MAC", "Category"]
        self.dev_list = MultiColumnListbox(parent=self.devFrame, header=self.dev_header, input_list=list(),
                                           keep_first=True, exclusion_list=["id"])
        # self.dev_list.bind("<<ListboxSelect>>", self.update_comm_list)
        self.dev_list.bind("<<TreeviewSelect>>", self.update_comm_list)

        self.devFrame.pack(side="top", fill="both", expand=True)

        # ** Bottom Right (communication) frame ** #
        self.commFrame = tk.Frame(self.rightFrame, width=500, bd=1, bg="#eeeeee")

        # title
        self.comm_title_var = tk.StringVar()
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
                            # "Destination Port", "Length", "Direction", "Raw"] #Direction being NS or EW
                            # "Destination Port", "Length", "Raw"] #Direction being NS or EW
                            "Destination Port", "Length"]  # Direction being NS or EW
        self.comm_list = MultiColumnListbox(parent=self.commFrame, header=self.comm_header, input_list=list(),
                                            exclusion_list=["id", "fileID"])  # , keep1st=True)
        # self.comm_list.bind("<<ListboxSelect>>", self.update_comm_list)

        '''
        self.comm_list = tk.Listbox(self.commFrame, yscrollcommand = self.comm_scrollbar.set, 
                                    selectmode="extended", exportselection=0, bd=0)

        self.comm_list.pack(side="left", fill="both", expand=True)
        self.comm_scrollbar.config( command = self.comm_list.yview )
        '''

        # To be added once packets have been added to the table
        self.comm_state = "any"
        self.b_ns = tk.Button(self.commFrame, text="N/S", command=(lambda s="ns": self.modify_comm_state(s)))
        self.b_ew = tk.Button(self.commFrame, text="E/W", command=(lambda s="ew": self.modify_comm_state(s)))

        self.comm_dev_restriction = "none"
        self.b_between = tk.Button(self.commFrame, text="Between",
                                   command=(lambda r="between": self.modify_comm_dev_restriction(r)))
        self.b_either = tk.Button(self.commFrame, text="Either",
                                  command=(lambda r="either": self.modify_comm_dev_restriction(r)))

        self.b_pkt10 = tk.Button(self.commFrame, text="10", command=(lambda n=10: self.modify_comm_num_pkts(n)))
        self.b_pkt100 = tk.Button(self.commFrame, text="100", command=(lambda n=100: self.modify_comm_num_pkts(n)))
        self.b_pkt1000 = tk.Button(self.commFrame, text="1000", command=(lambda n=1000: self.modify_comm_num_pkts(n)))
        self.b_pkt10000 = tk.Button(self.commFrame, text="10000",
                                    command=(lambda n=10000: self.modify_comm_num_pkts(n)))

        self.b_ns.pack(side="left")
        self.b_ew.pack(side="left")
        self.b_between.pack(side="left")
        self.b_either.pack(side="left")

        self.b_pkt10000.pack(side="right")
        self.b_pkt1000.pack(side="right")
        self.b_pkt100.pack(side="right")
        self.b_pkt10.pack(side="right")

        self.comm_list_num_pkts = 100
        # self.b_pkt100.config(state='disabled')

        self.b_ns.config(state='disabled')
        self.b_ew.config(state='disabled')
        self.b_between.config(state='disabled')
        self.b_either.config(state='disabled')
        self.b_pkt10.config(state='disabled')
        self.b_pkt100.config(state='disabled')
        self.b_pkt1000.config(state='disabled')
        self.b_pkt10000.config(state='disabled')

        self.comm_list_all_pkts = []

        # self.b_internal.pack(side="right")

        self.commFrame.pack(side="top", fill="both", expand=True)

        # *** Status Bar *** #
        self.statusFrame = tk.Frame(self.parent)
        self.status_var = tk.StringVar()
        self.status_var.set("No database connected...")
        self.status = tk.Label(self.statusFrame, textvariable=self.status_var, bd=1, bg="#eeeeee", relief=tk.SUNKEN,
                               anchor=tk.W, padx=5)
        self.status.pack(fill="both", expand=True)

        # *** Grid Placement *** #
        self.menuFrame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.capFrame.grid(row=1, column=0, rowspan=2, sticky="nsew")
        self.rightFrame.grid(row=1, column=1, rowspan=2, sticky="nsew")
        self.statusFrame.grid(row=3, column=0, columnspan=2, sticky="ew")

        # Grid configuration #
        self.parent.grid_rowconfigure(1, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_columnconfigure(1, weight=3)

    def yield_focus(self, window=None):
        if len(self.window_stack) == 0:
            if window is None:
                print("Error with yielding focus")
            else:
                self.window_stack.append(window)
                self.yield_focus()
        elif window is None:
            self.window_stack[-1].focus_set()
            self.window_stack[-1].grab_set()
            if self.window_stack[-1] != self.parent:
                self.window_stack[-1].transient(self.parent)
            self.window_stack[-1].lift()
            self.window_stack[-1].attributes('-topmost', True)
            self.window_stack[-1].attributes('-topmost', False)
        elif self.window_stack[-1] != window:
            # Previously top window yield status
            self.window_stack[-1].attributes('-topmost', False)
            # self.window_stack[-1].focus_release()
            self.window_stack[-1].grab_release()

            # Push new window to the top of the stack
            self.window_stack.append(window)
            self.yield_focus()

            # Wait for window to close before yielding focus to next in stack
            self.window_stack[-2].wait_window(self.window_stack[-1])
            # self.window_stack[-1].focus_release()
            self.window_stack[-1].grab_release()
            self.window_stack.pop()
            self.yield_focus()

    def popup_connect2database(self):
        self.w_db = tk.Toplevel()
        self.w_db.wm_title("Connect to Database")

        self.make_form_database(dbFields)

        #self.bind('<Return>', (lambda event, e=ents: self.connect_and_close(e)))
        self.bind('<Return>', (lambda event: self.connect_and_close))

        b_connect = tk.Button(self.w_db, text='Connect',
                              #command=(lambda e=ents: self.connect_and_close(e)))
                              command=self.connect_and_close)
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
        #ents.append(("Save", checkvar))
        self.db_cnx_entries.append(("Save", checkvar))

        self.yield_focus(self.w_db)

    def make_form_database(self, fields):
        db_handler_temp = DatabaseHandler()
        # entries = list()
        self.db_cnx_entries = list()

        for field in fields:
            row = tk.Frame(self.w_db)
            lab = tk.Label(row, width=12, text=field, anchor='w')
            if field == "passwd":
                ent = tk.Entry(row, show="\u2022", width=15)
            else:
                ent = tk.Entry(row)
            ent.insert(10, db_handler_temp.config.get(field, "none"))

            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            lab.pack(side=tk.LEFT)
            ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
            # entries.append((field, ent))
            self.db_cnx_entries.append((field, ent))

        # return entries

    def popup_create_new_database(self):
        self.w_db_new = tk.Toplevel()
        self.w_db_new.wm_title("Create New Database")

        #ents = self.make_form_new_database(dbNewFields)
        self.make_form_new_database(dbNewFields)

        #self.bind('<Return>', (lambda event, e=ents, c=True: self.connect_and_close(e, create=c)))
        self.bind('<Return>', (lambda event, c=True: self.connect_and_close(create=c)))

        b_create = tk.Button(self.w_db_new, text='Create',
                             #command=(lambda e=ents, c=True: self.connect_and_close(e, create=c)))
                             command=(lambda c=True: self.connect_and_close(create=c)))
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
        #ents.append(("Save", checkvar))
        self.db_cnx_entries.append(("Save", checkvar))

        messagebox.showinfo("CREATING a New Database",
                            "You are CREATING a new database.\n\n"
                            "You will need to use the existing mysql server password.")

        self.yield_focus(self.w_db_new)

    def make_form_new_database(self, fields):
        db_handler_temp = DatabaseHandler()
        #entries = list()
        self.db_cnx_entries = list()

        for field in fields:
            row = tk.Frame(self.w_db_new)
            lab = tk.Label(row, width=12, text=field, anchor='w')
            if field == "passwd":
                ent = tk.Entry(row, show="\u2022", width=15)
                skip_line = True
            else:
                ent = tk.Entry(row)
                skip_line = False
            ent.insert(10, db_handler_temp.config.get(field, "none"))

            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            lab.pack(side=tk.LEFT)
            ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
            #entries.append((field, ent))
            self.db_cnx_entries.append((field, ent))

            if skip_line:
                xtra_row = tk.Frame(self.w_db_new)
                xtra_lab = tk.Label(xtra_row, width=12, text=' ', anchor='w')
                xtra_row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
                xtra_lab.pack(side=tk.LEFT)

        #return entries

    #def connect_and_close(self, entries, create=False):
    def connect_and_close(self, create=False):
        db_handler_temp = DatabaseHandler()
        #(save_name, save_var) = entries.pop()
        (save_name, save_var) = self.db_cnx_entries.pop()
        save_val = save_var.get()
        # print(save_name, " = ", save_var, " = ", save_val)

        if create:
            #(db_label, db_name) = entries.pop()
            (db_label, db_name) = self.db_cnx_entries.pop()
            db_name = db_name.get()
            #db_handler_temp.db_connect(entries)
            db_handler_temp.db_connect(self.db_cnx_entries)

            if not db_handler_temp.connected:
                tk.messagebox.showerror("Error Connecting to Database",
                                        "There was some error while connecting to the database.\n" +
                                        "Please check all the data fields and try again.")
                return

            try:
                db_handler_temp.db.init_new_database(db_name)
            except mysql.connector.Error as err:
                if err.errno == mysql.connector.errorcode.ER_DB_CREATE_EXISTS:  # 1007
                    print("Database already exists")

                    reinit = tk.messagebox.askyesno("Database Creation Error",
                                                    "Cannot create database '%s' because it already exists.\n\n"
                                                    % db_name + "Re-initialize the existing database?",
                                                    default='no')

                    if reinit:
                        confirm = tk.messagebox.askyesno("Overwrite Existing Database",
                                                         "Are you sure you want to overwrite the database '%s'?\n\n" %
                                                         db_name + "This action is IRREVERSIBLE and all existing data "
                                                                   "will be LOST!",
                                                         default='no')
                        if confirm:
                            db_handler_temp.db.reinit_database(db_name)
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
            # entries.append(('database', db_name))
        else:
            #db_handler_temp.db_connect(entries)
            db_handler_temp.db_connect(self.db_cnx_entries)
        # db_handler_temp.db_connect(entries)

        if db_handler_temp.connected:
            self.db_handler = db_handler_temp
            # self.status_var.set("Connected to " + self.db_handler.config.get("database", "none"))
            self.status_var.set("Connected to " + self.db_handler.db_config.get("database", "none"))
            self.populate_capture_list()
            if save_val:
                self.popup_confirm_save()

            if create:
                # messagebox.showinfo("Success!",
                #                     "Successfully created and connected to the new database '%s'" % db_name)
                self.w_db_new.destroy()
            else:
                # messagebox.showinfo("Success!","Successfully connected to the database")
                self.w_db.destroy()

            # Enable main menu buttons
            self.b_main_import.config(state='normal')
            self.b_main_generate_MUD.config(state='normal')
            self.b_main_generate_report.config(state='normal')
            self.b_MUDdy.config(state='normal')
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
            #entries.append((save_name, save_var))
            self.db_cnx_entries.append((save_name, save_var))

    def popup_update_labeled_device_info(self):
        try:
            self.db_handler.db.insert_protocol_device()
            messagebox.showinfo("Success!", "Labeled Device Info Updated")
        except AttributeError:
            messagebox.showinfo("Failure", "Please make sure you are connected to a database and try again")

    def make_form_api(self, fields):
        #entries = list()
        self.api_key_entries = list()
        row = tk.Frame(self.w_db_new)
        lab = tk.Label(row, width=12, text=fields, anchor='w')
        ent = tk.Entry(row)
        ent.insert(10, self.api_key)

        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
        lab.pack(side=tk.LEFT)
        ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
        #entries.append((fields, ent))
        self.api_key_entries.append((fields, ent))

        #return entries

    def popup_update_api_key(self):
        self.w_db_new = tk.Toplevel()
        self.w_db_new.wm_title("Update Fingerbank API Key")

        #ents = self.make_form_api(APIFields)
        self.make_form_api(APIFields)

        #self.bind('<Return>', (lambda event, e=ents: self.save_api_config(e)))
        self.bind('<Return>', (lambda event: self.save_api_config))

        b_save = tk.Button(self.w_db_new, text='Save',
                           #command=(lambda e=ents: self.save_api_config(e)))
                           command=self.save_api_config)
        b_cancel = tk.Button(self.w_db_new, text='Cancel', command=self.w_db_new.destroy)

        if sys.platform == "win32":
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            b_save.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_save.pack(side=tk.RIGHT, padx=5, pady=5)
            b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_db_new)

    #def save_api_config(self, entries, filename='config.ini', section='API'):
    def save_api_config(self, filename='config.ini', section='API'):
        parser = ConfigParser()
        parser.read(filename)
        api_info = dict()
        #for entry in entries:
        for entry in self.api_key_entries:
            field = entry[0]
            text = entry[1].get()
            # print(field, " = ", text)
            api_info[field] = text
            parser[section] = api_info
        with open(filename, 'w') as configfile:
            parser.write(configfile)

        self.api_key = api_info['api_key']
        self.w_db_new.destroy()

    @staticmethod
    def read_api_config(filename='config.ini', section='API'):
        parser = ConfigParser()
        parser.read(filename)
        api_info = dict()
        if parser.has_section(section):
            items = parser.items(section)
            for item in items:
                api_info[item[0]] = item[1]
            # print("Fingerbank API Key: %s" % api_info['api_key'])
        else:
            print("No Fingerbank API Key Present")
            return ""
        return api_info['api_key']

    def popup_confirm_save(self):
        confirm = tk.messagebox.askyesno("MUD-PD: MUD Profiling Database",
                                         "Are you sure you want to save this configuration?\n\n" +
                                         "Any existing configuration will be OVERWRITTEN.",
                                         default='no')
        save_pwd = tk.messagebox.askyesno("WARNING",
                                          "Password will be saved in plaintext.\n\nSave password anyway?",
                                          default='no')
        # print(confirm)
        if confirm:
            self.db_handler.save_db_config(save_pwd=save_pwd)
        return

    def popup_import_capture(self):
        self.w_cap = tk.Toplevel()
        self.w_cap.wm_title("Import Packet Capture")

        # self.ents = self.make_form_capture(captureFields)
        #ents = self.make_form_capture(captureFields, lifecyclePhaseFields, captureEnvFields, captureTypeFields)
        self.make_form_capture(captureFields, lifecyclePhaseFields, captureEnvFields, captureTypeFields)

        #self.bind('<Return>', (lambda event, e=ents: self.import_and_close(e)))
        self.bind('<Return>', (lambda event: self.import_and_close))

        self.b_import = tk.Button(self.w_cap, text='Import',
                                  #command=(lambda e=ents: self.import_and_close(e)))
                                  command=self.import_and_close)

        self.b_cancel = tk.Button(self.w_cap, text='Cancel', command=self.w_cap.destroy)

        if sys.platform == "win32":
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_import.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_import.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_cap)

    #@staticmethod
    def open_file_callback(self, sv_entry):
        tk.Tk().withdraw()  # we don't want a full GUI, so keep the root window from appearing

        filename = askopenfilename()  # show an "Open" dialog box and return the path to the selected file
        sv_entry.set(filename)
        #entry.delete(0, tk.END)
        #entry.insert(0, filename)

        # TODO: Check if selected file is the previously selected one
        if filename != self.filename_prev:
            self.filename_prev = filename

            if filename.lower().endswith(".pcapng"):
                # Check for metadata embedded in the comment field
                self.cap_envi_metadata = capMeta.extract_comment(filename)

                # 'File': 'fileName', 'Activity': 'activity', 'Notes (optional)': 'details',
                #                    'Lifecycle Phase': 'lifecyclePhase', 'Setup': 'setup', 'Normal Operation': 'normalOperation',
                #                    'Removal': 'removal',
                #                    'Internet': 'internet', 'Human Interaction': 'humanInteraction',
                #                    'Preferred DNS Enabled': 'preferredDNS', 'Isolated': 'isolated',
                #                    'Duration-based': 'durationBased', 'Duration': 'duration', 'Action-based': 'actionBased',
                #                    'Action': 'deviceAction',
                # field2db[self.capture_entries[2][0].cget('text')]:
                #                     field2db[lifecyclePhaseFields[self.capture_entries[2][1].get()]]
                if len(self.cap_envi_metada) > 0:
                    for i, (x, y) in enumerate (self.capture_entries):
                        # Skip first entry
                        if i:
                            if i == 2:
                                try:
                                    if self.cap_envi_metadata[ field2db[x] ].lower() == "setup":
                                        y.set(1)
                                    elif self.cap_envi_metadata[ field2db[x] ].lower() == "normal operation":
                                        y.set(2)
                                    elif self.cap_envi_metadata[field2db[x]].lower() == "removal":
                                        y.set(3)
                                    else:
                                        print("Warning unexpected phase provided")

                                    print("Phase", x.cget("text"), y.get())
                                except:
                                    print("Warning: Likely field missing in file comment")
                            else:
                                try:
                                    if type(y) == type(tk.IntVar()):
                                        if self.cap_env_envi_metadata[ field2db[x] ].lower() == "true":
                                            y.set(1)
                                        elif self.cap_envi_metadata[ field2db[x] ].lower() == "false":
                                            y.set(0)
                                        else:
                                            print("Warning! non true/false value provided")
                                    elif type(y) == type(tk.StringVar()):
                                        y.set(self.cap_env_envi_metadata[ field2db[x] ])
                                    else:
                                        print("Warning! Unexpected variable type")
                                    #self.cap_envi_metadata[field2db[x.cget: y.get()]]

                                    print(x, field2db[x], y.get())
                                except:
                                    print("Warning! Likely environmental variable missing")
            else:
                self.cap_envi_metadata = dict()

            # TODO: Kill any/all existing worker threads if a new file was selected
            #self.q.put("kill")

            # TODO: Restart worker threads to process file
            #self.p_file = mp.Process(target=self.import_and_close_proc, args=(self.q))


    def make_form_capture(self, fields_general, fields_phase, fields_env, fields_type):
        #entries = list()
        self.capture_entries = list()
        for i, field in enumerate(fields_general):
            row = tk.Frame(self.w_cap)
            lab = tk.Label(row, width=15, text=field, anchor='w')
            sv_ent = tk.StringVar()
            ent = tk.Entry(row, textvariable=sv_ent)

            if i == 0:
                b_open = tk.Button(row, text='...',
                                   command=(lambda e=sv_ent: self.open_file_callback(e)))
                                   #command=(lambda e=ent: self.open_file_callback(e)))
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.LEFT, fill=tk.X)
                b_open.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
            else:
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

            #entries.append((field, ent))
            #self.capture_entries.append((field, ent))
            self.capture_entries.append((field, sv_ent))

        # Device Phase (Setup, Normal Operation, Removal)
        # lifecyclePhaseFields = 'Setup', 'Normal Operation', 'Removal'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=15, text="Lifecycle Phase", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)

        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_phz = tk.IntVar(None, 1)
        for i, field in enumerate(fields_phase):
            b_phz = tk.Radiobutton(row, text=field, variable=v_phz, value=i)
            b_phz.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)

        #entries.append((lab, v_phz))
        self.capture_entries.append((lab, v_phz))

        # Environment Variables (Internet, Human Interaction, Preferred DNS Enabled, Isolated
        # captureEnvFields = 'Internet', 'Human Interaction', 'Preferred DNS Enabled','Isolated'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=20, text="Environmental Variables", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)
        for i, field in enumerate(fields_env):
            if i % 2 == 0:
                row = tk.Frame(self.w_cap)
                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                v_env = tk.IntVar(None, 1)
            else:
                v_env = tk.IntVar()

            # v_env = tk.IntVar()
            b_env = tk.Checkbutton(row, text=field, variable=v_env)
            b_env.pack(side=tk.LEFT, padx=20, anchor=tk.W)

            #entries.append((field, v_env))
            self.capture_entries.append((field, v_env))
            # entries.append((b_env, v_env))

        # Capture Type (Duration-based, Duration, Action-based, Action)
        # captureTypeFields = 'Duration-based', 'Duration', 'Action-based', 'Action'
        row = tk.Frame(self.w_cap)
        lab = tk.Label(row, width=15, text="Capture Type", anchor='w')
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab.pack(side=tk.LEFT)

        def activate_check_duration():
            if v_dur.get() == 1:  # whenever checked
                e_dur.config(state='normal')
            elif v_dur.get() == 0:  # whenever unchecked
                e_dur.config(state='disabled')

        i = 0
        # Duration-based
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_dur = tk.IntVar()
        b_dur = tk.Checkbutton(row, text=fields_type[i], variable=v_dur, command=activate_check_duration)
        b_dur.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)
        #entries.append((fields_type[i], v_dur))
        self.capture_entries.append((fields_type[i], v_dur))

        # Duration
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab = tk.Label(row, padx=5, width=9, text=fields_type[i], anchor='w')
        lab.pack(side=tk.LEFT)
        sv_dur = tk.StringVar()
        e_dur = tk.Entry(row, textvariable=sv_dur)
        e_dur.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        e_dur.config(state='disabled')
        #entries.append((fields_type[i], e_dur))
        self.capture_entries.append((fields_type[i], sv_dur))

        def activate_check_action():
            if v_act.get() == 1:  # whenever checked
                e_act.config(state='normal')
            elif v_act.get() == 0:  # whenever unchecked
                e_act.config(state='disabled')

        # Action-based
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        v_act = tk.IntVar()
        b_act = tk.Checkbutton(row, text=fields_type[i], variable=v_act, command=activate_check_action)
        b_act.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5, anchor=tk.W)
        #entries.append((fields_type[i], v_act))
        self.capture_entries.append((fields_type[i], v_act))

        # Action
        i += 1
        row = tk.Frame(self.w_cap)
        row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        lab = tk.Label(row, padx=5, width=9, text=fields_type[i], anchor='w')
        lab.pack(side=tk.LEFT)
        sv_act = tk.StringVar()
        e_act = tk.Entry(row, textvariable=sv_act)
        e_act.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        e_act.config(state='disabled')
        #entries.append((fields_type[i], e_act))
        self.capture_entries.append((fields_type[i], sv_act))

        #return entries

    #def import_and_close(self, entries):
    def import_and_close(self):

        # Check if capture is already in database (using sha256)
        file_path = self.capture_entries[0][1].get()
        filehash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        captures = self.db_handler.db.select_unique_captures()

        if any(filehash in cap_hash for cap_hash in captures):
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Capture file already imported into database")
        else:
            #self.cap = CaptureDigest(entries[0][1].get())
            #self.cap = CaptureDigest(self.capture_entries[0][1].get())
            self.cap = CaptureDigest(file_path, api_key=self.api_key)
            print("finished importing")
            # messagebox.showinfo("Importing", "Please wait for the capture file to be processed")

            data_capture = {
                "fileName": self.cap.fname,
                "fileLoc": self.cap.fdir,
                "fileHash": self.cap.fileHash,
                "capDate": epoch2datetime(float(self.cap.cap_timestamp)),  # epoch2datetime(float(self.cap.cap_date)),
                "capDuration": self.cap.capDuration,
                #"details": entries[1][1].get(),
                #field2db[entries[2][0].cget('text')]: field2db[lifecyclePhaseFields[entries[2][1].get()]]
                "details": self.capture_entries[1][1].get(),
                field2db[self.capture_entries[2][0].cget('text')]:
                    field2db[lifecyclePhaseFields[self.capture_entries[2][1].get()]]
                # "Internet" : entries[3][1].get(),
                # "Human Interaction" : entries[4][1].get(),
                # "Preferred DNS Enabled" : entries[5][1].get(),
                # "Isolated" : entries[6][1].get(),
                # "Duration-based" : entries[7][1].get(),
                # "Duration" : entries[8][1].get(),
                # "Action-based" : entries[9][1].get(),
                # "Action" : entries[10][1].get()
            }

            for i in range(3, 11):
                #data_capture[field2db[entries[i][0]]] = entries[i][1].get()
                #print(i, entries[i][1].get())
                data_capture[field2db[self.capture_entries[i][0]]] = self.capture_entries[i][1].get()
                print(i, self.capture_entries[i][1].get())

            print('data_capture:', data_capture)

            print("(A) inserting capture file into database")
            self.db_handler.db.insert_capture(data_capture)
            temp_file_id = self.db_handler.db.select_last_insert_id()
            self.cap.id = temp_file_id[0]

            # Embed capture environment metadata into pcapng file
            for i, (x, y) in enumerate(self.capture_entries):
                # Skip first entry
                if i:
                    if i == 2:
                        if y.get() == 1:
                            self.cap_envi_metadata[ field2db[x.cget("text")] ] = "setup"
                        elif y.get() == 2:
                            self.cap_envi_metadata[ field2db[x.cget("text")] ] = "normal operation"
                        elif y.get() == 3:
                            self.cap_envi_metadata[ field2db[x.cget("text")] ] = "removal"
                    else:
                        if type(y) == type(tk.IntVar()):
                            self.cap_envi_metadata[ field2db[x] ] = str(bool(y.get()))
                        else:
                            self.cap_envi_metadata[ field2db[x] ] = y.get()

            self.cap.embed_meta(self.cap_envi_metadata)

            # Potentially threadable code

            # Popup window
            # self.yield_focus(self.w_cap)
            # print("(A) popup_import_capture_devices")
            print("(B) popup_import_capture_devices")
            self.popup_import_capture_devices(self.cap)

            print("(C) populate_capture_list")
            self.populate_capture_list()

            print("(D) import_packets")
            self.import_packets(self.cap)

            # TODO: Verify this placement works
            print("(E) insert_protocol_device\n\tUpdating Device Protocol Table")
            try:
                self.db_handler.db.insert_protocol_device()
                messagebox.showinfo("Success!", "Labeled Device Info Updated")
            except AttributeError:
                messagebox.showinfo("Failure", "Please make sure you are connected to a database and try again")

            print("(F) destroying import capture window")
            self.w_cap.destroy()


    def import_and_close_proc(self, q):

        # Check if capture is already in database (using sha256)
        file_path = self.capture_entries[0][1].get()
        filehash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        captures = self.db_handler.db.select_unique_captures()

        if any(filehash in cap_hash for cap_hash in captures):
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Capture file already imported into database")
        else:
            self.cap = CaptureDigest(file_path, api_key=self.api_key, mp=True)  # , q=q)
            print("finished importing")

            data_capture = {
                "fileName": self.cap.fname,
                "fileLoc": self.cap.fdir,
                "fileHash": self.cap.fileHash,
                "capDate": epoch2datetime(float(self.cap.cap_timestamp)),  # epoch2datetime(float(self.cap.cap_date)),
                "capDuration": self.cap.capDuration,
                "details": self.capture_entries[1][1].get(),
                field2db[self.capture_entries[2][0].cget('text')]:
                    field2db[lifecyclePhaseFields[self.capture_entries[2][1].get()]]
            }

            for i in range(3, 11):
                data_capture[field2db[self.capture_entries[i][0]]] = self.capture_entries[i][1].get()
                print(i, self.capture_entries[i][1].get())

            print('data_capture:', data_capture)

            print("(A) inserting capture file into database")
            self.db_handler.db.insert_capture(data_capture)
            temp_file_id = self.db_handler.db.select_last_insert_id()
            self.cap.id = temp_file_id[0]

            # Embed capture environment metadata into pcapng file
            self.cap.embed_meta(data_capture)

            # Potentially threadable code

            # Popup window
            # self.yield_focus(self.w_cap)
            # print("(A) popup_import_capture_devices")
            print("(B) popup_import_capture_devices")
            self.popup_import_capture_devices(self.cap)

            print("(C) populate_capture_list")
            self.populate_capture_list()

            print("(D) import_packets")
            self.import_packets(self.cap)

            print("(E) destroying import capture window")
            self.w_cap.destroy()


    def pre_popup_import_capture_devices(self):
        # sel_cap_path = self.cap_list.get_selected_row()[5] + "/" + self.cap_list.get_selected_row()[2]
        sel_cap_path = self.cap_list.get_selected_row()[6] + "/" + self.cap_list.get_selected_row()[2]

        start = datetime.now()

        if self.cap is None or (self.cap.fdir + "/" + self.cap.fname) != sel_cap_path:
            # self.popup_import_capture_devices( CaptureDigest(sel_cap_path, gui=True) )
            # start = datetime.now()
            self.cap = CaptureDigest(sel_cap_path)

            self.cap.id = self.cap_list.get_selected_row()[0]
            # populate as much data from the database as possible

            self.cap.import_pkts()

            stop = datetime.now()
            print("time to import = ", (stop - start).total_seconds())
            self.popup_import_capture_devices()
        else:
            self.popup_import_capture_devices()

            stop = datetime.now()
            print("time to import = ", (stop - start).total_seconds())

    def popup_import_capture_devices(self, cap=None):
        self.w_cap_dev = tk.Toplevel()

        if cap is None:
            if self.cap is None:
                print("Error: If no previous capture imported, a capture file must be provided.")
        elif self.cap is None:
            self.cap = cap

        self.w_cap_dev.wm_title(self.cap.fname)

        self.topDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        # TODO: add compatibility to change or store user defined capture date and time, or change how it's displayed
        #ents = self.make_form_capture_devices(captureInfoFields, self.cap.cap_date, self.cap.cap_time)
        self.make_form_capture_devices(captureInfoFields, self.cap.cap_date, self.cap.cap_time)

        self.botDevFrame = tk.Frame(self.w_cap_dev, width=600, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        # ** Left (Unlabeled) Dev Frame ** #
        self.unlabeledDevFrame = tk.Frame(self.botDevFrame, width=300)  # , bd=1, bg="#dfdfdf")

        self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.unlabeled_title_var = tk.StringVar()
        self.unlabeled_title_var.set("Unlabeled")
        self.unlabeled_title = tk.Label(self.unlabeledDevFrame, textvariable=self.unlabeled_title_var, bg="#eeeeee",
                                        bd=1, relief="flat")
        self.unlabeled_title.pack(side="top", fill=tk.X)

        self.unlabeled_dev_header = ["id", "Manufacturer", "MAC", "IPv4", "IPv6"]
        self.unlabeled_dev_list = MultiColumnListbox(parent=self.unlabeledDevFrame, header=self.unlabeled_dev_header,
                                                     input_list=list(), select_mode="browse", exclusion_list=["id"])
        self.unlabeled_dev_list.bind("<<TreeviewSelect>>", self.update_unlabeled_list_selection)

        # ** Right (Labeled) Dev Frame ** #
        self.labeledDevFrame = tk.Frame(self.botDevFrame, width=300)  # , bd=1, bg="#dfdfdf")

        self.labeled_title_var = tk.StringVar()
        self.labeled_title_var.set("Labeled")
        self.labeled_title = tk.Label(self.labeledDevFrame, textvariable=self.labeled_title_var, bg="#eeeeee", bd=1,
                                      relief="flat")
        self.labeled_title.pack(side="top", fill=tk.X)

        self.labeled_dev_header = ["id", "Manufacturer", "Model", "Internal Name", "Category", "MAC", "IPv4", "IPv6"]
        self.labeled_dev_list = MultiColumnListbox(parent=self.labeledDevFrame, header=self.labeled_dev_header,
                                                   input_list=list(), select_mode="browse", exclusion_list=["id"])
        self.labeled_dev_list.bind("<<TreeviewSelect>>", self.update_identified_list_selection)

        # Grid placements #
        self.topDevFrame.grid(row=0, column=0, sticky="new")
        self.botDevFrame.grid(row=1, column=0, sticky="nsew")
        self.cap_dev_title.grid(row=0, column=0, columnspan=2, sticky="new")
        self.unlabeledDevFrame.grid(row=1, column=0, sticky="nsew")
        self.labeledDevFrame.grid(row=1, column=1, sticky="nsew")

        # Grid configuration #
        self.botDevFrame.grid_rowconfigure(1, weight=1)
        self.botDevFrame.grid_columnconfigure(0, weight=1)
        self.botDevFrame.grid_columnconfigure(1, weight=1)

        self.w_cap_dev.grid_rowconfigure(1, weight=1)
        self.w_cap_dev.grid_columnconfigure(0, weight=1)

        # Buttons #
        self.b_cap_dev_close = tk.Button(self.unlabeledDevFrame, text='Close',
                                         command=(lambda c=self.cap.id: self.close_w_cap_dev(c)))

        self.b_cap_dev_import = tk.Button(self.unlabeledDevFrame, text='Import Device', state='disabled',
                                          command=self.popup_import_device)

        self.b_cap_dev_modify = tk.Button(self.labeledDevFrame, text='Modify State', state='disabled',
                                          #command=(lambda d=self.labeled_dev_list.get_selected_row():
                                          #         self.prep_popup_update_device_state(d)))
                                          command=self.prep_popup_update_device_state)

        self.b_cap_dev_close.pack(side=tk.LEFT, padx=5, pady=5)
        self.b_cap_dev_import.pack(side=tk.RIGHT, padx=5, pady=5)
        self.b_cap_dev_modify.pack(side=tk.RIGHT, padx=5, pady=5)

        # Update unlabeled, labeled lists and try to select the first element
        self.refresh_unlabeled_labeled_lists()
        # Select first element of each list
        # Try because the list might be empty
        self.unlabeled_dev_list.focus(0)
        self.unlabeled_dev_list.selection_set(0)
        self.labeled_dev_list.focus(0)
        self.labeled_dev_list.selection_set(0)

        self.yield_focus(self.w_cap_dev)

    def update_unlabeled_list_selection(self, _):
        self.unlabeled_dev_list_sel = self.unlabeled_dev_list.get(self.unlabeled_dev_list.selection())
        print("self.unlabeled_dev_list_sel = ", self.unlabeled_dev_list_sel)

    def update_identified_list_selection(self, _):
        self.labeled_dev_list_sel = self.labeled_dev_list.get(self.labeled_dev_list.selection())
        print("self.labeled_dev_list_sel = ", self.labeled_dev_list_sel)

    #def prep_popup_update_device_state(self, d):
    def prep_popup_update_device_state(self):
        # Need to update d in call to "prep_popup_update_device_state"
        # d = self.identified_dev_list_sel
        d = self.labeled_dev_list_sel
        print("d = ", d)
        mac = d[5]
        device_id = d[0]
        # self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
        fw_ver = self.db_handler.db.select_most_recent_fw_ver({'deviceID': device_id,
                                                               'capDate': self.cap.cap_date + " " + self.cap.cap_time})

        device_state_data = {'fileID': self.cap.id,  # self.cap.fileID,
                             'mac_addr': mac.upper(),
                             'deviceID': device_id,
                             # need to comment out the next line
                             'internalName': d[2],
                             'fw_ver': fw_ver,
                             'ipv4_addr': d[6],
                             'ipv6_addr': d[7]}

        print("ipv4:", device_state_data['ipv4_addr'])
        print("ipv6:", device_state_data['ipv6_addr'])

        self.popup_update_device_state(device_state_data)

    # def close_w_cap_dev(self, capName):
    def close_w_cap_dev(self, cap_id):

        # Check if any of the devices seen have been added to the device_state table already and add if not
        # for dev in self.identified

        # self.populate_device_list(capture = capName)
        self.populate_device_list(capture_ids=[cap_id])
        # self.populate_device_list(capture = capName)
        self.w_cap_dev.destroy()

    # def refresh_unidentified_identified_lists(self):
    def refresh_unlabeled_labeled_lists(self):
        # Clear lists
        # self.unlabeled_dev_list.clear()
        # self.labeled_dev_list.clear()

        # Sort devices from Capture into either labeled or unlabeled device lists
        macs_in_dev_tbl = self.db_handler.db.select_device_macs()

        print("num uniqueMacs:", len(self.cap.uniqueMAC))

        # Sort devices found in the capture file into two lists: labeled, and unlabeled
        # Check if the devices in the capture file have been sorted yet
        if self.cap.newDevicesImported is not True:
            # self.unlabeled_dev_list.clear()
            # self.labeled_dev_list.clear()

            imported_devices = list()

            # Loop through the uniqueMAC addresses found in the capture file
            for mac in self.cap.uniqueMAC:
                print("mac", mac)

                # Check for a matching MAC address in the "Device" table
                match = [(device_id, mac_addr, unlabeled) for device_id, mac_addr, unlabeled in macs_in_dev_tbl if
                         mac == mac_addr]
                if (not match) or match[0][2]:

                    # Check if an entry for the prefix exists in the mac_to_mfr table
                    mac2mfr = self.db_handler.db.select_mac_to_mfr()
                    # mac_prefix = mac.upper()[0:8]
                    mac_prefix = mac[0:8]
                    # Need to address this statement
                    # mfr_match = [(mac2mfrID, x, mfr) for mac2mfrID, x, mfr in mac2mfr if mac_prefix==x]
                    mfr_match = [mfr for _, x, mfr in mac2mfr if mac_prefix == x]
                    if mfr_match:
                        # if mac_prefix in [x for (id, x, mfr) in mac2mfr]:
                        mfr = mfr_match[0]
                        if mfr == "**company not found**" or mfr == "None" or mfr is None:
                            mfr = lookup_mac(mac)
                    else:
                        mfr = lookup_mac(mac)
                    if mfr != "**company not found**" and mfr != "None" and mfr is not None:
                        self.db_handler.db.insert_mac_to_mfr({'mac_prefix': mac_prefix, 'mfr': mfr})

                    # device_data = {'mac_addr' : mac.upper(), 'mfr': mfr}
                    device_data = {'mac_addr': mac, 'mfr': mfr}

                    # self.db_handler.db.insert_device_unidentified(device_data)
                    self.db_handler.db.insert_device_unlabeled(device_data)

                    temp_device_id = self.db_handler.db.select_last_insert_id()
                    device_id = temp_device_id[0]

                    # TODO COMPLETE THE REPLACEMENT OF THE OLD findIP and findIPs functions
                    (ip_set, ipv6_set, hasMultiple) = self.cap.findIPs(mac)
                    if hasMultiple:
                        print("Warning: multiple IPv4 or IPv6 addresses found, providing the first one only")
                    ip = list(ip_set)[0]
                    ipv6 = list(ipv6_set)[0]

                    # Insert device_state info into device_state table
                    self.db_handler.db.insert_device_state_unlabeled(
                        {"fileID": self.cap.id,  # temporary, needs to be updated later
                         "deviceID": device_id,
                         "ipv4_addr": ip,
                         "ipv6_addr": ipv6})

                    self.cap.unlabeledDev.append(device_id)
                    imported_devices.append((device_id, mac))

                    # Insert device into unlabeled listbox
                    self.unlabeled_dev_list.append((device_id, mfr, mac, ip, ipv6))

                else:
                    device_id = match[0][0]
                    self.cap.labeledDev.append(device_id)
                    imported_devices += match
                    print(device_id, type(device_id))
                    device = self.db_handler.db.select_device(device_id)

                    (_, mfr, model, _, internalName, category, mudCapable, wifi, ethernet, bluetooth,
                     G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = device[0]

                    # Get device state info
                    device_state = self.db_handler.db.select_device_state(self.cap.id, device_id)
                    if len(device_state) == 1:
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = device_state[0]
                    elif len(device_state) == 0:
                        # TODO COMPLETE THE REPLACEMENT OF THE OLD findIP and findIPs functions
                        (ip_set, ipv6_set, hasMultiple) = self.cap.findIPs(mac)
                        if hasMultiple:
                            print("Warning: multiple IPv4 or IPv6 addresses found, providing the first one only")
                        ip = list(ip_set)[0]
                        ipv6 = list(ipv6_set)[0]

                        # May want to modify this not to take the previous fw_version
                        fw_ver = self.db_handler.db.select_most_recent_fw_ver({'deviceID': device_id, 'capDate':
                            self.cap.cap_date + " " +
                            self.cap.cap_time})
                        self.db_handler.db.insert_device_state({"fileID": self.cap.id,
                                                                "deviceID": device_id,
                                                                "fw_ver": fw_ver,
                                                                "ipv4_addr": ip,
                                                                "ipv6_addr": ipv6})
                    else:
                        print("ERROR, something went horribly wrong with the database")
                        ip = None
                        ipv6 = None

                    # Insert device into labeled listbox
                    self.labeled_dev_list.append((device_id, mfr, model, internalName, category, mac.upper(), ip,
                                                  ipv6))

                # Insert device into device_in_capture table
                self.db_handler.db.insert_device_in_capture_unique({'fileID': self.cap.id,
                                                                    'deviceID': device_id})

            self.cap.newDevicesImported = True

        else:
            # Loop through lists of self.cap.labeledDev and self.cap.unlabeledDev and
            #   check if the device is no longer in the respective listboxes and
            #     move check that it's in the correct one
            # Check if unlabeled_dev_list is unpopulated and populate if not
            if self.unlabeled_dev_list.num_nodes > 0:

                for unlabeledDevice in self.unlabeled_dev_list.get_list():
                    device_id = unlabeledDevice[0]
                    if device_id not in self.cap.unlabeledDev:
                        self.unlabeled_dev_list.remove_by_value(device_id, 0)

                        # Collect necessary information about device and move it into the labeled_dev_list listbox
                        device = self.db_handler.db.select_device(device_id)
                        (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3, G4,
                         G5, zigbee, zwave, other, notes, unlabeled) = device[0]

                        device_state = self.db_handler.db.select_device_state(self.cap.id, device_id)
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = device_state[0]

                        self.labeled_dev_list.append_unique((device_id, mfr, model, internalName,
                                                             category, mac_addr, ip, ipv6))

                        self.cap.labeledDev.append(device_id)
            else:
                for device_id in self.cap.unlabeledDev:

                    # Collect necessary information about device and place it into unlabeled_dev_list listbox
                    device = self.db_handler.db.select_device(device_id)
                    print("deviceID", device_id)
                    # (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth, G3,
                    # G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()
                    (_, mfr, _, mac_addr, _, _, _, _, _, _, _, _, _, _, _, _, _, unlabeled) = device[0]

                    device_state = self.db_handler.db.select_device_state(self.cap.id, device_id)
                    # (deviceStateID, _, _, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
                    (deviceStateID, _, _, _, ip, ipv6) = device_state[0]

                    if not unlabeled:
                        print("ERROR with populating unlabeled device list (device is labeled)")
                        return
                    self.unlabeled_dev_list.append_unique((device_id, mfr, mac_addr, ip, ipv6))

            # check if labeled_dev_list is empty and populate if it is
            if self.labeled_dev_list.num_nodes > 0:
                labeled_device_ids = list()
                # labeled_device_ids = self.labeled_dev_list.get_list()
                for labeled_dev in self.labeled_dev_list.get_list():
                    labeled_device_ids.append(labeled_dev[0])
                for device_id in self.cap.labeledDev:
                    if device_id not in labeled_device_ids:
                        # Collect necessary information about device and move it into the labeled_dev_list listbox
                        device = self.db_handler.db.select_device(device_id)
                        (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth,
                         G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = device[0]

                        device_state = self.db_handler.db.select_device_state(self.cap.id, device_id)
                        (deviceStateID, _, _, fw_ver, ip, ipv6) = device_state[0]

                        self.labeled_dev_list.append_unique((device_id, mfr, model, internalName,
                                                             category, mac_addr, ip, ipv6))
            else:
                for device_id in self.cap.labeledDev:

                    # Collect necessary information about device and place it into labeled_dev_list listbox
                    device = self.db_handler.db.select_device(device_id)
                    # (_, mfr, model, mac_addr, internalName, category, mudCapable, wifi, ethernet, bluetooth,
                    # G3, G4, G5, zigbee, zwave, other, notes, unlabeled) = self.db_handler.db.cursor.fetchone()
                    (_, mfr, model, mac_addr, internalName, category, _, _, _, _, _, _, _, _, _, _, _, unlabeled) = \
                        device[0]

                    device_state = self.db_handler.db.select_device_state(self.cap.id, device_id)
                    (deviceStateID, _, _, fw_ver, ip, ipv6) = device_state[0]

                    if unlabeled:
                        print("ERROR with populating labeled device list (device is unlabeled)")
                        return
                    self.labeled_dev_list.append_unique((device_id, mfr, model, internalName,
                                                         category, mac_addr, ip, ipv6))

        # Enable / Disable buttons as deemed necessary
        if self.unlabeled_dev_list.num_nodes > 0:
            self.b_cap_dev_import.config(state="normal")
        else:
            self.b_cap_dev_import.config(state="disabled")

        if self.labeled_dev_list.num_nodes > 0:
            self.b_cap_dev_modify.config(state="normal")
        else:
            self.b_cap_dev_modify.config(state="disabled")

    def make_form_capture_devices(self, fields, cap_date, cap_time):
        #entries = []
        self.capture_devices_entries = list()

        for i, field in enumerate(fields):
            row = tk.Frame(self.topDevFrame)  # w_cap_dev)
            # row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
            row.pack(side=tk.TOP, fill=tk.X)

            lab = tk.Label(row, width=15, text=field, anchor='w')
            lab.pack(side=tk.LEFT, fill="both")  # previously just tk.LEFT
            ent = tk.Entry(row, width=15)
            # ent.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)#previously tk.X
            ent.pack(side=tk.LEFT)  # , fill=tk.X)#previously tk.X

            if not i:
                ent.insert(10, cap_date)
            else:
                ent.insert(10, cap_time)

            #entries.append((field, ent))
            self.capture_devices_entries.append((field, ent))

        #return entries

    # def popup_import_device(self, fname):
    def popup_import_device(self):
        self.w_dev = tk.Toplevel()
        self.w_dev.wm_title("Import Devices")

        device_id = self.unlabeled_dev_list_sel[0]
        mfr = self.unlabeled_dev_list_sel[1]
        mac = self.unlabeled_dev_list_sel[2].upper()
        ipv4 = self.unlabeled_dev_list_sel[3]
        ipv6 = self.unlabeled_dev_list_sel[4]

        #ents = self.make_form_device(deviceFields, deviceOptions, mfr, mac)
        self.make_form_device(deviceFields, deviceOptions, mfr, mac)

        #dev_in_cap_data = {'mac_addr': mac,
        self.dev_in_cap_data = {'mac_addr': mac,
                                'fileID': self.cap.id,
                                'deviceID': device_id}

        # dev_in_cap_data['imported'] = True

        b_import = tk.Button(self.w_dev, text='Import',
                             #command=(lambda e=ents, d=dev_in_cap_data, i=(ipv4, ipv6):
                             # self.import_dev_and_close(e, d, i)))
                             command=(lambda i=(ipv4, ipv6): self.import_dev_and_close(i)))

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
        self.device_entries = list()

        dev_name = ""
        try:
            dev_name = self.cap.modellookup[mac_addr]
        except KeyError as ke:
            print("Model not found for: ", str(ke))
        print("Device Name: ", dev_name)
        cache_data = self.db_handler.db.select_cache_device({'model': dev_name})
        print("Cache Data: ", cache_data)
        print("Options: ", options)

        ent = None
        row = None
        for i, field in enumerate(fields):
            row = tk.Frame(self.w_dev)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            lab = tk.Label(row, width=15, text=field, anchor='w')
            lab.pack(side=tk.LEFT)

            if i < len(fields) - 1:
                if field == 'MAC':
                    lab = tk.Label(row, width=15, text=mac_addr, anchor='w', fg='gray')
                    lab.pack(side=tk.LEFT)
                    #entries.append((field, mac_addr))
                    self.device_entries.append((field, mac_addr))
                    continue
                else:
                    ent = tk.Entry(row)
                    ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                    if field == 'Model':
                        try:
                            ent.insert(30, dev_name)
                        except KeyError as ke:
                            print("Model not found for: ", str(ke))

            if not i:
                if ent is not None:
                    ent.insert(30, mfr)

            #entries.append((field, ent))
            self.device_entries.append((field, ent))

        for i, option in enumerate(options):
            if i == len(options) - 1:
                row = tk.Frame(self.w_dev)
                lab = tk.Label(row, width=10, text=option, anchor='w')
                ent = tk.Entry(row)

                row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
                # lab.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
                lab.pack(side=tk.LEFT)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

                if cache_data:
                    ent.insert(30, cache_data[0][i + 1])
                #entries.append((option, ent))
                self.device_entries.append((option, ent))
            else:
                if i % 5 == 0:
                    row = tk.Frame(self.w_dev)
                    row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

                checkvar = tk.IntVar()
                if row is not None:
                    ckb = tk.Checkbutton(row, text=option, width=10, justify=tk.LEFT, variable=checkvar)
                    ckb.pack(side=tk.LEFT, anchor="w")

                if cache_data:
                    if cache_data[0][i + 1] == 1:
                        checkvar.set(True)

                #if option == "wifi" or option == "WiFi":
                #    checkvar.set(True)

                #entries.append((option, checkvar))
                self.device_entries.append((option, checkvar))

        #return entries

    #def import_dev_and_close(self, entries, dev_in_cap_data, ips):
    def import_dev_and_close(self, ips):
        device_data = {"unlabeled": False}
        #for entry in entries:
        for entry in self.device_entries:
            field = entry[0]

            if field == 'MAC':
                #value = dev_in_cap_data['mac_addr']
                value = self.dev_in_cap_data['mac_addr']
            else:
                value = entry[1].get()

            try:
                dbfield = field2db[field]
            except KeyError as ke:
                print('Error:', ke)
                pass
            else:
                device_data[dbfield] = value
                print('field: %s value %s -> database field: %s' % (field, value, dbfield))

        self.db_handler.db.insert_device(device_data)
        #self.db_handler.db.insert_device_in_capture(dev_in_cap_data)
        self.db_handler.db.insert_device_in_capture(self.dev_in_cap_data)

        #mac = dev_in_cap_data['mac_addr']
        #device_id = dev_in_cap_data['device_id']
        mac = self.dev_in_cap_data['mac_addr']
        device_id = self.dev_in_cap_data['deviceID']

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

        self.cap.unlabeledDev.remove(device_id)
        self.cap.labeledDev.append(device_id)
        self.refresh_unlabeled_labeled_lists()

        fw_ver = self.db_handler.db.select_most_recent_fw_ver({'deviceID': device_id,
                                                               'capDate': self.cap.cap_date + " " + self.cap.cap_time})

        #device_state_data = {'fileID': dev_in_cap_data['fileID'],
        device_state_data = {'fileID': self.dev_in_cap_data['fileID'],
                             'mac_addr': mac,
                             'deviceID': device_id,
                             'internalName': device_data['internalName'],
                             'fw_ver': fw_ver,
                             'ipv4_addr': ips[0],
                             'ipv6_addr': ips[1]}

        try:
            self.popup_update_device_state(device_state_data)
        except mysql.connector.errors.InterfaceError as mysql_ie:
            tk.Tk().withdraw()
            messagebox.showerror(mysql_ie, "Please create a unique Internal Name")

        self.w_dev.destroy()

    def popup_update_device_state(self, device_state_data):
        self.w_dev_state = tk.Toplevel()
        self.w_dev_state.wm_title(device_state_data['internalName'])

        #ents = self.make_form_device_state(device_state_data)
        self.make_form_device_state(device_state_data)

        #self.w_dev_state.bind('<Return>', (lambda event, d=device_state_data, e=ents:
        self.w_dev_state.bind('<Return>', (lambda event, d=device_state_data: self.import_dev_state_and_close(d)))

        b_update = tk.Button(self.w_dev_state, text='Update',
                             #command=(lambda d=device_state_data, e=ents: self.import_dev_state_and_close(d, e)))
                             command=(lambda d=device_state_data: self.import_dev_state_and_close(d)))

        b_close = tk.Button(self.w_dev_state, text='Close', command=self.w_dev_state.destroy)

        if sys.platform == "win32":
            b_close.pack(side=tk.RIGHT, padx=5, pady=5)
            b_update.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            b_update.pack(side=tk.RIGHT, padx=5, pady=5)
            b_close.pack(side=tk.RIGHT, padx=5, pady=5)

        self.yield_focus(self.w_dev_state)

    def make_form_device_state(self, device_state_data):
        self.device_state_entries = dict()
        #entries = {}

        for i, (label, value) in enumerate(device_state_data.items()):
            # if not i:
            if label == 'fileID' or label == 'deviceID' or label == 'device_id':
                continue
            if value is None:
                value = ''
            row = tk.Frame(self.w_dev_state)
            row.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

            lab = tk.Label(row, width=15,
                           text=str(field2db.inverse[label]).replace('[', '').replace(']', '').replace("'", ''),
                           anchor='w')
            lab.pack(side=tk.LEFT)
            if label == 'fw_ver':
                v = tk.StringVar()
                ent = tk.Entry(row, textvariable=v)
                ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
                ent.insert(25, value)

                #entries[label] = v
                self.device_state_entries[label] = v
            else:
                lab = tk.Label(row, width=25, text=value, anchor='w', fg='gray')
                lab.pack(side=tk.LEFT)
                #entries[label] = value
                self.device_state_entries[label] = value

        #return entries

    #def import_dev_state_and_close(self, device_state_data, entries):
    def import_dev_state_and_close(self, device_state_data):
        print("device_state_data: ", device_state_data)
        #print("entries: ", entries)
        print("entries: ", self.device_state_entries)

        #print(entries['fw_ver'].get())
        #device_state_data['fw_ver'] = str(entries['fw_ver'].get())
        print(self.device_state_entries['fw_ver'].get())
        device_state_data['fw_ver'] = str(self.device_state_entries['fw_ver'].get())

        # Check if there is already an entry for this data:
        device_state = self.db_handler.db.select_device_state(device_state_data["fileID"],
                                                              device_state_data["deviceID"])
        temp = device_state[0]
        print(temp)
        if temp is None:
            self.db_handler.db.insert_device_state(device_state_data)
        else:
            device_state_data["id"] = temp[0]
            self.db_handler.db.update_device_state(device_state_data)

        self.w_dev_state.destroy()

    @staticmethod
    def fetch(entries):
        for entry in entries:
            field = entry[0]
            text = entry[1].get()
            print('%s: "%s"' % (field, text))

    # Uses Treeview
    def populate_capture_list(self):
        # clear previous list
        self.cap_list.clear()
        self.cap_list.append((0, "All..."))

        # Get and insert all captures currently added to database
        caps_imported = self.db_handler.db.select_imported_captures()
        for (cap_i_id, fileName, fileLoc, fileHash, cap_date, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in caps_imported:
            self.cap_list.append((cap_i_id, cap_date, fileName, deviceAction, capDuration, details, fileLoc))

        # Set focus on the first element
        self.cap_list.focus(0)
        self.cap_list.selection_set(0)

    # Uses Treeview
    def update_dev_list(self, _):
        cap_ids = list()

        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)
            # cap_date = cap_details[0]
            cap_date = cap_details[1]

            if cap_date == "All...":
                self.populate_device_list()
                self.b_main_inspect.config(state="disabled")
                # break
                return
            else:
                cap_ids.append(cap_details[0])

                # self.b_main_inspect.config(state="normal")
        self.populate_device_list(capture_ids=cap_ids)
        self.b_main_inspect.config(state="normal")

    def populate_device_list(self, capture_ids=None):  # , append=False):
        # clear previous list
        self.dev_list.clear()
        self.dev_list.append((0, "All..."))

        # Get and insert all captures currently added to database
        if capture_ids is None:
            devices = self.db_handler.db.select_devices()
        else:
            devices = self.db_handler.db.select_devices_from_caplist(capture_ids)

        for (dev_id, mfr, model, mac_addr, internalName, deviceCategory, mudCapable, wifi, ethernet, bluetooth,
             G3, G4, G5, zigbee, zwave, otherProtocols, notes, unlabeled) in devices:
            self.dev_list.append((dev_id, mfr, model, internalName, mac_addr, deviceCategory))  # for early stages

        self.dev_list.focus(0)
        self.dev_list.selection_set(0)

    def update_comm_list(self, _):
        self.populate_comm_list()

    def import_packets(self, cap):
        print("In import_packets")
        h = {"fileID": cap.id}
        batch = []

        start = datetime.now()

        i = 0
        for p in cap.pkt_info:
            p.update(h)
            batch.append(p)

            # if i < 1023:
            if i < 511:
                i += 1
            else:
                self.db_handler.db.insert_packet_batch(batch)
                batch.clear()
                i = 0

        # Insert the stragglers
        self.db_handler.db.insert_packet_batch(batch)

        stop = datetime.now()
        print("time to import = ", (stop - start).total_seconds())

        self.populate_comm_list()

    def populate_comm_list(self, append=False):
        # Clear previous list
        if not append:
            self.comm_list.clear()
            self.db_handler.db.drop_cap_toi()
            self.db_handler.db.drop_dev_toi()
            self.db_handler.db.drop_pkt_toi()

        print("\nPopulate Comm List")

        # Selecting based on cap list
        self.db_handler.db.capture_id_list.clear()
        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)

            print("cap_details", cap_details)

            cap_date = cap_details[1]

            if cap_date == "All...":
                print("All Captures")

                for cap_data in self.cap_list.get_list()[1:]:
                    self.db_handler.db.capture_id_list.append(cap_data[0])
                break
            else:
                self.db_handler.db.capture_id_list.append(cap_details[0])

        print("capture_id_list", self.db_handler.db.capture_id_list)
        # Check if the list is empty and return if it is
        if not self.db_handler.db.capture_id_list:
            return
        self.db_handler.db.create_pkt_toi_from_capture_id_list()

        self.db_handler.db.device_id_list.clear()
        for dev in self.dev_list.selection():
            dev_details = self.dev_list.get(dev)

            print("dev_details", dev_details)

            dev_name = dev_details[1]
            print("dev =", dev_name)

            if dev_name == "All...":
                # print("No device restrictions")
                for dev_data in self.dev_list.get_list()[1:]:
                    self.db_handler.db.device_id_list.append(dev_data[0])
                break
            else:
                self.db_handler.db.device_id_list.append(dev_details[0])

        print("device_id_list", self.db_handler.db.device_id_list)
        self.db_handler.db.create_dev_toi_from_fileID_list()

        # Selecting based on E/W or N/S
        if self.comm_state == "any":
            ew = [0, 1]
        elif self.comm_state == "ns":
            ew = [0]
        elif self.comm_state == "ew":
            ew = [1]
        else:
            ew = list()

        # Get files from tables of interest
        self.comm_list_all_pkts = self.db_handler.db.select_pkt_toi(ew, self.comm_list_num_pkts)

        # Get and insert all captures currently added to database
        #   might be interesting to include destination URL and NOTES
        for (pkt_id, fileID, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
             ew, tlp, tlp_srcport, tlp_dstport, pkt_length) in self.comm_list_all_pkts:

            # Handle instances where data is NULL/None
            if ip_ver is None:
                ip_ver = ''
                ip_src = ''
                ip_dst = ''
            if tlp is None:
                tlp = ''
                tlp_srcport = ''
                tlp_dstport = ''

            self.comm_list.append((pkt_id, fileID, pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew,
                                   protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))

        self.comm_list.focus(0)
        self.comm_list.selection_set(0)

    def modify_comm_state(self, button):
        print("button:", button)
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
            self.b_ns.config(fg="black")
            self.b_ew.config(fg="black")
            # update communication table view
        elif self.comm_state == "ns":
            self.b_ns.config(fg="green")
            self.b_ew.config(fg="red")
            # update communication table view
        elif self.comm_state == "ew":
            self.b_ns.config(fg="red")
            self.b_ew.config(fg="green")
            # update communication table view
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
        print("comm_dev_restriction: ", self.comm_dev_restriction)
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
            self.b_between.config(fg="black")
            self.b_either.config(fg="black")
            # update communication table view
        elif self.comm_dev_restriction == "between":
            self.b_between.config(fg="green")
            self.b_either.config(fg="red")
            # update communication table view
        elif self.comm_dev_restriction == "either":
            self.b_between.config(fg="red")
            self.b_either.config(fg="green")
            # update communication table view
        else:
            print("Something went wrong with modifying the communication device restriction")

        print("comm_dev_restriction:", self.comm_dev_restriction)
        self.populate_comm_list()

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

        dev_select_label = tk.Label(prompt_row, width=45, text="Please select the device you would like to profile:",
                                    anchor='w')
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

        # Frames for Device, Gateway, and PCAPs
        self.topMudDevFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        self.midMudGateFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        self.botMudPCAPFrame = tk.Frame(self.w_gen_mud, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        # ** Top Device Frame ** #
        # dev_select_label = tk.Label(self.topDevFrame, width=20, text="Select the device to profile:", anchor='w')
        # dev_select_label.pack(side=tk.LEFT)

        # self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.mud_dev_title_var = tk.StringVar()
        self.mud_dev_title_var.set("Device to Profile:")
        self.mud_dev_title = tk.Label(self.topMudDevFrame, textvariable=self.mud_dev_title_var,
                                      bg="#eeeeee", bd=1, relief="flat")
        self.mud_dev_title.pack(side="top", fill=tk.X)

        # self.mud_dev_header = ["Manufacturer", "Model", "MAC Address", "Internal Name", "Category"]
        self.mud_dev_header = ["id", "Internal Name", "Manufacturer", "Model", "MAC Address", "Category"]
        self.mud_dev_list = MultiColumnListbox(parent=self.topMudDevFrame, header=self.mud_dev_header,
                                               input_list=list(), select_mode="browse", exclusion_list=["id"])
        # unidentified_list_selection
        # self.mud_dev_list.bind("<<TreeviewSelect>>", self.update_gateway_list_selection)
        self.mud_dev_list.bind("<<TreeviewSelect>>", self.populate_mud_gate_list)

        # ** Middle Gateway Frame ** #
        self.mud_gate_title_var = tk.StringVar()
        self.mud_gate_title_var.set("Network Gateway:")
        self.mud_gate_title = tk.Label(self.midMudGateFrame, textvariable=self.mud_gate_title_var,
                                       bg="#eeeeee", bd=1, relief="flat")
        self.mud_gate_title.pack(side="top", fill=tk.X)

        self.mud_gate_header = ["id", "Internal Name", "Manufacturer", "Model", "Category",
                                "MAC Address", "IPv4", "IPv6"]
        self.mud_gate_list = MultiColumnListbox(parent=self.midMudGateFrame, header=self.mud_gate_header,
                                                input_list=list(), select_mode="browse", exclusion_list=["id"])
        # identified_list_selection
        # self.mud_gate_list.bind("<<TreeviewSelect>>", self.update_pcap_list_selection)
        self.mud_gate_list.bind("<<TreeviewSelect>>", self.populate_mud_pcap_list)

        # ** Bot PCAP Frame ** #
        self.mud_pcap_title_var = tk.StringVar()
        self.mud_pcap_title_var.set("Select Packet Captures (PCAPs):")
        self.mud_pcap_title = tk.Label(self.botMudPCAPFrame, textvariable=self.mud_pcap_title_var,
                                       bg="#eeeeee", bd=1, relief="flat")
        self.mud_pcap_title.pack(side="top", fill=tk.X)

        self.mud_pcap_header = ["id", "Date", "Capture Name", "Activity", "Duration (seconds)", "Details",
                                "Capture File Location"]
        # self.mud_pcap_header = ["Date","Capture Name","Activity", "Details","Capture File Location"]
        self.mud_pcap_list = MultiColumnListbox(parent=self.botMudPCAPFrame, header=self.mud_pcap_header,
                                                input_list=list(), keep_first=True, exclusion_list=["id"])
        # identified_list_selection
        self.mud_pcap_list.bind("<<TreeviewSelect>>", self.select_mud_pcaps)

        # Grid placements #
        self.topMudDevFrame.grid(row=0, column=0, sticky="nsew")  # new
        self.midMudGateFrame.grid(row=1, column=0, sticky="nsew")
        self.botMudPCAPFrame.grid(row=2, column=0, sticky="nsew")

        # Grid configuration #
        # self.topMudDevFrame.grid_rowconfigure(0, weight=1)
        # self.midMudGateFrame.grid_rowconfigure(1, weight=1)
        # self.botMudPCAPFrame.grid_rowconfigure(2, weight=1)

        self.w_gen_mud.grid_rowconfigure(0, weight=1)
        self.w_gen_mud.grid_rowconfigure(1, weight=1)
        self.w_gen_mud.grid_rowconfigure(2, weight=1)

        self.b_mud_generate = tk.Button(self.botMudPCAPFrame, text='Generate', state='disabled',
                                        command=self.generate_mud_file)

        self.b_mud_cancel = tk.Button(self.botMudPCAPFrame, text='Cancel', command=self.w_gen_mud.destroy)

        if sys.platform == "win32":
            self.b_mud_cancel.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_mud_generate.pack(side=tk.RIGHT, padx=5, pady=5)
        else:
            self.b_mud_generate.pack(side=tk.RIGHT, padx=5, pady=5)
            self.b_mud_cancel.pack(side=tk.RIGHT, padx=5, pady=5)

        # Update unidentified, identified lists and try to select the first element
        # self.refresh_mud_lists()
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

    def select_mud_pcaps(self, _):
        print("Select MUD pcaps")
        self.mud_pcap_sel = []

        print("mud_pcap_list.selection():", self.mud_pcap_list.selection())

        for pcap_item in self.mud_pcap_list.selection():
            pcap = self.mud_pcap_list.get(pcap_item)
            print("pcap:", pcap)

            if pcap[1] == "All...":
                caps_imported = self.db_handler.db.select_imported_captures_with({"deviceID": self.device_id,
                                                                                  "gatewayID": self.gatewayID})

                for (cap_id, fileName, fileLoc, fileHash, cap_date, capDuration, lifecyclePhase,
                     internet, humanInteraction, preferredDNS, isolated, durationBased,
                     duration, actionBased, deviceAction, details) in caps_imported:
                    self.mud_pcap_sel.append(fileLoc + "/" + fileName)
                break
            else:
                self.mud_pcap_sel.append(pcap[4] + pcap[1])

        self.b_mud_generate.config(state='normal')

    def generate_mud_file(self):  # , event):
        print("Preparing to generate mud file")
        self.mud_gen_obj = MUDgeeWrapper()

        # self.mud_gen_obj.set_device(mac=self.mud_device[3], name=self.mud_device[2])
        self.mud_gen_obj.set_device(mac=self.mud_device[4], name=self.mud_device[3])
        # self.mud_config = MUDgeeWrapper({'device_config':{'device':mac, 'deviceName':internalName}})

        gateway_ips = self.db_handler.db.select_gateway_ips({'gateway_mac': self.gateway_mac})

        ip = None
        ipv6 = None

        for (ipv4_addr, ipv6_addr) in gateway_ips:
            print("ipv4_addr:", ipv4_addr)
            print("ipv4:", ip)
            print("ipv6_addr:", ipv6_addr)
            print("ipv6:", ipv6)

            if ip is not None and ip != ipv4_addr:
                if ip == "Not found" or ip == "0.0.0.0":
                    if ipv4_addr != "Not found" and ipv4_addr != "0.0.0.0":
                        ip = ipv4_addr
                else:
                    messagebox.showerror("MUD Gateway Selection Error",
                                         "The selected gateway appears to have either multiple IPv4 addresses"
                                         " or IPv6 addresses!")
                    return
            else:
                ip = ipv4_addr

            if ipv6 is not None and ipv6 != ipv6_addr:
                if ipv6 == "Not found" or ipv6 == "::":
                    if ipv6_addr != "Not found" and ipv6_addr != "::":
                        ipv6 = ipv6_addr
                else:
                    messagebox.showerror("MUD Gateway Selection Error",
                                         "The selected gateway appears to have either multiple IPv4 addresses"
                                         " or IPv6 addresses!")
                    return
            else:
                ipv6 = ipv6_addr

        if ip == "Not found" or ip == "0.0.0.0":
            if ipv6 == "Not found" or ipv6 == "::":
                messagebox.showwarning("MUD Gateway Selection Warning",
                                       "The selected gateway does not have valid IPv4 or IPV6 addresses.")
            else:
                messagebox.showwarning("MUD Gateway Selection Warning",
                                       "The selected gateway does not have a valid IPv4 address.")
                # return
        elif ipv6 == "Not found" or ipv6 == "::":
            messagebox.showwarning("Problem with MUD Gateway Selection",
                                   "The selected gateway does not have a valid IPv6 address.")
            # return

        # self.mud_gate_list.append((mfr, model, internalName, category, mac))

        # self.mud_gen_obj.set_gateway(mac=self.mud_gateway[4], ip=ip, ipv6=ipv6)
        self.mud_gen_obj.set_gateway(mac=self.mud_gateway[5], ip=ip, ipv6=ipv6)

        # pcap_list = self.mud_pcap_sel

        # self.mud_gen_obj.gen_mudfile(pcap_list)
        print("Generating MUD file")
        self.mud_gen_obj.gen_mudfile(self.mud_pcap_sel)
        messagebox.showinfo("MUD File Generation Complete", "The generated MUD file is in the 'mudfiles' directory.")

    def populate_mud_dev_list(self):
        # Get and insert all captures currently added to database
        self.mud_dev_list.clear()
        print("Populating MUD Device List")
        devices = self.db_handler.db.select_devices_imported()

        for (dev_id, mfr, model, mac, internalName, category) in devices:
            self.mud_dev_list.append((dev_id, internalName, mfr, model, mac, category))
            # self.mud_dev_list.append(internalName + ' | ' + mac)

        # self.gate_select_list = tk.OptionMenu(self.row_gate, self.mud_gate_var, *self.mud_gate_list)
        # self.gate_select_list.pack(side=tk.LEFT)

    def populate_mud_gate_list(self, _):  # , ignored_dev = None):
        print("Populating MUD Gateway list")
        self.mud_gate_list.clear()
        # self.mud_gate_list.append(('--',))

        # device = self.mud_dev_list.get_selected_row()
        self.mud_device = self.mud_dev_list.get(self.mud_dev_list.selection())
        print("device:", self.mud_device)
        # ignored_dev = self.mud_device[4]
        # self.dev_mac = self.mud_device[3]
        self.dev_mac = self.mud_device[4]
        self.device_id = self.mud_device[0]
        print("self.dev_mac:")
        print("\t", self.dev_mac)
        print("self.device_id:")
        print("\t", self.device_id)

        if self.dev_mac is None or self.device_id is None or self.device_id == 0:
            print("Returning from gate selection early")
            return

        # Get and insert all captures currently added to database
        devices = self.db_handler.db.select_devices_imported_ignore({'ignored_device_id': self.device_id})

        for (dev_id, mfr, model, mac, internalName, category, ipv4, ipv6) in devices:
            self.mud_gate_list.append((dev_id, internalName, mfr, model, category, mac, ipv4, ipv6))
            # self.mud_gate_list.append(internalName + ' | ' + mac)
            # print("\t" + internalName + ' | ' + mac)

        # Set focus on the first element
        self.mud_gate_list.focus(0)
        self.mud_gate_list.selection_set(0)

        self.populate_mud_pcap_list(_)  # '--','--')

    def populate_mud_pcap_list(self, _):  # , device=None, gateway=None):
        print("Populating MUD PCAP list")

        # clear previous list
        self.mud_pcap_list.clear()

        self.mud_device = self.mud_dev_list.get(self.mud_dev_list.selection())
        # self.dev_mac = self.mud_device[3]
        self.dev_mac = self.mud_device[4]
        self.device_id = self.mud_device[0]

        self.mud_gateway = self.mud_gate_list.get(self.mud_gate_list.selection())
        # self.gateway_mac = self.mud_gateway[4]
        self.gateway_mac = self.mud_gateway[5]
        self.gatewayID = self.mud_gateway[0]

        print("device:", self.dev_mac)
        print("device_id:", self.device_id)
        print("gateway:", self.gateway_mac)
        print("gatewayID:", self.gatewayID)

        if self.device_id is None or self.device_id == 0 or self.gatewayID is None or self.gatewayID == 0:
            print("Returning from mud pcap selection early")
            return
        self.mud_pcap_list.append((0, "All..."))

        # Get and insert all captures currently added to database
        caps_imported = self.db_handler.db.select_imported_captures_with({"deviceID": self.device_id,
                                                                          "gatewayID": self.gatewayID})

        for (cap_id, fileName, fileLoc, fileHash, cap_date, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in caps_imported:
            self.mud_pcap_list.append(
                (cap_id, cap_date, fileName, deviceAction, duration, details, fileLoc))  # for early stages

        # Set focus on the first element
        self.mud_pcap_list.focus(0)
        self.mud_pcap_list.selection_set(0)

    def generate_report_wizard(self):
        self.w_gen_report = tk.Toplevel()
        self.w_gen_report.wm_title('Generate Device Report Wizard')

        # Frames for Device, Gateway, and PCAPs
        self.topReportDevFrame = tk.Frame(self.w_gen_report, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        self.botReportPCAPFrame = tk.Frame(self.w_gen_report, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")

        # ** Top Device Frame ** #
        # Title
        self.report_dev_title_var = tk.StringVar()
        self.report_dev_title_var.set("Device to Profile:")
        self.report_dev_title = tk.Label(self.topReportDevFrame, textvariable=self.report_dev_title_var, bg="#eeeeee",
                                         bd=1, relief="flat")
        self.report_dev_title.pack(side="top", fill=tk.X)

        # Listbox
        self.report_dev_header = ["id", "Internal Name", "Manufacturer", "Model", "MAC Address", "Category"]
        self.report_dev_list = MultiColumnListbox(parent=self.topReportDevFrame, header=self.report_dev_header,
                                                  input_list=list(), keep_first=True, exclusion_list=["id"],
                                                  select_mode="browse")
        self.report_dev_list.bind("<<TreeviewSelect>>", self.populate_report_pcap_list)

        # ** Bot PCAP Frame ** #
        # Title
        self.report_pcap_title_var = tk.StringVar()
        self.report_pcap_title_var.set("Select Packet Captures (PCAPs):")
        self.report_pcap_title = tk.Label(self.botReportPCAPFrame, textvariable=self.report_pcap_title_var,
                                          bg="#eeeeee", bd=1, relief="flat")
        self.report_pcap_title.pack(side="top", fill=tk.X)

        # Listbox
        self.report_pcap_header = ["id", "Date", "Capture Name", "Activity", "Duration (seconds)", "Details",
                                   "Capture File Location", "ID"]
        self.report_pcap_list = MultiColumnListbox(parent=self.botReportPCAPFrame, header=self.report_pcap_header,
                                                   input_list=list(), keep_first=True, exclusion_list=["id"])
        self.report_pcap_list.bind("<<TreeviewSelect>>", self.select_report_pcaps)

        # Grid placements #
        self.topReportDevFrame.grid(row=0, column=0, sticky="nsew")
        self.botReportPCAPFrame.grid(row=1, column=0, sticky="nsew")

        self.w_gen_report.grid_rowconfigure(0, weight=1)
        self.w_gen_report.grid_rowconfigure(1, weight=1)

        # Buttons #
        self.b_report_generate = tk.Button(self.botReportPCAPFrame, text='Generate', state='disabled',
                                           command=self.generate_report)

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

        devices = self.db_handler.db.select_devices_imported()
        for (dev_id, mfr, model, mac, internalName, category) in devices:
            self.report_dev_list.append((dev_id, internalName, mfr, model, mac, category))

    def populate_report_pcap_list(self, _):  # unknown if need "event"
        print("Populating Report PCAP list")

        # clear previous list
        self.report_pcap_list.clear()

        # self.report_device = self.report_dev_list.get(self.report_dev_list.selection())
        # self.report_device = self.report_dev_list.get_selection_set()
        self.report_device = self.report_dev_list.get_selection_set().pop()
        if self.report_device is not None and len(self.report_device) >= 5:
            self.dev_mac = self.report_device[4]
            self.device_id = self.report_device[0]
        else:
            self.dev_mac = None
            self.device_id = None

        print("device:", self.dev_mac)
        print("device_id:", self.device_id)

        self.report_pcap_list.append((0, "All...",))

        # Get and insert all captures currently added to database
        if self.report_device[1] == "All...":
            print("all devices selected")
            caps_imported = self.db_handler.db.select_imported_captures()
        else:
            caps_imported = self.db_handler.db.select_imported_captures_with_device({"deviceID": self.device_id})

        # TODO: check why cap_i_id appears twice in the append statement below (originally just id)
        for (cap_i_id, fileName, fileLoc, fileHash, cap_date, capDuration, lifecyclePhase,
             internet, humanInteraction, preferredDNS, isolated, durationBased,
             duration, actionBased, deviceAction, details) in caps_imported:
            self.report_pcap_list.append(
                (cap_i_id, cap_date, fileName, deviceAction, duration, details, fileLoc, cap_i_id))  # for early stages

        # Set focus on the first element
        self.report_pcap_list.focus(0)
        self.report_pcap_list.selection_set(0)

    def select_report_pcaps(self, _):  # Originally _ was "event"
        print("Select Report pcaps")
        self.report_pcap_where = ' '

        print("report_pcap_list.selection():", self.report_pcap_list.selection())

        first = True

        for pcap_item in self.report_pcap_list.selection():
            pcap = self.report_pcap_list.get(pcap_item)
            print("pcap:", pcap)

            if pcap[1] != "All...":
                if first:
                    self.report_pcap_where = " WHERE c.id = %s" % pcap[6]
                    first = False
                else:
                    self.report_pcap_where += " OR c.id = %s" % pcap[6]

        self.report_pcap_where += ';'

        print("self.report_pcap_where:", self.report_pcap_where)

        self.b_report_generate.config(state='normal')

    def generate_report(self):
        print("Preparing to generate report file")

        for dev_item in self.report_dev_list.selection():
            dev = self.report_dev_list.get(dev_item)

            if dev[1] == "All...":
                print("All selected")
                devs_imported = self.db_handler.db.select_devices_imported()
                for (device_id, mfr, model, mac, internalName, category) in devs_imported:
                    self.report_gen_obj = ReportGenerator({'name': internalName, 'mac': mac})

                    # Write to file
                    self.report_gen_obj.write_header()

                    pcap_info = self.db_handler.db.select_caps_with_device_where({"deviceID": device_id},
                                                                                 conditions=self.report_pcap_where)
                    print("len(pcap_info)", len(pcap_info))

                    # Need to add end_time and duration information to database
                    for (capture_id, fileName, fileLoc, fileHash, start_time, capDuration, lifecyclePhase,
                         internet, humanInteraction, preferredDNS, isolated, durationBased,
                         duration, actionBased, deviceAction, details) in pcap_info:
                        capture_info = {'filename': fileName,
                                        'sha256': fileHash,
                                        # 'activity'         : activity,
                                        # 'modifiers' : modifiers,
                                        'phase': field2db.inverse[lifecyclePhase][0],
                                        'internet': internet,
                                        'humanInteraction': humanInteraction,
                                        'preferredDNS': preferredDNS,
                                        'isolated': isolated,
                                        'actionBased': actionBased,
                                        'deviceAction': deviceAction,
                                        'durationBased': durationBased,
                                        'duration': duration,
                                        'capDuration': capDuration,
                                        'start_time': start_time,
                                        'end_time': start_time + timedelta(seconds=int(capDuration)),
                                        'details': details,
                                        'other_devices': list()}

                        #capture_info['other_devices'] = []
                        devs_except = self.db_handler.db.select_devices_in_caps_except({"captureID": capture_id,
                                                                                        "deviceID": device_id})
                        for (dev_e_id, dev_e_internalName, dev_e_mac) in devs_except:
                            capture_info['other_devices'].append({'name': dev_e_internalName, 'mac': dev_e_mac})

                        # Append capture information
                        self.report_gen_obj.write_capture_info(capture_info)
                break

            else:
                print("Generating report for one device:\t%s" % dev[1])
                self.report_gen_obj = ReportGenerator({'name': dev[1], 'mac': dev[4]})

                # Write header to file
                self.report_gen_obj.write_header()

                pcap_info = self.db_handler.db.select_caps_with_device_where({'deviceID': dev[0]},
                                                                             conditions=self.report_pcap_where)

                for (capture_id, fileName, fileLoc, fileHash, start_time, capDuration, lifecyclePhase,
                     internet, humanInteraction, preferredDNS, isolated, durationBased,
                     duration, actionBased, deviceAction, details) in pcap_info:

                    capture_info = {'filename': fileName,
                                    'sha256': fileHash,
                                    # 'activity'         : activity,
                                    # 'modifiers' : modifiers,
                                    'phase': field2db.inverse[lifecyclePhase][0],
                                    'internet': internet,
                                    'humanInteraction': humanInteraction,
                                    'preferredDNS': preferredDNS,
                                    'isolated': isolated,
                                    'actionBased': actionBased,
                                    'deviceAction': deviceAction,
                                    'durationBased': durationBased,
                                    'duration': duration,
                                    'capDuration': capDuration,
                                    'start_time': start_time,
                                    'end_time': start_time + timedelta(seconds=int(capDuration)),
                                    'details': details,
                                    'other_devices': list()}

                    #capture_info['other_devices'] = []
                    devs_except = self.db_handler.db.select_devices_in_caps_except({"captureID": capture_id,
                                                                                    "deviceID": dev[0]})
                    for (dev_e_id, internalName, dev_e_mac) in devs_except:
                        capture_info['other_devices'].append({'name': internalName, 'mac': dev_e_mac})

                    # Append capture information
                    self.report_gen_obj.write_capture_info(capture_info)

        messagebox.showinfo("Report Generation Complete", "The generated reports are in the 'reports' directory.")

    def popup_about(self):
        self.w_about = tk.Toplevel()
        self.w_about.wm_title("About")

        frame_summary = tk.Frame(self.w_about)
        summary = tk.Message(frame_summary,
                             text="This is a proof of concept for evaluating network traffic " +
                                  "for use in auditing the network, generating MUD files, and " +
                                  "identifying various privacy concerns.\n\n" +
                                  "This is a work in progress.", width=500)

        frame_summary.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        summary.pack(side="left")

        frame_src = tk.Frame(self.w_about)
        sources = tk.Message(frame_src, text="Icons used under Creative Commons BY 3.0 License:\n" +
                                             "CC 3.0 BY Flaticon: www.flaticon.com is licensed by " +
                                             "http://creativecommons.org/licenses/by/3.0/ " +
                                             "Icons made by https://www.flaticon.com/authors/smashicons\n" +
                                             "Icons made by Kirill Kazachek", width=500)
        frame_src.pack(side="top", fill="both", padx=5, pady=2, expand=True)
        sources.pack(side="left")

        frame_close = tk.Frame(self.w_about)
        b_close = tk.Button(frame_close, text="Close", command=self.w_about.destroy)
        frame_close.pack(side="top", fill="x", padx=5, pady=2, expand=True)
        b_close.pack(side="bottom", padx=5, pady=5)

        self.yield_focus(self.w_about)

    def __exit__(self):
        self.db_handler.__exit__()
        print("Cleaned up on exit")
        self.parent.quit()


#class MUDWizard(tk.Tk):
class MUDWizard(tk.Toplevel):

    def __init__(self, parent, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.wm_title("MUD Wizard")
        self.parent = parent
        self.parent.b_MUDdy.config(state='disabled')

        self.hosts_internet = list()
        self.hosts_local = list()
        self.dns_name = ''
        self.ipversion = IPVersion.IPV4

        self.protocol_options = ('Any', 'TCP', 'UDP')
        self.init_direction_options = ('Either', 'Thing', 'Remote')

        self.current_page = 0
        self.sv_device = tk.StringVar()
        self.v_internet = tk.BooleanVar()
        self.v_internet.set(True)
        self.v_local = tk.BooleanVar()
        self.v_local.set(True)
        self.sv_desc = tk.StringVar()
        self.sv_mfr = tk.StringVar()
        self.sv_summary = tk.StringVar()

        self.mud = ''
        self.mud_name = f'mud-{random.randint(10000, 99999)}'
        self.acl = []
        self.policies = {}
        self.cb_v_list = list()
        self.db_handler = self.parent.db_handler
        self.mud_device = dict()
        self.row_nav = 2000

        self.support_info = make_support_info(1, 'https://lighting.example.com/hvac1.json', 48, True, 'Test Device',
                                 'https://jci.example.com/doc/hvac1', mfg_name='Test Manufacturer')

        self.rules = {"internet": dict(),
                      "local": dict(),
                      "mfr_same": dict(),
                      "mfr_named": dict(),
                      "controller_my": dict(),
                      "controller": dict()}

        print("self.parent.test", self.parent.test)

        container = tk.Frame(self)

        container.pack(side="top", fil="both", expand = True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}  # At a quick glance I can't tell if this is a set or dict
        self.frame_list = list()  # []

        # TODO: See if this can be removed
        try:
            self.db_handler.db.insert_protocol_device()
            print("Success!", "Labeled Device Info Updated")
        except AttributeError:
            messagebox.showinfo("Failure", "Please make sure you are connected to a database and try again")

        for F in (MUDPage0Select, MUDPage1Description, MUDPage2Internet, MUDPage3Local, MUDPage4SameMan,
                  MUDPage5NamedMan, MUDPage6MyControl, MUDPage7Control, MUDPage8Summary):
            self.frame_list.append(F)
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        print(self.frames)
        #self.current_page = 0
        self.show_frame(MUDPage0Select)

        self.parent.yield_focus(self)
        #self.mainloop()

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

        time.sleep(0.25)
        if cont == MUDPage2Internet:
            # TODO: Check if page contains any IP addresses, and show message if so
            # Warning about hostnames needing to be domain names, not IP addresses
            tk.messagebox.showinfo("Warning", "For proper functionality and alignment with the MUD Specification, "
                                              "these hostnames should be domain names, not IP addresses.")
        elif cont == MUDPage3Local:
            tk.messagebox.showinfo("Warning", "Hostnames for Local entries are for reference/context during this "
                                              "wizard only and will neither be saved, nor used in the MUD file. ANY "
                                              "local device can follow the rules defined.")
        elif cont == MUDPage5NamedMan:
            tk.messagebox.showinfo("Warning", "For proper functionality and alignment with the MUD Specification, "
                                              "these hostnames should be domain names, NOT IP addresses.")
        elif cont == MUDPage7Control:
            tk.messagebox.showinfo("Warning", "For proper functionality and alignment with the MUD Specification, "
                                              "these hostnames should be class URIs, NOT IP addresses.")

        #print("width: ", frame.winfo_width())
        #print("height: ", frame.winfo_height())

    def next_page(self):#, current_page): #TODO: Fix this

        #support_info = make_support_info(1, 'https://lighting.example.com/hvac1.json', 48, True, 'Test Device',
        #                                 'https://jci.example.com/doc/hvac1', mfg_name='Test Manufacturer')
        #options = []
        if self.current_page == 0:
            self.current_page += 1
            self.show_frame(self.frame_list[self.current_page])
        else:
            for i, v in enumerate(self.cb_v_list):
                if i and v.get() and i>=self.current_page:
                    self.current_page = i+1
                    self.show_frame(self.frame_list[self.current_page])
                    return

            # Go to Summary Page
            self.current_page = 8
            self.show_frame(self.frame_list[self.current_page])

            # Check and format MUD file info
            self.format_mud_info()
            self.sv_summary.set(json.dumps(self.mud, indent=4))
            self.frames[MUDPage8Summary].fill_summary()
            #self.frames[MUDPage8Summary].sv_summary.set(json.dumps(self.mud, indent=4))

    def prev_page(self): # TODO: Fix this
        if self.current_page > 1:
            for i, v in reversed(list(enumerate(self.cb_v_list))):
                if i and v.get() and i<(self.current_page-1):
                    self.current_page = i+1
                    self.show_frame(self.frame_list[self.current_page])
                    return
            self.current_page = 1
            self.show_frame(self.frame_list[self.current_page])
        else:
            self.current_page = 0
            self.show_frame(self.frame_list[self.current_page])

    def retrieve_hosts_internet(self, comm_list):
        self.hosts_internet = []
        for i in comm_list:
            if i[3] == 1:
                iptest = IP(i[2])
                if iptest.iptype() != 'ULA' or 'MULTICAST' not in iptest.iptype():
                    self.hosts_internet.append((i[1], i[2], i[4], i[5], i[3]))
            else:
                iptest = IP(i[2])
                if iptest.iptype() == 'PUBLIC':
                    try:
                        self.dns_name = socket.gethostbyaddr(i[2])
                        print(self.dns_name[0])
                    except socket.herror as he:
                        print("DNS Name not found for", i[2])
                        self.hosts_internet.append((i[1], i[2], i[4], i[5], i[3]))
                        continue
                    self.hosts_internet.append((i[1], self.dns_name[0], i[4], i[5], i[3]))
        return self.hosts_internet

    def retrieve_hosts_local(self, comm_list):
        self.hosts_local = []
        for i in comm_list:
            if i[3] == 1:
                iptest = IP(i[2])
                if iptest.iptype() == 'ULA' or 'MULTICAST' in iptest.iptype():
                    self.hosts_local.append((i[1], i[2], i[4], i[5], i[3]))
            else:
                iptest = IP(i[2])
                if iptest.iptype() != 'PUBLIC':
                    self.hosts_local.append((i[1], i[2], i[4], i[5], i[3]))
        return self.hosts_local


    def add_rule(self, frame, first_entry=False):  # Ignore the "first_entry" for now
        frame.max_row += 1
        v_host = tk.StringVar()
        v_protocol = tk.StringVar()
        v_port_local = tk.StringVar()
        v_port_remote = tk.StringVar()
        v_initiation_direction = tk.StringVar()

        # Host
        l_host = tk.Label(frame.contentFrame.scrollable_frame, text="Host")
        l_host.grid(row=frame.max_row, column=0, sticky='w')
        # TODO: Change this to a combobox entry with each entry being observed destination (dst) hosts
        e_host = tk.Entry(frame.contentFrame.scrollable_frame, width=40, textvariable=v_host)
        e_host.grid(row=frame.max_row, column=1, columnspan=6, sticky="ew")

        self.rules[frame.communication][frame.max_row] = {"host": (v_host, l_host, e_host)}

        # Protocol
        c_protocol = None
        l_protocol = tk.Label(frame.contentFrame.scrollable_frame, text="Protocol")
        l_protocol.grid(row=frame.max_row, column=7, sticky='w')
        self.rules[frame.communication][frame.max_row]["protocol"] = (v_protocol, l_protocol, c_protocol)
        c_protocol = self.create_combobox(frame)
        c_protocol.grid(row=frame.max_row, column=8, sticky='w')
        c_protocol.bind("<<ComboboxSelected>>", lambda f=frame.contentFrame.scrollable_frame, r=frame.max_row:
        self.protocol_updated(
            f, r))
        self.rules[frame.communication][frame.max_row]["protocol"] = (v_protocol, l_protocol, c_protocol)

        # TODO: Remove unnecessary code for the plus button
        # Button to Add or Remove entry
        v_modify = tk.StringVar()
        if first_entry:
            v_modify.set(" + ")
            modify_command = self.add_rule
            modify_args = False
        else:
            v_modify.set(" - ")
            modify_command = self.remove_rule
            modify_args = frame.max_row

        b_modify = tk.Button(frame.contentFrame.scrollable_frame, textvariable=v_modify, command= lambda f=frame,
                                                                                        a=modify_args:
        modify_command(f, a))
        b_modify.grid(row=frame.max_row, column=9, sticky='w')
        self.rules[frame.communication][frame.max_row]['remove_button'] = (b_modify,)

        frame.max_row += 1

        # Local Ports
        v_port_local.set("Any")
        l_port_local = tk.Label(frame.contentFrame.scrollable_frame, text="Local Port")
        l_port_local.grid(row=frame.max_row, column=0, columnspan=2, sticky='w')
        e_port_local = tk.Entry(frame.contentFrame.scrollable_frame, width=5, textvariable=v_port_local)
        e_port_local.grid(row=frame.max_row, column=2, sticky="w")
        self.rules[frame.communication][frame.max_row] = {"port_local": (v_port_local, l_port_local, e_port_local)}

        # Remote Ports
        v_port_remote.set("Any")
        l_port_remote = tk.Label(frame.contentFrame.scrollable_frame, text="Remote Port")
        l_port_remote.grid(row=frame.max_row, column=3, columnspan=2, sticky='e')
        e_port_remote = tk.Entry(frame.contentFrame.scrollable_frame, width=5, textvariable=v_port_remote)
        e_port_remote.grid(row=frame.max_row, column=5, sticky="w")
        self.rules[frame.communication][frame.max_row]["port_remote"] = (v_port_remote, l_port_remote, e_port_remote)

        # Initiation Direction
        c_initiation_direction = None
        l_initiation_direction = tk.Label(frame.contentFrame.scrollable_frame, text="Initiated by")
        l_initiation_direction.grid(row=frame.max_row, column=7, sticky='w')
        self.rules[frame.communication][frame.max_row]["initiation_direction"] = (v_initiation_direction,
                                                                                  l_initiation_direction,
                                                                                  c_initiation_direction)
        c_initiation_direction = self.create_combobox(frame, opt_type='initiation_direction')
        c_initiation_direction.grid(row=frame.max_row, column=8, sticky='w')
        self.rules[frame.communication][frame.max_row]["initiation_direction"] = (v_initiation_direction,
                                                                                  l_initiation_direction,
                                                                                  c_initiation_direction)

        # TODO: See if there is a way to scroll to the bottom
        #self.rules[frame.communication][frame.max_row]["initiation_direction"][1].see("end")
        #frame.contentFrame.scrollable_frame.see("end")

    def remove_rule(self, frame, row=None):
        if row == None:
            row = frame.max_row

        print("Remove_rule button row:", row)

        # Go through row pairs of rules, pull out tkinter objects (as fields), forget them, and pop from rules dict
        for r in [row, row+1]:
            fields = self.rules[frame.communication][r]
            for key in fields:
                self.forget_fields(fields[key])
            self.rules[frame.communication].pop(r)#, None)

    def forget_fields(self, tk_fields):
        for f in tk_fields:
            if type(f) is tk.StringVar:
                pass
            elif type(f) in [tk.Label, tk.Entry, tk.Button, tk.Checkbutton, ttk.Combobox]:
                f.grid_forget()
            else:
                print("Unexpected datatype %s, skipping" % type(f))

    def create_combobox(self, frame, opt_type="protocol", row=None):  # , options=[]):#, text_var=None):
        #if opt_type == "custom":
        #    combo_options = options
        #else:
        if opt_type == "protocol":
            values = self.protocol_options
        elif opt_type == "initiation_direction":
            values = self.init_direction_options
        #elif opt_type == "host":
        #    # TODO: Pull Hosts?
        #    values = ('Host A', 'Host B', 'Host B')
        else:
            print('Error: invalid rule_type')
            return

        if row is None:
            combo_options = self.rules[frame.communication][frame.max_row][opt_type][0]
        else:
            combo_options = self.rules[frame.communication][frame.row][opt_type][0]

        combobox = ttk.Combobox(frame.contentFrame.scrollable_frame, width=6, textvariable=combo_options,
                                state="readonly")

        combobox['values'] = values
        combobox.current(0)

        return combobox

    # TODO: Complete this portion
    #def protocol_updated(self, event, frame, row):
    def protocol_updated(self, frame, row):
        event = None

        print(frame, row)

        pass

        if event != "Any":
            # add local
            pass

            # add remote
            pass

            # add or remove direction
            if event == "TCP" and frame.communication != "controller":
                # add direction
                pass
            else:
                # hide the grid object
                pass
        else:
            # hide local, remote, and direction
            pass

    def create_port_entries(self, frame, row=None):
        if row == None:
            e_port_local = tk.Entry(frame, width=6,
                                    textvariable=self.rules[frame.communication][frame.max_row]['port_local'])
            e_port_remote = tk.Entry(frame, width=6,
                                     textvariable=self.rules[frame.communication][frame.max_row]['port_remote'])
        else:
            e_port_local = tk.Entry(frame, width=6, textvariable=self.rules[frame.communication][row]['port_local'])
            e_port_remote = tk.Entry(frame, width=6, textvariable=self.rules[frame.communication][row]['port_remote'])

        e_port_local.insert(0, 'any')
        e_port_remote.insert(0, 'any')

        return (e_port_local, e_port_remote)

    # TODO: Finish this method for assembling MUD files
    def format_mud_info(self):
        # Reset acl and policies
        self.acl = []
        self.policies = {}
        #self.domain_warning = False

        for direction_initiated in [Direction.TO_DEVICE, Direction.FROM_DEVICE]:

            acl_names = make_acl_names(self.mud_name, self.ipversion, direction_initiated)
            self.policies.update(make_policy(direction_initiated, acl_names))

            for (i, comm) in enumerate(self.rules.keys()):
                # Check if there are any valid entries stored here and continue to next comm if not
                if not self.cb_v_list[i+1].get():
                    continue

                # Set communication type
                if comm == "local":
                    type = MatchType.IS_LOCAL
                elif comm == "internet":
                    type = MatchType.IS_CLOUD
                elif comm == "mfr_same":
                    type = MatchType.IS_MYMFG
                elif comm == "mfr_named":
                    type = MatchType.IS_MFG
                elif comm == "controller_my":
                    type = MatchType.IS_MY_CONTROLLER
                elif comm == "controller":
                    type = MatchType.IS_CONTROLLER
                else:
                    print("Communication type error! Skipping")
                    continue

                #for row in enumerate(reversed(self.rules[comm])):
                for (j, row_a) in enumerate(list(self.rules[comm].keys())[0::2]):
                    row_b = row_a+1

                    # Get host
                    host = self.rules[comm][row_a]['host'][0].get()

                    # Get protocol
                    protocol = self.rules[comm][row_a]['protocol'][0].get()

                    # Get local port
                    port_local = self.rules[comm][row_b]['port_local'][0].get()
                    if port_local.upper() == "ANY":
                        port_local = None
                    elif port_local.isnumeric:
                        port_local = int(port_local)

                    # Get remote port
                    port_remote = self.rules[comm][row_b]['port_remote'][0].get()
                    if port_remote.upper() == "ANY":
                        port_remote = None
                    elif port_remote.isnumeric:
                        port_remote = int(port_remote)

                    # Get direction initiated
                    direction_init = self.rules[comm][row_b]['initiation_direction'][0].get()
                    if direction_init == "Either":
                        direction_init = direction_initiated
                    elif direction_init == "Thing":
                        direction_init = Direction.FROM_DEVICE
                    elif direction_init == "Remote":
                        direction_init = Direction.TO_DEVICE
                    else:
                        print("Error: Unexpected initiation direction value - skipping rule.")

                    # Check values and set appropriate fields
                    if protocol == self.protocol_options[0]:
                        prot = Protocol.ANY
                        # Override direction_init value since this shall not be specified
                        if direction_init != direction_initiated:
                            print("Warning: initiation direction specified when not allowed - ignoring value")
                        direction_init = direction_initiated
                        # Override port values since these shall not be specified
                        if port_local is not None and port_local.upper() != "ANY":
                            print("Warning: local port specified when not allowed - ignoring value")
                        port_local = None  # []
                        if port_remote is not None and port_remote.upper() != "ANY":
                            print("Warning: remote port specified when not allowed - ignoring value")
                        port_remote = None  # []
                    elif protocol == self.protocol_options[1]:
                        prot = Protocol.TCP
                        # Check if the initiation direction matches and skip to next rule if not
                        if direction_initiated != direction_init:
                            print("Initiation direction doesn't match, saving for second pass, or already added")
                            continue
                    elif protocol == self.protocol_options[2]:
                        prot = Protocol.UDP
                        # Override direction_init value since this shall not be specified
                        if direction_init != direction_initiated:
                            print("Warning: initiation direction specified when not allowed - ignoring value")
                        direction_init = direction_initiated
                    else:
                        print("Protocol type error! Skipping")
                        continue

                    # TODO: Revisit if want to handle non-domain/URL/URI/URN hosts
                    #if not re.match(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}$', host):
                    #    self.domain_warning = True

                    # Append rule to acl
                    self.acl.append(make_acls([self.ipversion], host, prot, type, direction_init,
                                              local_ports=[port_local], remote_ports=[port_remote],
                                              acl_names=acl_names))

                    #for protocol_direction in [Direction.TO_DEVICE, Direction.FROM_DEVICE]:
                    #    ace.append(make_ace(protocol_direction, host, prot, type, direction_init, self.ipversion,
                    #                        local_ports=[port_local], remote_ports=[port_remote]))

        self.mud = make_mud(self.support_info, self.policies, self.acl)

    # TODO: Modify this to either prompt asking where to save the file, or display where the file has been outputted
    def generate_mud_file(self):
        # TODO: rewrite using regex to make cleaner
        fpath = 'mudfiles/' + self.support_info['mfg-name'].replace(' ', '_').replace(',', '').replace('.', '')
        if not os.path.isdir(fpath):
            os.mkdir(fpath)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        dest_path = fpath + "/" + self.support_info['systeminfo'].replace(' ', '_') + "_" + timestamp + ".json"

        # Save data to file
        with open(dest_path, 'w') as fp:
            json.dump(self.mud, fp, indent=4)

        # Notify user of location of file
        tk.messagebox.showinfo("MUD File Saved", "MUD file saved in " + dest_path)

        self.__exit__()

    def cancel(self):
        # TODO: Implement a confirmation Popup with the ability to not cancel
        tk.messagebox.showinfo("Confirm Cancel", "Note this is just a placeholder")
        self.__exit__()

    def __exit__(self):
        self.parent.b_MUDdy.config(state='normal')
        self.destroy()


# TODO: MUD Device Selection Page
class MUDPage0Select(tk.Frame):

    def __init__(self, parent, controller):
        # TODO: See if this is where the window dimensions should be set
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller

        self.hosts_internet = []
        self.hosts_local = []
        self.device_id = ''
        self.dev_mac = ''
        self.dev_mfr = ''

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = tk.Frame(self, width=622, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")  # , width=300) #, bd=1, bg="#eeeeee")

        self.mud_dev_title_var = tk.StringVar()
        self.mud_dev_title_var.set("Device to Profile:")
        self.mud_dev_title = tk.Label(self.headerFrame, textvariable=self.mud_dev_title_var,
                                      bg="#eeeeee", bd=1, relief="flat")
        self.mud_dev_title.grid(row=0, sticky="nsew")

        self.mud_dev_header = ["id", "Internal Name", "Manufacturer", "Model", "MAC Address", "Category"]
        self.mud_dev_list = MultiColumnListbox(parent=self.contentFrame, header=self.mud_dev_header,
                                               input_list=list(), select_mode="browse", exclusion_list=["id"], row=1,
                                               sticky="nsew")
        self.mud_dev_list.bind("<<TreeviewSelect>>", self.retrieve_device_info)

        b_cancel = tk.Button(self.navigationFrame, text="Cancel", command=lambda: self.controller.cancel())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())

        b_cancel.grid(row=0, column=0, sticky='nsw')
        b_next.grid(row=0, column=1, sticky='nse')

        # Setup Device Selection Multi-column listbox
        self.populate_mud_dev_list()
        self.mud_dev_list.focus(0)
        self.mud_dev_list.selection_set(0)

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid_rowconfigure(1, weight=1)
        self.contentFrame.grid_columnconfigure(0, weight=1)
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(1, weight=1)
        self.navigationFrame.grid(row=self.controller.row_nav, column=0, sticky='sew')

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def populate_mud_dev_list(self):
        # Get and insert all captures currently added to database
        self.mud_dev_list.clear()
        print("Populating MUD Device List")
        try:
            devices = self.controller.db_handler.db.select_devices_imported()
            for (dev_id, mfr, model, mac, internalName, category) in devices:
                self.mud_dev_list.append((dev_id, internalName, mfr, model, mac, category))
        except AttributeError as ae:
            print("Database not connected, please connect to a database")

    def retrieve_device_info(self, _):  # , ignored_dev = None):
        print("Retrieving Device Info")

        self.controller.mud_device = self.mud_dev_list.get(self.mud_dev_list.selection())
        print("device:", self.controller.mud_device)

        # Populates Device String Variable for the next page
        for i, v in enumerate(self.controller.mud_device):
            if i == 1:
                self.controller.sv_device.set(v)
            elif i in [4, 5]:
                self.controller.sv_device.set(self.controller.sv_device.get() + "  -  " + v)

        self.device_id = self.controller.mud_device[0]
        self.dev_mac = self.controller.mud_device[4]
        self.dev_mfr = self.controller.mud_device[2]
        print("self.dev_mac:")
        print("\t", self.dev_mac)
        print("self.device_id:")
        print("\t", self.device_id)
        print("self.device_mfr:")
        print("\t", self.dev_mfr)

    def next_page(self):
        print("Populating device communication list")
        try:
            comm_info = self.controller.db_handler.db.select_device_communication_info({'new_deviceID': self.device_id})
            print(comm_info)
            self.hosts_internet = self.controller.retrieve_hosts_internet(comm_info)
            self.hosts_local = self.controller.retrieve_hosts_local(comm_info)
        except AttributeError as ae:
            print("Error: ", ae)
            # Skipping rest of method if fails.
            self.controller.next_page()
            return

        ipv4 = False
        ipv6 = False
        # Autofill Device Details
        self.controller.sv_mfr.set(self.dev_mfr)

        print("Internet hosts:", len(self.hosts_internet), self.hosts_internet)
        print("Local hosts:", len(self.hosts_local), self.hosts_local)

        # Internet
        if self.hosts_internet:
            self.controller.cb_v_list[1].set(True)

            for (protocol, host, port_remote, port_local, ip_version) in self.hosts_internet:
                self.controller.add_rule(self.controller.frames[MUDPage2Internet])
                self.controller.rules[self.controller.frames[MUDPage2Internet].communication][
                    self.controller.frames[MUDPage2Internet].max_row-1]['host'][0].set(host)  #set(host[1])
                self.controller.rules[self.controller.frames[MUDPage2Internet].communication][
                    self.controller.frames[MUDPage2Internet].max_row-1]['protocol'][0].set(protocol.upper()) #host[
                # 0].upper())
                self.controller.rules[self.controller.frames[MUDPage2Internet].communication][
                    self.controller.frames[MUDPage2Internet].max_row]['port_remote'][0].set(port_remote)#host[2])
                self.controller.rules[self.controller.frames[MUDPage2Internet].communication][
                    self.controller.frames[MUDPage2Internet].max_row]['port_local'][0].set(port_local)#host[3])
                if ip_version:
                    ipv6 = True
                else:
                    ipv4 = True
        else:
            self.controller.add_rule(self.controller.frames[MUDPage2Internet])

        # Local
        if self.hosts_local:
            self.controller.cb_v_list[2].set(True)

            for (protocol, host, port_remote, port_local, ip_version) in self.hosts_local:
                self.controller.add_rule(self.controller.frames[MUDPage3Local])
                self.controller.rules[self.controller.frames[MUDPage3Local].communication][
                    self.controller.frames[MUDPage3Local].max_row-1]['host'][0].set(host)#[1])
                #Disable hostname modification since it will be unused
                self.controller.rules[self.controller.frames[MUDPage3Local].communication][
                    self.controller.frames[MUDPage3Local].max_row-1]['host'][2].config(state="disabled")
                self.controller.rules[self.controller.frames[MUDPage3Local].communication][
                    self.controller.frames[MUDPage3Local].max_row-1]['protocol'][0].set(protocol.upper())#host[
                # 0].upper())
                self.controller.rules[self.controller.frames[MUDPage3Local].communication][
                    self.controller.frames[MUDPage3Local].max_row]['port_remote'][0].set(port_remote)#host[2])
                self.controller.rules[self.controller.frames[MUDPage3Local].communication][
                    self.controller.frames[MUDPage3Local].max_row]['port_local'][0].set(port_local)#host[3])
                if ip_version:
                    ipv6 = True
                else:
                    ipv4 = True
        else:
            self.controller.add_rule(self.controller.frames[MUDPage3Local])

        if ipv4 and ipv6:
            self.controller.ipversion = IPVersion.BOTH
        elif ipv4:
            self.controller.ipversion = IPVersion.IPV4
        elif ipv6:
            self.controller.ipversion = IPVersion.IPV6
        else:
            print("Warning: Impossible ip version combination found")

        self.controller.next_page()


# TODO: MUD Description Page
class MUDPage1Description(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = tk.Frame(self)#, width=300, bd=1, bg="#eeeeee")  # , bg="#dfdfdf")
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Device Details Header
        title = tk.Label(self.headerFrame, text="Device Details", bg="#eeeeee", bd=1, relief="flat")
        title.grid(row=0, sticky="nsew")

        # Device Selection
        l_device = tk.Label(self.contentFrame, text="Device:")
        l_device.grid(row=0, sticky="nw")
        self.lb_device = tk.Label(self.contentFrame, textvariable=self.controller.sv_device)
        self.lb_device.grid(row=0, column=1, columnspan=5, sticky="nw")

        # Support URL
        l_support_url = tk.Label(self.contentFrame, text="Support URL:")
        self.sv_support_url = tk.StringVar()
        e_support_url = tk.Entry(self.contentFrame, textvariable=self.sv_support_url)#, expand="y", fill="x")
        l_support_url.grid(row=1, column=0, columnspan=2, sticky="w")
        e_support_url.grid(row=1, column=2, columnspan=4, sticky="ew")

        # Manufacturer
        l_mfr = tk.Label(self.contentFrame, text="Manufacturer:")
        e_mfr = tk.Entry(self.contentFrame, textvariable=self.controller.sv_mfr)  # , expand="y", fill="x")
        l_mfr.grid(row=2, column=0, columnspan=2, sticky="w")
        e_mfr.grid(row=2, column=2, columnspan=4, sticky="ew")

        v_mfr = ""
        e_mfr.insert(0, v_mfr)

        # Documentation URL
        l_doc_url = tk.Label(self.contentFrame, text="Documentation URL:")
        self.sv_doc_url = tk.StringVar()
        e_doc_url = tk.Entry(self.contentFrame, textvariable=self.sv_doc_url)#, expand="y", fill="x")
        l_doc_url.grid(row=3, column=0, columnspan=3, sticky="w")
        e_doc_url.grid(row=3, column=3, columnspan=3, sticky="ew")

        # Device Description
        l_desc = tk.Label(self.contentFrame, text="Device Description:")
        e_desc = tk.Entry(self.contentFrame, textvariable=self.controller.sv_desc)  # , expand="y", fill="x")
        l_desc.grid(row=4, column=0, sticky="w")
        e_desc.grid(row=5, column=0, columnspan=6, sticky="nesw")

        # Communication types to Define [checkbox]
        l_comm_types = tk.Label(self.contentFrame, text="Select types of communication to define:")
        l_comm_types.grid(row=6, columnspan=5, sticky='w')

        # Select all/none checkbox
        self.sv_toggle = tk.StringVar(value="All")
        v_toggle = tk.BooleanVar()
        self.controller.cb_v_list.append(v_toggle)
        cb_toggle = tk.Checkbutton(self.contentFrame, textvariable=self.sv_toggle, variable=v_toggle,
                                   command=self.cb_toggle)
        cb_toggle.grid(row=6, column=5, sticky="w")

        # Remote/Internet Hosts
        v_internet = tk.BooleanVar()
        self.controller.cb_v_list.append(v_internet)
        cb_internet = tk.Checkbutton(self.contentFrame, text="Internet", variable=v_internet)
        cb_internet.grid(row=7, columnspan=6, sticky="w")

        # Local Hosts
        v_local = tk.BooleanVar()
        self.controller.cb_v_list.append(v_local)
        cb_local = tk.Checkbutton(self.contentFrame, text="Local", variable=v_local)
        cb_local.grid(row=8, columnspan=6, sticky="w")

        # Same Manufacturer
        v_mfr_same = tk.BooleanVar()
        self.controller.cb_v_list.append(v_mfr_same)
        cb_mfr_same = tk.Checkbutton(self.contentFrame, text="Same Manufacturer", variable=v_mfr_same)
        cb_mfr_same.grid(row=9, columnspan=6, sticky="w")

        # Other Named Manufacturers
        v_mfr_other = tk.BooleanVar()
        self.controller.cb_v_list.append(v_mfr_other)
        cb_mfr_other = tk.Checkbutton(self.contentFrame, text="Other Named Manufacturers", variable=v_mfr_other)
        cb_mfr_other.grid(row=10, columnspan=6, sticky="w")

        # My-Controller class of devices
        v_controller_my = tk.BooleanVar()
        self.controller.cb_v_list.append(v_controller_my)
        cb_controller_my = tk.Checkbutton(self.contentFrame, text="Network-Defined Controller", variable=v_controller_my)
        cb_controller_my.grid(row=11, columnspan=6, sticky="w")

        # Controllers
        v_controller = tk.BooleanVar()
        self.controller.cb_v_list.append(v_controller)
        cb_controller = tk.Checkbutton(self.contentFrame, text="Controller", variable=v_controller)
        cb_controller.grid(row=12, columnspan=6, sticky="w")

        # Navigation Buttons
        b_help = tk.Button(self.navigationFrame, text=" ? ", command=lambda: self.comm_help())
        b_help.grid(row=0, column=0, sticky="sw")

        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=4, sticky="se")
        b_next.grid(row=0, column=5, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")
        self.contentFrame.grid_rowconfigure(0, weight=1)
        self.contentFrame.grid_columnconfigure(3, weight=1)

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Future:
        # Best guess: more open (use mostly "any")
        # Best guess: more closed (use mostly specific protocols and ports)

    def cb_toggle(self):#, event):
        toggle = False
        for i, cb in enumerate(self.controller.cb_v_list):#self.cb_v_list):
            if not i:
                toggle = cb.get()
                if toggle:
                    self.sv_toggle.set("None")
                else:
                    self.sv_toggle.set("All")
            else:
                cb.set(toggle)

    def comm_help(self):
        tk.messagebox.showinfo("Defining Communication",
                               "Internet: Select this type to enter domain names of services that you want this "
                               "device to access.\n\n"
                               "Local: Access to/from any local host for specific services (like COAP or HTTP)\n\n"
                               "Same Manufacturer: Access to devices to/from the same manufacturer based on the "
                               "domain name in the MUD URL.\n\n"
                               "Other Manufacturer: Access to  of devices that are identified by the domain names in "
                               "their MUD URLs\n\n"
                               "Device-Specific Controller: Access to controllers specific to this device (no need to "
                               "name a class). This is \"my-controller\".\n\n"
                               "Controller Access: Access to classes of devices that are known to be controllers.  "
                               "Use this when you want different types of devices to access the same controller.")

    def next_page(self):
        # TODO: Check what the "1" and "48" are
        self.controller.support_info = make_support_info(1, self.sv_support_url.get(), 48, True,
                                                         self.controller.mud_device[1],
                                                         self.sv_doc_url.get(), mfg_name=self.controller.sv_mfr.get())
        self.controller.next_page()

    # TODO: Future, could update the mfr table at this point if the manufacturer input isn't found in the database or
    #  is different
    def update_mfr(self):
        pass


# TODO: Internet
class MUDPage2Internet(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        #MUDPage0Select.__init__(self, parent, controller)
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "internet"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self)#, width=500)  # , bg="#ffffff")
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        title = tk.Label(self.headerFrame, text="Internet Hosts", bg="#eeeeee", bd=1, relief="flat")
        title.grid(row=0, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text = " + ", command=lambda: self.add_internet())
        b_add_entry.grid(row=self.max_row, column=8, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")
        # self.contentFrame.grid_rowconfigure(0, weight=1)
        # self.contentFrame.grid_columnconfigure(0, weight=1)
        # self.contentFrame.grid_columnconfigure(1, weight=2)
        # self.contentFrame.grid_columnconfigure(2, weight=1)
        # self.contentFrame.grid_columnconfigure(3, weight=2)
        # self.contentFrame.grid_columnconfigure(4, weight=1)
        # self.contentFrame.grid_columnconfigure(5, weight=0)
        # self.contentFrame.grid_columnconfigure(6, weight=0)
        # self.contentFrame.grid_columnconfigure(7, weight=0)
        # self.contentFrame.grid_columnconfigure(8, weight=1)

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        #self.add_internet()

    # In case anything else should occur beyond the add_rule method
    def add_internet(self):
        self.controller.add_rule(self)

    def next_page(self):
        # TODO: ADD INTERNET ACL
        #self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: Local
class MUDPage3Local(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "local"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self, width=600)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        label = tk.Label(self.headerFrame, text="Local Hosts", bg="#eeeeee", bd=1, relief="flat")
        label.grid(row=0, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text=" + ", command=lambda: self.add_local())
        b_add_entry.grid(row=self.max_row, column=8, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        #self.add_local()

    # In case anything else should occur beyond the add_rule method
    def add_local(self):
       self.controller.add_rule(self)

    def next_page(self):
        # TODO: ADD Local ACL
        # self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: Same Manufacturers
class MUDPage4SameMan(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "mfr_same"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        label = tk.Label(self.headerFrame, text="Same Manufacturer", bg="#eeeeee", bd=1, relief="flat")
        label.grid(row=0, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text=" + ", command=lambda: self.add_same_mfr())
        b_add_entry.grid(row=self.max_row, column=8, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        self.add_same_mfr()

    # In case anything else should occur beyond the add_rule method
    def add_same_mfr(self):
        self.controller.add_rule(self)
        self.controller.rules[self.communication][self.max_row - 1]["host"][0].set("(filled in by system)")
        self.controller.rules[self.communication][self.max_row - 1]["host"][2].config(state="disabled")

    def next_page(self):
        # TODO: ADD SAME MANUFACTURER ACL
        # self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: Named Manufacturers
class MUDPage5NamedMan(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "mfr_named"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        label = tk.Label(self.headerFrame, text="Other Named Manufacturer(s)", bg="#eeeeee", bd=1, relief="flat")
        label.grid(row=0, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text=" + ", command=lambda: self.add_named_mfr())
        b_add_entry.grid(row=self.max_row, column=8, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        self.add_named_mfr()

    # In case anything else should occur beyond the add_rule method
    def add_named_mfr(self):
        self.controller.add_rule(self)

    def next_page(self):
        # TODO: ADD SAME MANUFACTURER ACL
        # self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: My-Controller
class MUDPage6MyControl(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "controller_my"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        title = tk.Label(self.headerFrame, text="Network-Specific Controllers", bg="#eeeeee", bd=1, relief="flat")
        title.grid(row=0, columnspan=6, sticky='new')
        subtitle = tk.Label(self.headerFrame, text="(my-controller)", bg="#eeeeee", bd=1, relief="flat")
        subtitle.grid(row=1, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text=" + ", command=lambda: self.add_my_controller())
        b_add_entry.grid(row=0, column=6, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        self.add_my_controller()

    def add_my_controller(self):
        self.controller.add_rule(self)
        self.controller.rules[self.communication][self.max_row - 1]["host"][0].set("(filled in by local admin)")
        self.controller.rules[self.communication][self.max_row - 1]["host"][2].config(state="disabled")

    def next_page(self):
        # TODO: ADD MY-CONTROLLER ACL
        # self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: Controllers
class MUDPage7Control(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.communication = "controller"
        self.controller.rules[self.communication] = dict()
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = ScrollableFrame(self)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Header
        title = tk.Label(self.headerFrame, text="Controllers", bg="#eeeeee", bd=1, relief="flat")
        title.grid(row=0, columnspan=6, sticky='new')

        # Button for adding entries/rules
        b_add_entry = tk.Button(self.headerFrame, text=" + ", command=lambda: self.add_controller())
        b_add_entry.grid(row=self.max_row, column=8, sticky="ne")

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_next = tk.Button(self.navigationFrame, text="Next", command=lambda: self.next_page())
        b_back.grid(row=0, column=5, sticky="se")
        b_next.grid(row=0, column=6, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")

        # Navigation
        self.navigationFrame.grid(row=2, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load up 1 instance to fill in at launch
        self.add_controller()

    # In case anything else should occur beyond the add_rule method
    def add_controller(self):
        self.controller.add_rule(self)

    def next_page(self):
        # TODO: ADD CONTROLLER ACL
        # self.controller.acl.append('stuff')
        self.controller.next_page()


# TODO: Generate MUD File
class MUDPage8Summary(MUDPage0Select, tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        self.max_row = 0

        self.headerFrame = tk.Frame(self, bg="#eeeeee")
        self.contentFrame = tk.Frame(self)
        self.navigationFrame = tk.Frame(self, bg="#eeeeee")

        # Summary header
        title = tk.Label(self.headerFrame, text="MUD File Summary", bg="#eeeeee")
        title.grid(row=0, columnspan=6, sticky='new')

        # TODO: Implement the actual summary information (probably in a normal listbox with all the text
        # Summary contents
        #sv_summary = tk.StringVar()
        #lb_summary = tk.Label(self.contentFrame, textvariable=sv_summary)
        #lb_summary.grid(row=1, sticky="w")
        # TODO: Remove this when real implementation complete
        #sv_summary.set("This\nis\na\nplaceholder\nfor\nthe\nMUD\nfile\nsummary\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
        #                   "\nHI!")
        self.st_summary = scrolledtext.ScrolledText(self.contentFrame, wrap=tk.WORD,
                                               width=40, height=10, font=("Times New Roman", 15))
        self.st_summary.grid(row=1, sticky="nsew")
        #self.st_summary.insert(tk.INSERT, self.controller.sv_summary.get())
        #st_summary.insert(tk.INSERT, json.dumps(self.controller.mud, indent=4))

        # Navigation Buttons
        b_back = tk.Button(self.navigationFrame, text="Back", command=lambda: self.controller.prev_page())
        b_save = tk.Button(self.navigationFrame, text="Save", command=lambda: self.controller.generate_mud_file())

        b_back.grid(row=0, column=1, sticky="se")
        b_save.grid(row=0, column=2, sticky="se")

        # *** Configure the grid *** #
        # Header
        self.headerFrame.grid(row=0, column=0, sticky="new")
        self.headerFrame.grid_rowconfigure(0, weight=1)
        self.headerFrame.grid_columnconfigure(0, weight=1)

        # Content
        self.contentFrame.grid(row=1, column=0, sticky="nsew")
        self.contentFrame.grid_rowconfigure(1, weight=1)
        self.contentFrame.grid_columnconfigure(0, weight=1)

        # Navigation
        self.navigationFrame.grid(row=self.controller.row_nav, column=0, sticky='sew')
        self.navigationFrame.grid_rowconfigure(0, weight=1)
        self.navigationFrame.grid_columnconfigure(0, weight=1)

        # Overall
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # TODO: considered not making this disabled, or provide an "ADVANCED" toggle to allow manual editing of the file
        #self.st_summary.configure(state="disabled")

    def fill_summary(self):
        self.st_summary.insert(tk.INSERT, self.controller.sv_summary.get())
        self.st_summary.configure(state="disabled")


def epoch2datetime(epochtime):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epochtime))


class DatabaseHandler:

    def __init__(self, filename='config.ini', section='mysql'):
        try:
            self.config = self.read_db_config(filename, section)
        except ConfigParser.Error:
            self.config = {"host": "", "database": "", "user": "", "passwd": ""}
        self.connected = False
        self.db = None
        self.db_config = None

    @staticmethod
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

    def save_db_config(self, filename='config.ini', section='mysql', save_pwd=False):
        parser = ConfigParser()
        parser.read(filename)
        info = {}
        for entry in self.db_config:
            field = entry
            text = self.db_config[entry]
            if save_pwd or field != "passwd":
                info[field] = text
            else:
                info[field] = ""
            # print(field, " = ", text)
            parser[section] = info
        with open(filename, 'w') as configfile:
            parser.write(configfile)

    def db_connect(self, entries):
        self.db_config = dict()

        for entry in entries:
            field = entry[0]
            text = entry[1].get()
            # print(field, " = ", text)
            self.db_config[field] = text

        try:
            self.db = CaptureDatabase(self.db_config)
        except mysql.connector.Error:
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

    # Gets the requested values of the height and width.
    #windowWidth = 800#root.winfo_reqwidth()
    #windowHeight = 500#root.winfo_reqheight()
    #print("Width", windowWidth, "Height", windowHeight)

    # Gets both half the screen width/height and window width/height
    #positionRight = int(root.winfo_screenwidth() / 2 - windowWidth / 2)
    #positionDown = int(root.winfo_screenheight() / 2 - windowHeight / 2)

    # Positions the window in the center of the page.
    #root.geometry("+{}+{}".format(positionRight, positionDown))

    root.mainloop()