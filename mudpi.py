#!/usr/bin/python3

from src.bidict import BiDict
from src.capture_database import CaptureDatabase
#from capture_database import DatabaseHandler
from src.capture_database import CaptureDigest
from datetime import datetime
import hashlib
from src.lookup import lookup_mac, lookup_hostname
import math
from src.multicolumn_listbox import MultiColumnListbox
#from multiprocessing import Process, Queue
import multiprocessing
import pyshark
import subprocess
import sys
import time
import concurrent

import tkinter as tk
from tkinter import ttk
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
        #self.parent.title("MUDdy Networks") #MUDdy Airwaves
        self.parent.title("MUDPI - MUD Profiling for IoT") #MUDdy Airwaves

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
        
        self.helpSubMenu = tk.Menu(self.fileMenu)
        self.fileMenu.add_cascade(label="Help", menu=self.helpSubMenu)
        self.helpSubMenu.add_command(label="About", command=self.popup_about)


        #### Main Window ####
        # Menu top
        self.menuFrame = tk.Frame(self.parent, bd=1, bg="#dfdfdf") #, bg="#dfdfdf"

        icon_connect = tk.PhotoImage(file="data/icons/database40px.png")
        b_connect = tk.Button(self.menuFrame, compound="top", image=icon_connect, width="40", height="40", command=self.popup_connect2database, highlightthickness=0, activebackground="black", bd=0)
        b_connect.image = icon_connect
        b_connect.pack(side="left")

        icon_import = tk.PhotoImage(file="data/icons/import40px.png")
        b_import = tk.Button(self.menuFrame, compound="top", image=icon_import, width="40", height="40", command=self.popup_import_capture, highlightthickness=0, activebackground="black", bd=0)
        b_import.image = icon_import
        b_import.pack(side="left")


        #b_y = tk.Button(self.menuFrame, state="disabled", text="Generate MUD File", highlightbackground="#dfdfdf", wraplength=80)#, anchor=tk.N+tk.W)
        b_generate_MUD = tk.Button(self.menuFrame, state="disabled", text="Generate MUD File", wraplength=80, command=self.generate_MUD_wizard)#, anchor=tk.N+tk.W)
        b_generate_MUD.pack(side="left")

        b_generate_report = tk.Button(self.menuFrame, state="disabled", text="Generate Device Report", wraplength=80, command=self.generate_report_wizard)#, anchor=tk.N+tk.W)
        b_generate_report.pack(side="left")

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
                              command=self.pre_popup_import_capture_devices)
        '''
                              command=(lambda hd0=4, hd1=1 :
                                           self.popup_import_capture_devices(
                    CaptureDigest(
                        self.cap_list.get_selected_row()[hd0] + "/" +
                        self.cap_list.get_selected_row()[hd1]))))
        '''
        b_inspect.pack(side="right")
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
        self.dev_header = ["Manufacturer", "Model", "Internal Name", "MAC", "Category"]
        self.dev_list = MultiColumnListbox(self.devFrame, self.dev_header, list(), keep1st=True)
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
        self.comm_header = ["Time", "MAC", "IPver", "Source", "Destination", "E/W",
                            "Protocol", "Transport Protocol", "Source Port",
                            #"Destination Port", "Length", "Direction", "Raw"] #Direction being NS or EW
                            #"Destination Port", "Length", "Raw"] #Direction being NS or EW
                            "Destination Port", "Length"] #Direction being NS or EW
        self.comm_list = MultiColumnListbox(self.commFrame, self.comm_header, list())#, keep1st=True)
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
        self.b_pkt100.config(state='disabled')

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

    def connect_and_close(self, entries):
        db_handler_temp = DatabaseHandler()
        (save_name, save_var) = entries.pop()
        save_val = save_var.get()
        #print(save_name, " = ", save_var, " = ", save_val)

        db_handler_temp.db_connect(entries)

        if db_handler_temp.connected:
            self.db_handler = db_handler_temp
            self.status_var.set("Connected to " + self.db_handler.config.get("database","none"))
            self.populate_capture_list()
            if save_val:
                self.popup_confirm_save()
            self.w_db.destroy()
            
        else:
            tk.messagebox.showerror("Error", "Problem connecting to database")
            entries.append((save_name, save_var))
            '''
            tk.Tk().withdraw()
            messagebox.showerror("Error", "Problem connecting to database")
            '''

    def popup_confirm_save(self):
        confirm = tk.messagebox.askyesno("MUDPI - Profiling IoT", "Are you sure you want to save this configuration?\n\nAny existing configuration will be OVERWRITTEN.")
        save_pwd = tk.messagebox.askyesno("WARNING", "Password will be saved in plaintext.\n\nSave password anyway?")
        #print(confirm)
        if confirm:
            self.db_handler.save_db_config(save_pwd=save_pwd)

    def popup_import_capture(self):
        self.w_cap = tk.Toplevel()
        self.w_cap.wm_title("Import Packet Capture")

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


    def import_with_progbar(self, cap=None):
        #tk.Tk().withdraw()
        self.w_import_progress = tk.Toplevel()
        self.w_import_progress.wm_title("Capture Import")
        self.w_import_progress.geometry("200x50")
        if cap != None:
            self.cap = cap
        #self.cap = cap

        tk.Label(self.w_import_progress, text="Import progress", width=20).grid(row=0, column=0)

        progress_var = tk.IntVar()
        progress_bar = ttk.Progressbar(self.w_import_progress, variable=progress_var, maximum=self.cap.fsize)
        progress_bar.grid(row=1, column=0)
        self.w_import_progress.pack_slaves()

        progress_var.set(self.cap.progress)
        self.w_import_progress.update()
        
        #start = datetime.now()
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

        #Check if capture is already in database (using md5hash)
        filehash = hashlib.md5(open(entries[0][1].get(),'rb').read()).hexdigest()
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
            self.cap.import_pkts()

            #self.import_with_progbar(CaptureDigest(entries[0][1].get()))
            
            print("finished importing")
            #messagebox.showinfo("Importing", "Please wait for the capture file to be processed")

            data_capture = {
                "fileName" : self.cap.fname,
                "fileLoc" : self.cap.fdir,
                "fileHash" : self.cap.fileHash,
                
                "capDate" : epoch2datetime(float(self.cap.capTimeStamp)),#epoch2datetime(float(self.cap.capDate)),
                "activity" : entries[1][1].get(),
                "details" : entries[2][1].get()
                }


            # Popup window
            #self.yield_focus(self.w_cap)
            #print("(A) popup_import_capture_devices")
            self.popup_import_capture_devices(self.cap)

            #print("(B) db_handler.db.insert_capture")
            self.db_handler.db.insert_capture(data_capture)
            #print("(C) populate_capture_list")
            self.populate_capture_list()

            #print("(D) import_packets")
            self.import_packets(self.cap)

            self.w_cap.destroy()


    def pre_popup_import_capture_devices(self):
        sel_cap_path = self.cap_list.get_selected_row()[4] + "/" + self.cap_list.get_selected_row()[1]

        if self.cap == None or (self.cap.fdir + "/" + self.cap.fname) != sel_cap_path:
            #self.popup_import_capture_devices( CaptureDigest(sel_cap_path, gui=True) )
            start = datetime.now()
            self.cap = CaptureDigest(sel_cap_path)


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
        self.unidentifiedDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.cap_dev_title = tk.Label(self.botDevFrame, text="Devices", bg="#dfdfdf", bd=1, relief="flat", anchor="n")

        self.unidentified_title_var=tk.StringVar()
        self.unidentified_title_var.set("Unidentified")
        self.unidentified_title = tk.Label(self.unidentifiedDevFrame, textvariable=self.unidentified_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.unidentified_title.pack(side="top", fill=tk.X)

        self.unidentified_dev_header = ["Manufacturer", "MAC", "IPv4", "IPv6"]
        self.unidentified_dev_list = MultiColumnListbox(parent=self.unidentifiedDevFrame,
                                                   header=self.unidentified_dev_header,
                                                   list=list(), selectmode="browse")
        self.unidentified_dev_list.bind("<<TreeviewSelect>>", self.update_unidentified_list_selection)

        ## Right (Identified) Dev Frame
        self.identifiedDevFrame = tk.Frame(self.botDevFrame, width=300)#, bd=1, bg="#dfdfdf")

        self.identified_title_var=tk.StringVar()
        self.identified_title_var.set("Identified")
        self.identified_title = tk.Label(self.identifiedDevFrame, textvariable=self.identified_title_var, bg="#eeeeee", bd=1, relief="flat")
        self.identified_title.pack(side="top", fill=tk.X)

        self.identified_dev_header = ["Manufacturer", "Model", "Internal Name", "Category", "MAC", "IPv4", "IPv6"]
        self.identified_dev_list = MultiColumnListbox(parent=self.identifiedDevFrame,
                                                 header=self.identified_dev_header,
                                                 list=list(), selectmode="browse")
        self.identified_dev_list.bind("<<TreeviewSelect>>", self.update_identified_list_selection)


        # Grid placements #
        self.topDevFrame.grid(row=0, column=0, sticky="new")
        self.botDevFrame.grid(row=1, column=0, sticky="nsew")
        self.cap_dev_title.grid(row=0, column=0, columnspan=2, sticky="new")
        self.unidentifiedDevFrame.grid(row=1, column=0, sticky="nsew")
        self.identifiedDevFrame.grid(row=1, column=1, sticky="nsew")

        # Grid configuration #
        self.botDevFrame.grid_rowconfigure(1, weight=1)
        self.botDevFrame.grid_columnconfigure(0, weight=1)
        self.botDevFrame.grid_columnconfigure(1, weight=1)

        self.w_cap_dev.grid_rowconfigure(1, weight=1)
        self.w_cap_dev.grid_columnconfigure(0, weight=1)

        '''
        # Select first element of each list
        # Try becuase the list might be empty
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
        self.b_cap_dev_close = tk.Button(self.unidentifiedDevFrame, text='Close', command=(lambda c=self.cap.fname : self.close_w_cap_dev(c)))
        self.b_cap_dev_import = tk.Button(self.unidentifiedDevFrame, text='Import Device', state='disabled',
                             command=(lambda f={'fileName':self.cap.fname,'fileHash':self.cap.fileHash}:
                                          self.popup_import_device(f)))
                                  #command=(lambda e=0, d={'fileName':self.cap.fname,'fileHash':self.cap.fileHash,
                                  #                        'mac_addr':self.unidentified_dev_list.get_selected_row()[1]}:
                                  #             self.popup_import_device(self.unidentified_dev_list.get_selected_row()[e],d)))
                             
        self.b_cap_dev_modify = tk.Button(self.identifiedDevFrame, text='Modify State', state='disabled',
                             #command=(lambda d=self.identified_dev_list.selection(): self.prep_popup_update_device_state(d)))
                             command=(lambda d=self.identified_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))

        self.b_cap_dev_close.pack(side=tk.LEFT, padx=5, pady=5)
        self.b_cap_dev_import.pack(side=tk.RIGHT, padx=5, pady=5)
        self.b_cap_dev_modify.pack(side=tk.RIGHT, padx=5, pady=5)

        # Update unidentified, identified lists and try to select the first element
        self.refresh_unidentified_identified_lists()
        # Select first element of each list
        # Try becuase the list might be empty
        self.unidentified_dev_list.focus(0)
        self.unidentified_dev_list.selection_set(0)
        self.identified_dev_list.focus(0)
        self.identified_dev_list.selection_set(0)

        self.yield_focus(self.w_cap_dev)

    def update_unidentified_list_selection(self, event):
        self.unidentified_dev_list_sel = self.unidentified_dev_list.get( self.unidentified_dev_list.selection() )
        print("self.identified_dev_list_sel = ", self.unidentified_dev_list_sel)

    def update_identified_list_selection(self, event):
        self.identified_dev_list_sel = self.identified_dev_list.get( self.identified_dev_list.selection() )
        print("self.identified_dev_list_sel = ", self.identified_dev_list_sel)

    def prep_popup_update_device_state(self, d):
        d = self.identified_dev_list_sel
        #print("d = ",d)
        mac = d[4]
        self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        print(self.cap.capTimeStamp)
        temp = self.db_handler.db.cursor.fetchone()
        print("temp: ", temp)

        if temp == None:
            fw_ver = ''
        else:
            fw_ver = temp[0]

        device_state_data = {'fileHash'     : self.cap.fileHash,
                             'mac_addr'     : mac.upper(),
                             'internalName' : d[2],
                             'fw_ver'       : fw_ver,
                             #'ipv4_addr'    : self.cap.findIP(mac),
                             #'ipv6_addr'    : self.cap.findIP(mac, v6=True)}
                             'ipv4_addr'    : d[5],
                             'ipv6_addr'    : d[6]}

        print("ipv4:",device_state_data['ipv4_addr'])
        print("ipv6:",device_state_data['ipv6_addr'])
        
        self.popup_update_device_state(device_state_data)

    def close_w_cap_dev(self, capName):

        #Check if any of the devices seen have been added to the device_state table already and add if not
        #for dev in self.identified

        self.populate_device_list(capture = capName)
        self.w_cap_dev.destroy()


    def refresh_unidentified_identified_lists(self):
        # Clear lists
        self.unidentified_dev_list.clear()
        self.identified_dev_list.clear()

        # Sort devices from Capture into either identified or unidentified device lists
        self.db_handler.db.select_device_macs()
        macsInDevTbl = self.db_handler.db.cursor.fetchall()
        #print("macsInDevTbl: ", macsInDevTbl)
        #print()
        #identifiedMacsInDb = self.db_handler.db.cursor.fetchall()
        #print("identifiedMacsInDb: ", identifiedMacsInDb)
        self.db_handler.db.select_identified_devices_from_cap(self.cap.fileHash)
        #macsInDfCTbl = self.db_handler.db.cursor.fetchall()
        #print("macsInDfCTbl: ", macsInDfCTbl)
        devFromCapTbl = self.db_handler.db.cursor.fetchall()
        #print("devFromCapTbl: ", devFromCapTbl)
        #print()

        print("num uniqueMacs:", len(self.cap.uniqueMAC))
        for mac in self.cap.uniqueMAC:
            unidentified = True
            if mac.upper() in [x.upper() for (x,) in macsInDevTbl]:
                # Get device info
                self.db_handler.db.select_device(mac)
                (id, mfr, model, mac_addr, internalName, category, mudCapable, wifi, bluetooth, G3, G4, G5, zigbee, zwave, other, notes, unidentified) = self.db_handler.db.cursor.fetchone()

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

                self.db_handler.db.insert_device_unidentified(device_data)


                # Insert device_state info into device_state table
                #ip = self.cap.findIP(mac)
                #ipv6 = self.cap.findIP(mac, v6=True)
                (ip, ipv6) = self.cap.findIPs(mac)

                self.db_handler.db.insert_device_state_unidentified(
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

            if unidentified:
                self.unidentified_dev_list.append((lookup_mac(mac), mac.upper(), self.cap.findIP(mac), self.cap.findIP(mac, v6=True)))
            else: #May want to include firmware version here
                self.identified_dev_list.append((mfr, model, internalName, category, mac.upper(), ip, ipv6))


            '''
            # Get device state info
            self.db_handler.db.select_device_state(self.cap.fileHash, mac)
            if self.db_handler.db.cursor.rowcount == 1:
                (id, hash, mac_addr, internalName, fw_ver, ip, ipv6) = self.db_handler.db.cursor.fetchone()
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

        # Enable / Disable buttons as deemed necessary
        if self.unidentified_dev_list.num_nodes > 0:
            self.b_cap_dev_import.config(state="normal")
        else:
            self.b_cap_dev_import.config(state="disabled")

        if self.identified_dev_list.num_nodes > 0:
            self.b_cap_dev_modify.config(state="normal")
        else:
            self.b_cap_dev_modify.config(state="disabled")

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

        mfr = self.unidentified_dev_list_sel[0]
        mac = self.unidentified_dev_list_sel[1].upper()
        ipv4 = self.unidentified_dev_list_sel[2]
        ipv6 = self.unidentified_dev_list_sel[3]
        #print("ipv4",ipv4)
        #print("ipv6",ipv6)
        #print(mfr)

        ents = self.make_form_device(deviceFields, deviceOptions, mfr, mac)

        dev_in_cap_data = fname
        dev_in_cap_data['mac_addr'] = mac
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
                
                if option == "wifi" or option == "WiFi":
                    checkvar.set(True)

                entries.append((option, checkvar))

        return entries

    def import_dev_and_close(self, entries, dev_in_cap_data, ips):
        device_data = {"unidentified":False}
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
        #print("mac:", mac)

        # Check if MAC to Mfr entry exists ;lkj
        self.db_handler.db.select_mac_to_mfr()
        mac2mfr = self.db_handler.db.cursor.fetchall()
        #mac_prefix = dev_in_cap_data['mac_addr'].upper()[0:8]
        mac_prefix = mac.upper()[0:8]
        if mac_prefix not in [x for (id, x, mfr) in mac2mfr]:
            #print(entries[0])
            self.db_handler.db.insert_mac_to_mfr({'mac_prefix':mac_prefix, 'mfr':entries[0][1].get()})

        self.refresh_unidentified_identified_lists()

        #mac = dev_in_cap_data['mac_addr']

        self.db_handler.db.select_most_recent_fw_ver({'mac_addr' : mac,
                                                      #'capDate'  : self.cap.capTimeStamp})
                                                      'capDate'  : self.cap.capDate + " " + self.cap.capTime})
        try:
            (fw_ver,) = self.db_handler.db.cursor.fetchone()
        except TypeError as te:
            fw_ver = ''
            
        device_state_data = {'fileHash'     : dev_in_cap_data['fileHash'],
                             'mac_addr'     : mac,
                             'internalName' : device_data['internalName'],
                             'fw_ver'       : fw_ver,
                             #'ipv4_addr'    : self.cap.findIP(mac),
                             #'ipv6_addr'    : self.cap.findIP(mac, v6=True)}
                             'ipv4_addr'    : ips[0],
                             'ipv6_addr'    : ips[1]}

        try:
            self.popup_update_device_state(device_state_data)
        except _mysql_connector.MySQLInterfaceError as msqle:
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
        self.db_handler.db.select_device_state(device_state_data["fileHash"], device_state_data["mac_addr"])
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
        self.cap_list.append(("All...",))

        # Get and insert all captures currently added to database
        self.db_handler.db.select_imported_captures()

        for (id, fileName, fileLoc, fileHash, capDate, activity,
             details) in self.db_handler.db.cursor:
            self.cap_list.append((capDate, fileName, activity, details, fileLoc)) #for early stages
        
        # Set focus on the first element
        self.cap_list.focus(0)
        self.cap_list.selection_set(0)


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
             G3, G4, G5, zigbee, zwave, otherProtocols, notes, unidentified) in self.db_handler.db.cursor:
            self.dev_list.append_unique((mfr, model, internalName, mac_addr, deviceCategory)) #for early stages

        self.dev_list.focus(0)
        self.dev_list.selection_set(0)
        
        #:LKJ
        #self.populate_comm_list(None)


    def update_comm_list(self, event):
        first = True


        self.populate_comm_list()
        return



        #for dev in self.dev_list.curselection():
        for dev in self.dev_list.selection():
            cap_details = self.cap_list.get(cap)
            cap_date = cap_details[0]
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
        h = {"fileHash" : cap.fileHash}
        for p in cap.pkt_info:
            #print("pre update:", p)
            p.update(h)
            #print("post update:", p)
            self.db_handler.db.insert_packet( p )

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
        first = True
        for cap in self.cap_list.selection():
            cap_details = self.cap_list.get(cap)
            cap_date = cap_details[0]

            if cap_date == "All...":
                #self.populate_device_list()
                print("All Captures")
                self.db_handler.db.create_cap_toi()
                break
            else:
                cap_name = cap_details[1] #{'fileName':cap_name}
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
            


        # Selecting based on dev list
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



        # Selecting based on E/W or N/S
        if self.comm_state == "any":
            ew = {"ew":"(TRUE OR FALSE)"}
        elif self.comm_state == "ns":
            ew = {"ew":False}
        elif self.comm_state == "ew":
            ew = {"ew":True}
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
        self.db_handler.db.select_pkt_toi(ew)


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



        i = 0
        for (id, fileHash, pkt_datetime, pkt_epochtime, mac_addr, protocol, ip_ver, ip_src, ip_dst,
            ew, tlp, tlp_srcport, tlp_dstport, pkt_length) in self.comm_list_all_pkts: 
            #self.comm_list.insert(tk.END, [pkt_time, mac_addr, ip_ver, ip_src, ip_dst, ew, 
            #                               protocol, tlp, tlp_srcport, tlp_dstport, pkt_length])

            
            
            self.comm_list.append_unique((pkt_datetime, mac_addr, ip_ver, ip_src, ip_dst, ew, 
                                          protocol, tlp, tlp_srcport, tlp_dstport, pkt_length))
            
            i+=1

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
            if i >= self.comm_list_num_pkts: 
                break

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

        topFrame = tk.Frame(self.w_internal_addr, bd=1, bg="#eeeeee")#, bg="#dfdfdf")
        subtitle = tk.Label(topFrame, text="Current Address Ranges", bg="#eeeeee", bd=1, relief="flat")
        subtitle.pack(side="top", fill=tk.X)

        botFrame = tk.Frame(elf.w_internal_addr, width=300, bd=1, bg="#eeeeee")#, bg="#dfdfdf")

        addr_range_list_header = ["Lower Bound", "Upper Bound", "IP Version"]
        addr_range_list = MultiColumnListbox(parent=botFrame,
                                                   header=addr_range_list_header,
                                                   list=list(), selectmode="browse")
        #To be aded later
        #self.unidentified_dev_list.bind("<<TreeviewSelect>>", self.update_unidentified_list_selection)


        # Grid placements #
        #self.topDevFrame.grid(row=0, column=0, sticky="new")
        #self.botDevFrame.grid(row=1, column=0, sticky="nsew")
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
                                                command=(lambda d=self.identified_dev_list.get_selected_row(): self.prep_popup_update_device_state(d)))

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
    def generate_MUD_wizard(self):
        print("You shouldn't have gotten to the generate MUD wizard yet")
        pass

        self.w_gen_mud = tk.Toplevel()
        self.w_gen_mud.wm_title('Generate MUD File Wizard')
        #current spot developed

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


        

    def generate_report_wizard(self):
        print("You shouldn't have gotten to the generate report wizard yet")




    def popup_about(self):
        w_about = tk.Toplevel()
        w_about.wm_title("About")

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

