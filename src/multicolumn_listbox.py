'''
Here the TreeView widget is configured as a multi-column listbox
with adjustable column width and column-header-click sorting.
Taken from: https://stackoverflow.com/questions/5286093/display-listbox-with-columns-using-tkinter
'''
try:
    import Tkinter as tk
    import tkFont
    import ttk
except ImportError:  # Python 3
    import tkinter as tk
    import tkinter.font as tkFont
    import tkinter.ttk as ttk

PAD_X = 5

class MultiColumnListbox(object):
    """use a ttk.TreeView as a multicolumn ListBox"""

    def __init__(self, parent, header, list, selectmode="extended", keep1st=False, exclusionList=[]):
        self.parent = parent
        self.header = header
        self.exclusionList = exclusionList
        self.displaycolumns = []

        self.tree = None
        self.num_nodes = 0
        self._setup_widgets(selectmode)
        self._build_tree(list)
        self.keep1st = keep1st
        #self._setup_widgets(header, selectmode)
        #self._build_tree(header, list)


    #def _setup_widgets(self, header, selectmode):
    def _setup_widgets(self, selectmode):
        '''
        s = """\click on header to sort by that column
to change width of column drag boundary
        """
        #msg = ttk.Label(wraplength="4i", justify="left", anchor="n",
            padding=(10, 2, 10, 6), text=s)
        msg.pack(fill='x')
        '''
        container = ttk.Frame(self.parent)
        container.pack(fill='both', expand=True)
        # create a treeview with dual scrollbars
        self.tree = ttk.Treeview(container,columns=self.header, show="headings", selectmode=selectmode) #arg0 "container" added
        vsb = ttk.Scrollbar(container,orient="vertical", command=self.tree.yview) #arg0 "container" added
        hsb = ttk.Scrollbar(container,orient="horizontal", command=self.tree.xview) #arg0 "container" added

        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(column=0, row=0, sticky='nsew', in_=container)
        vsb.grid(column=1, row=0, sticky='ns', in_=container)
        hsb.grid(column=0, row=1, sticky='ew', in_=container)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

    #def _build_tree(self, header, list):
    def _build_tree(self, list):
        #self.header = header
        for col in self.header:
            if col in self.exclusionList:
                continue
            self.displaycolumns.append(col)
            self.tree.heading(col, text=col,#text=col.title(),
                command=lambda c=col: self._sortby(c, 0))
            # adjust the column's width to the header string
            self.tree.column(col,
                #width=tkFont.Font().measure(col.title()))
                width=tkFont.Font().measure(col))

        for item in list:
            self.tree.insert('', 'end', values=item)
            self._adjust_width(item)

        self._update_displayColumns()


    # adjust column's width if necessary to fit each value
    def _adjust_width(self, item):
        for ix, val in enumerate(item):
            col_w = tkFont.Font().measure(str(val) + "__")
            if self.tree.column(self.header[ix],width=None) < (col_w + 2 * PAD_X):
                self.tree.column(self.header[ix], width=(col_w + 2 * PAD_X))


    def _sortby(self, col, descending):
        """sort tree contents when a column header is clicked on"""
        # grab values to sort
        data = [(self.tree.set(child, col), child) \
                    for child in self.tree.get_children('')]
        # if the data to be sorted is numeric change to float
        #data =  change_numeric(data)
        # now sort the data in place
        if self.keep1st:
            first = data.pop(0)
        data.sort(reverse=descending)
        if self.keep1st:
            data.insert(0, first)

        for ix, item in enumerate(data):
            if self.keep1st and ix == 0:
                continue
            self.tree.move(item[1], '', ix)
        # switch the heading so it will sort in the opposite direction
        self.tree.heading(col, command=lambda col=col: self._sortby(col, int(not descending)))

    def _update_displayColumns(self):
        self.displaycolumns=[]

        for h in self.header:
            if h not in self.exclusionList:
                self.displaycolumns.append(h)

        self.tree["displaycolumns"]=self.displaycolumns


    def bind(self, *args, **kwargs):
        self.tree.bind(*args, **kwargs)

    def selection(self, *args, **kwargs):
        #idx = self.tree.get_children()[index]
        #self.focus(idx)
        #self.selection_set(idx)
        print ("self.tree.selection() = ", self.tree.selection())
        return self.tree.selection()

    '''
    def event_generate(self, *args, **kwargs):
        self.tree.event_generate(*args, **kwargs)
    '''

    def get(self, item):
        return self.tree.item(item)["values"]

    def get_selected_row(self):
        #print("self.get( self.selection()[0] = ", self.get( self.selection()[0] ))
        #return self.get( self.selection()[0] )
        sel = self.selection()
        if len(sel) > 0:
            return self.get( self.selection()[0] )
        else:
            return -1

    def focus(self, index):
        #children = self.tree.get_children()
        #if len(children) > 0:
        #    self.tree.focus( children[index] )
        if self.num_nodes > 0:
            self.tree.focus( self.tree.get_children()[index] )
        #idx = self.tree.get_children()[index]
        #self.tree.focus(idx)

    def selection_set(self, index):
        #children = self.tree.get_children()
        #if len(children) > 0:
        #    self.tree.selection_set( children[index] )
        if self.num_nodes > 0:
            self.tree.selection_set( self.tree.get_children()[index] )
        #idx = self.tree.get_children()[index]
        #self.tree.selection_set(idx)

    def append(self, item):
        self.tree.insert('', 'end', values=item)
        # adjust column's width if necessary to fit each value
        self._adjust_width(item)
        self.num_nodes += 1

    def append_unique(self, item):
        children = self.tree.get_children()
        if len(children) == 0:
            self.append(item)
        else:
            unique = True
            for child in children:
                values = self.tree.item(child, 'values')
                if item == values:
                    unique = False
                    break
            if unique:
                self.append(item)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.num_nodes = 0

    def populate(self, item_list):
        for item in item_list:
            self.append(item)

    def populate_unique(self, item_list):
        children = self.tree.get_children()
        if len(children) == 0:
            for item in item_list:
                self.append(item)
        else:
            #print(len(children))
            for item in item_list:
                unique = True
                for child in children:
                    values = self.tree.item(child, 'values')
                    if item == values:
                        unique = False
                        break
                if unique:
                    self.append(item)

    def exclude_column(self, exclusion):
        if exclusion not in exclusionList:
            exclusionList.append(exclusion)
        self._update_displayColumns

    def include_column(self, inclusion):
        if inclusion in exclusionList:
            exclusionList.remove(inclusion)
        self._update_displayColumns


# the test data ...
'''
car_header = ['car', 'repair']
car_list = [
('Hyundai', 'brakes') ,
('Honda', 'light') ,
('Lexus', 'battery') ,
('Benz', 'wiper') ,
('Ford', 'tire') ,
('Chevy', 'air') ,
('Chrysler', 'piston') ,
('Toyota', 'brake pedal') ,
('BMW', 'seat') ,
('test',) ,
()
]
'''
car_header = ['ID','Car', 'Repair']
car_list = [
(1, 'Hyundai', 'brakes') ,
(2, 'Honda', 'light') ,
(3, 'Lexus', 'battery') ,
(4, 'Benz', 'wiper') ,
(5, 'Ford', 'tire') ,
(6, 'Chevy', 'air') ,
(7, 'Chrysler', 'piston') ,
(8, 'Toyota', 'brake pedal') ,
(9, 'BMW', 'seat') ,
(10, 'test',) ,
()
]

def printSelection(tree, event=None):
    #print(type(tree))

    # print(type(tree.partitionsOpenDiskTree))
    # triggered off left button click on text_field
    #textList = tree.item(tree.focus())["values"]

    for sel in tree.selection():
        itemList = tree.item(sel)["values"]
        line = ''
        for item in itemList:
            line += str(item) + " "

        print(line)

        #for (car, repair) in itemList:
            #print(car + " " + item)

    #textList = tree.item(tree.selection())["values"]
    
    #for item in itemList:
        #print(item)

'''
#def clearListbox(tree, event=None):
def clearListbox(tree):
    tree.delete(*tree.get_children())
'''
#def populateListbox(tree, event=None):
def populateListbox(lb):
    for item in car_list:
        lb.append(item)


if __name__ == '__main__':
    root = tk.Tk()
    root.title("Multicolumn Treeview/Listbox")
    #listbox = MultiColumnListbox()
    listbox = MultiColumnListbox(root, car_header, car_list, exclusionList=["ID"])
    listbox.append(('Mazda', 'window'))

    #listbox.tree.bind("<<TreeviewSelect>>", lambda event, lb=listbox.tree: printSelection(lb))
    #listbox.tree.bind("<<TreeviewSelect>>", lambda event, lbt=listbox.tree: printSelection(lbt))
    listbox.bind("<<TreeviewSelect>>", lambda event, lbt=listbox.tree: printSelection(lbt))
    #"<ButtonRelease-1>"

#    b_clear = tk.Button(root, text="Clear", command=(lambda event, lb=listbox.tree: clearListbox(lb)))
    b_clear = tk.Button(root, text="Clear", command=listbox.clear)
#    b_clear = tk.Button(root, text="Clear", command=(lambda lbt=listbox.tree: clearListbox(lbt)))
    b_clear.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

#    b_load = tk.Button(root, text="Load", command=(lambda event, lb=listbox.tree: poplulateListbox(lb)))
    b_load = tk.Button(root, text="Load", command=(lambda lst=car_list: listbox.populate_unique(lst)))
    #b_load = tk.Button(root, text="Load", command=(lambda lb=listbox: populateListbox(lb)))
    b_load.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

    zero = listbox.tree.get_children()[0]
    listbox.tree.focus(zero)
    listbox.tree.selection_set(zero)
    #listbox1 = MultiColumnListbox(root, car_header, car_list)
    #listbox1.append(('Mazda', 'window'))

    root.mainloop()
