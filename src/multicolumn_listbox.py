# Here the TreeView widget is configured as a multi-column listbox
# with adjustable column width and column-header-click sorting.
# Taken from: https://stackoverflow.com/questions/5286093/display-listbox-with-columns-using-tkinter

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
    # use a ttk.TreeView as a multicolumn ListBox
    def __init__(self, parent, header, input_list, select_mode="extended", keep_first=False, exclusion_list=list(),
                 row=None, column=None):
        self.parent = parent
        self.header = header
        self.exclusion_list = exclusion_list
        self.display_columns = list()

        self.container = ttk.Frame(self.parent)

        self.tree = None
        self.num_nodes = 0
        self._setup_widgets(select_mode, row=row, column=column)
        self._build_tree(input_list)
        self.keep_first = keep_first

    def _setup_widgets(self, select_mode, row=None, column=None):
        #container = ttk.Frame(self.parent)
        if row is None and column is None:
            self.container.pack(fill='both', expand=True)
        else:
            self.container.grid(row=row, column=column, sticky="nsew")
        # create a treeview with dual scrollbars
        self.tree = ttk.Treeview(self.container, columns=self.header, show="headings", selectmode=select_mode)
        vsb = ttk.Scrollbar(self.container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.container, orient="horizontal", command=self.tree.xview)

        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(column=0, row=0, sticky='nsew', in_=self.container)
        vsb.grid(column=1, row=0, sticky='ns', in_=self.container)
        hsb.grid(column=0, row=1, sticky='ew', in_=self.container)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

    def _build_tree(self, input_list):
        for col in self.header:
            if col in self.exclusion_list:
                continue
            self.display_columns.append(col)
            self.tree.heading(col, text=col, command=lambda c=col: self._sortby(c, 0))

            # adjust the column's width to the header string
            self.tree.column(col, width=tkFont.Font().measure(col))

        for item in input_list:
            self.tree.insert('', 'end', values=item)
            self._adjust_width(item)

        self._update_displayColumns()

    # adjust column's width if necessary to fit each value
    def _adjust_width(self, item):
        for ix, val in enumerate(item):
            col_w = tkFont.Font().measure(str(val) + "__")
            if self.tree.column(self.header[ix], width=None) < (col_w + 2 * PAD_X):
                self.tree.column(self.header[ix], width=(col_w + 2 * PAD_X))

    # Sort tree contents when a column header is clicked on
    def _sortby(self, col, descending):
        # grab values to sort
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]

        # now sort the data in place
        if self.keep_first:
            first = data.pop(0)
        data.sort(reverse=descending)
        if self.keep_first:
            data.insert(0, first)

        for ix, item in enumerate(data):
            if self.keep_first and ix == 0:
                continue
            self.tree.move(item[1], '', ix)
        # switch the heading so it will sort in the opposite direction
        self.tree.heading(col, command=lambda col=col: self._sortby(col, int(not descending)))

    def _update_displayColumns(self):
        self.display_columns = list()

        for h in self.header:
            if h not in self.exclusion_list:
                self.display_columns.append(h)

        self.tree["displaycolumns"] = self.display_columns

    def bind(self, *args, **kwargs):
        self.tree.bind(*args, **kwargs)

    def selection(self):  # , *args, **kwargs):
        print("self.tree.selection() = ", self.tree.selection())
        return self.tree.selection()

    '''
    def event_generate(self, *args, **kwargs):
        self.tree.event_generate(*args, **kwargs)
    '''

    def get(self, item):
        return self.tree.item(item)["values"]

    def get_selection_set(self):
        sel = self.selection()

        sel_val = list()
        for s in sel:
            sel_val.append(self.get(s))

        return sel_val

    def get_list(self):
        temp_list = []
        for child in self.tree.get_children():
            temp_list.append(self.tree.item(child)["values"])
        return temp_list

    def get_selected_row(self):
        sel = self.selection()
        if len(sel) > 0:
            return self.get(self.selection()[0])
        else:
            return -1

    def focus(self, index):
        if self.num_nodes > 0:
            self.tree.focus(self.tree.get_children()[index])

    def selection_set(self, index):
        if self.num_nodes > 0:
            self.tree.selection_set(self.tree.get_children()[index])

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
        if exclusion not in self.exclusion_list:
            self.exclusion_list.append(exclusion)
        self._update_displayColumns

    def include_column(self, inclusion):
        if inclusion in self.exclusion_list:
            self.exclusion_list.remove(inclusion)
        self._update_displayColumns

    def is_empty(self):
        if self.num_nodes == 0:
            return True
        else:
            return False

    def remove_by_value(self, value, column):
        children = self.tree.get_children()
        if len(children) > 0:
            for child in children:
                values = self.tree.item(child, 'values')

                if str(value) == values[column]:
                    self.tree.delete(*[child])
                    return

    def remove_exact(self, item):
        if self.tree.exists(item):
            self.tree.delete(*[item])


def printSelection(tree):  # , event=None):
    # print(type(tree))

    # print(type(tree.partitionsOpenDiskTree))
    # triggered off left button click on text_field
    # textList = tree.item(tree.focus())["values"]

    for sel in tree.selection():
        itemList = tree.item(sel)["values"]
        line = ''
        for item in itemList:
            line += str(item) + " "

        print(line)


'''
#def clearListbox(tree, event=None):
def clearListbox(tree):
    tree.delete(*tree.get_children())
'''


def populateListbox(lb):
    for item in car_list:
        lb.append(item)


# Unit test
if __name__ == '__main__':
    root = tk.Tk()
    root.title("Multicolumn Treeview/Listbox")

    car_header = ['ID', 'Car', 'Repair']
    car_list = [
        (1, 'Hyundai', 'brakes'),
        (2, 'Honda', 'light'),
        (3, 'Lexus', 'battery'),
        (4, 'Benz', 'wiper'),
        (5, 'Ford', 'tire'),
        (6, 'Chevy', 'air'),
        (7, 'Chrysler', 'piston'),
        (8, 'Toyota', 'brake pedal'),
        (9, 'BMW', 'seat'),
        (10, 'test',)
    ]
    listbox = MultiColumnListbox(root, car_header, car_list, exclusion_list=["ID"])
    mazda = (11, 'Mazda', 'window')
    # listbox.append((11, 'Mazda', 'window'))

    # listbox.tree.bind("<<TreeviewSelect>>", lambda event, lb=listbox.tree: printSelection(lb))
    # listbox.tree.bind("<<TreeviewSelect>>", lambda event, lbt=listbox.tree: printSelection(lbt))
    listbox.bind("<<TreeviewSelect>>", lambda event, lbt=listbox.tree: printSelection(lbt))
    # "<ButtonRelease-1>"

    # b_clear = tk.Button(root, text="Clear", command=(lambda event, lb=listbox.tree: clearListbox(lb)))
    b_clear = tk.Button(root, text="Clear", command=listbox.clear)
    # b_clear = tk.Button(root, text="Clear", command=(lambda lbt=listbox.tree: clearListbox(lbt)))
    b_clear.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

    # b_load = tk.Button(root, text="Load", command=(lambda event, lb=listbox.tree: poplulateListbox(lb)))
    b_load = tk.Button(root, text="Load", command=(lambda lst=car_list: listbox.populate_unique(lst)))
    # b_load = tk.Button(root, text="Load", command=(lambda lb=listbox: populateListbox(lb)))
    b_load.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

    b_add = tk.Button(root, text="Add", command=(lambda mzda=mazda: listbox.append_unique(mzda)))
    b_add.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

    b_remove = tk.Button(root, text="Remove", command=(lambda val=11, col=0: listbox.remove_by_value(val, col)))
    b_remove.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)

    print("listbox.tree.get_children()[1]", listbox.tree.get_children()[1])
    # print("listbox.tree.identify_column(0)", listbox.tree.identify_column('ID'))
    print("listbox.tree.column('ID', option='id')", listbox.tree.column('ID', option='id'))
    print("")
    print("child")

    zero = listbox.tree.get_children()[0]
    listbox.tree.focus(zero)
    listbox.tree.selection_set(zero)
    # listbox1 = MultiColumnListbox(root, car_header, car_list)
    # listbox1.append(('Mazda', 'window'))

    root.mainloop()
