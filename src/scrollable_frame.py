import tkinter as tk
from tkinter import ttk

# Borrowed from: https://blog.tecladocode.com/tkinter-scrollable-frames/
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)#, bg="#ffffff")
        canvas.configure(background="white")
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)

        #s = ttk.Style()
        #s.configure('Frame1.TFrame', background="white")
        #s.configure("TFrame", background="white")
        self.scrollable_frame = tk.Frame(canvas, bg="#ffffff")
        #self.scrollable_frame = ttk.Frame(canvas, background="white")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")