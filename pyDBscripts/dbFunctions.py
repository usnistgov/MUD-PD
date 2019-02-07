#! /usr/bin/python3

import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="MudDB123!"
)

print(mydb)
