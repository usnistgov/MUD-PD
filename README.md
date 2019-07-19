# MUDPI
(MUD Profiling for IoT)
A tool for Profiling IoT devices particularly for use with MUD
N.B. This tool is still in the development phase

# Prerequisite
1. Python 3.7.2+
  Check version
```sh
   python3 --version
```
  Install/Update:
```sh
   brew install python3
```
     or
```sh
   Follow instructions at https://www.python.org/downloads/
```

2. MySQL
  a. MySQL Workbench (recommended)

```sh
   Follow directions at https://dev.mysql.com/downloads/workbench/    
```

  b. If only want MySQL Community Server (untested)

```sh
   Follow directions at https://dev.mysql.com/downloads/mysql/
```

3. LibPcap
Used for generating packet captures to import into the database and tool 

```sh
    Linux: ``apt-get install tcpdump''
    OSX: readily available by default.
    Windows: follow instructions at: https://nmap.org/npcap/
```

# Installation

```sh
   git clone https://github.com/usnistgov/MUDPI.git
   cd MUDPI
   pip3 install -r requirements.txt
```
MySQL DB:
```sh
   Follow directions at https://dev.mysql.com/doc/workbench/en/wb-mysql-connections-new.html
```
     or
```sh
  Follow directions at https://dev.mysql.com/doc/refman/5.7/en/creating-database.html

shell> mysql -u username -p

mysql> CREATE DATABASE <your_db_name>;

mysql> USE <your_db_name>
Database changed

shell> mysql -h host -u user -p <your_db_name>
Enter password: ********
```

# Execute
```sh
   python3 mudpi.py
```