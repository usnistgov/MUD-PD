# MUDPI
(MUD Profiling for IoT)
A tool for Profiling IoT devices particularly for use with MUD
N.B. This tool is still in the development phase

## Prerequisite
1. Python 3.7.2+

   * Check version
     ```sh
shell> python3 --version
     ```
   * Install/Update:
     ```sh
shell> brew install python3
     ```
     or

     Follow instructions at https://www.python.org/downloads/

2. MySQL
   1. MySQL Workbench (recommended)

      Follow directions at https://dev.mysql.com/downloads/workbench/    

   2. If only want MySQL Community Server (untested)

      Follow directions at https://dev.mysql.com/downloads/mysql/


3. LibPcap

   Used for generating packet captures to import into the database and tool 
   ```sh
   Linux: ``apt-get install tcpdump''
   OSX: readily available by default.
   Windows: follow instructions at: https://nmap.org/npcap/
   ```

## Installation

1. Install tool
   ```sh
   shell> git clone https://github.com/usnistgov/MUDPI.git
   shell> cd MUDPI
   shell> pip3 install -r requirements.txt
   ```

1. Create MySQL Database:

   1. MySQL Workbench

      Follow directions at https://dev.mysql.com/doc/workbench/en/wb-mysql-connections-new.html

      or

   2. MySQL Server:

      Follow directions at https://dev.mysql.com/doc/refman/5.7/en/creating-database.html

      ```sh
      shell> mysql -u username -p

      mysql> CREATE DATABASE <your_db_name>;

      mysql> USE <your_db_name>
      Database changed

      shell> mysql -h host -u user -p <your_db_name>
      Enter password: ********
      ```

## Execute
```sh
shell> python3 mudpi.py
```