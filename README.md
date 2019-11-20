# MUD-PD
MUD Profiling Database (formerly MUD Profiling for IoT (MUDPI))

A tool for Profiling IoT devices particularly for use with MUD

*N.B. This tool is still in the development phase, and has only been tested on Linux (Ubuntu 18+) and macOS (10.14).*

## Prerequisite
1. Python 3.7.2+

   * Check version
     ```sh
     shell> python3 --version
     ```
   * Instructions for updating/installing python3 can be found at: https://www.python.org/downloads/
     You can also try the following commands
     * macOS:
     ```sh
     shell> brew install python3
     ```

     * Linux
     ```sh
     shell> sudo apt-get install python3.7
     ```

2. MySQL
   1. MySQL Workbench (recommended because this is being used in development)

      Follow directions at https://dev.mysql.com/downloads/workbench/    

   2. If only want MySQL Community Server (theoretically, this should also work)

      Follow directions at https://dev.mysql.com/downloads/mysql/

3. pip
   * macOS:
   ```sh
   shell> curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
   shell> python3 get-pip.py
   ```

   * Linux:
   ```sh
   shell> sudo apt-get install python3-pip
   ```

4. Tkinter for Python3 (may already be installed)
   * macOS: iunstructions can be found at python.org/downloads/mac/tcltk/

   * Linux
   ```sh
   shell> sudo apt-get install python3-tk
   ```

5. LibPcap

   Used for generating packet captures to import into the database and tool 
   * Linux:
   ```sh
   shell> apt-get install tcpdump
   ```
   * macOS: readily available by default.
   * Windows: follow instructions at: https://nmap.org/npcap/



## Installation

1. Install tool:
   ```sh
   shell> git clone https://github.com/usnistgov/MUD-PD.git
   shell> cd MUD-PD
   shell> pip3 install -r requirements.txt
   ```

2. Create MySQL Database:

   1. MySQL Server:

      Follow directions at https://dev.mysql.com/doc/refman/5.7/en/creating-database.html

      ```sh
      shell> mysql -u username -p

      mysql> CREATE DATABASE <your_db_name>;

      mysql> USE <your_db_name>
      Database changed

      shell> mysql -h host -u user -p <your_db_name>
      Enter password: ********
      ```

   2. MySQL Workbench

      Follow directions at https://dev.mysql.com/doc/workbench/en/wb-mysql-connections-new.html

3. Install MUDgee: (for MUD file generation)
   * Follow instructions at:  https://github.com/ayyoob/mudgee
   * ***NOTE:*** Both the MUDgee and MUD-PD repositories must be installed in the same parent directory
   * Latest verified compatible version: Latest commit f63a88d on Jul 5 2019

## Execute
```sh
shell> python3 mudpd.py
```