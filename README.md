# MUD-PD

A tool for characterizing the network behavior of IoT devices particularly for use with MUD (Manufacturer Usage Description)

MUD Specification: https://tools.ietf.org/html/rfc8520 


*N.B. This tool is still in the development phase, and has only been tested on Linux (Ubuntu 18+) and macOS (10.14).*

## Prerequisites
1. Python 3.7.2+

   * Check version
     ```sh
     shell> python3 --version
     ```
   * Instructions for updating/installing python3 can be found at https://www.python.org/downloads/
     You can also try the following commands
     * macOS:
     ```sh
     shell> brew install python3
     ```

     * Linux
     ```sh
     shell> sudo apt-get install python3.7
     ```

2. MySQL (options)
   1. MySQL Workbench (recommended because this is being used in development)

      Follow directions at https://dev.mysql.com/downloads/workbench/    

   2. If only want MySQL Community Server (theoretically, this should also work)

      Follow directions at https://dev.mysql.com/downloads/mysql/

3. pip (may already be installed)
   * macOS:
   ```sh
   shell> curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
   shell> python3 get-pip.py
   ```

   * Linux:
   ```sh
   shell> sudo apt-get install python3-pip
   ```

4. TkInter for Python3 (may already be installed)
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
   * macOS: readily available by default
   * Windows: follow instructions at https://nmap.org/npcap/



## Installation

1. Install MUD-PD:
   ```sh
   shell> git clone https://github.com/usnistgov/MUD-PD.git
   shell> cd MUD-PD
   shell> pip3 install -r requirements.txt
   ```

2. Install MUDgee: (for MUD file generation)
   * Follow instructions at:  https://github.com/ayyoob/mudgee
   * ***IMPORTANT:***
      * Both the MUDgee and MUD-PD repositories must be installed in the same parent directory
      * Latest verified compatible version: Latest commit f63a88d on Jul 5 2019

## Execution
```sh
shell> python3 mudpd.py
```

## First Steps

   ![MUD-PD GUI at Start-up](/data/images/mudpd_main.png)

1. Create your first database:
   ![Create Database Button](/data/images/mudpd_main_create.png)
   ![Create Database](/data/images/mudpd_DB_create.png)

   * Connect to existing database:
     ![Connect to Database Button](/data/images/mudpd_main_connect.png)
     ![Connect to Database](/data/images/mudpd_DB_connect.png)

2. Import PCAP files:
   ![Import PCAP files](/data/images/mudpd_main_import.png)
