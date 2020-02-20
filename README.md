# MUD-PD
**MUD Profiling Database**

A tool for profiling IoT devices particularly for use with MUD

*N.B. This tool is still in the development phase, and has only been tested on Linux (Ubuntu 18+) and macOS (10.14).*

## Prerequisites
0. Git
     * macOS: easiest through an installer such as the one found at: https://www.atlassian.com/git/tutorials/install-git

     * Linux:
     ```sh
     shell> sudo apt-get install git
     ```
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
   1. MySQL Server

      Follow directions at: https://dev.mysql.com/downloads/mysql/

   2. MySQL Workbench (optional)

      (recommended for those who may wish to interact directly with the database and write custom queries)

      Follow directions at: https://dev.mysql.com/downloads/workbench/    

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
   * macOS: instructions can be found at https://python.org/downloads/mac/tcltk/

   * Linux:
   ```sh
   shell> sudo apt-get install python3-tk
   ```

5. LibPcap

   Used for generating packet captures to import into the database and tool 
   * Linux:
   ```sh
   shell> sudo apt-get install tcpdump
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

   ![MUD-PD GUI at Start-up](/data/images/mudpd_main_labeled2.png)

   <ol type="a">
    <li>Connect to existing database</li>
    <li>Create and (re)initialize database</li>
    <li>Import capture file</li>
    <li>Generate MUD file</li>
    <li>Generate device report</li>
    <li>Box containing list of imported capture files</li>
    <li>Box containing list of local devices active on network during traffic captures</li>
    <li>Box containing list of communication within selected capture files</li>
    <li>Inspect selected imported capture file</li>
    <li>Toggle communication view to north/south (external), east/west (internal), or unfiltered traffic</li>
    <li>Future feature not yet enabled. Eventually to filter communication to only that "between" selected devices or any packets to/from "either" device but not necessarily between both</li>
    <li>Limit list of packets in communication box to the selected number</li>
  </ol>

   A. Connect to existing database

   B. Create and (re)initialize database

   C. Import capture file

   D. Generate MUD file

   E. Generate device report

   F. Box containing list of imported capture files

   G. Box containing list of local devices active on network during traffic captures

   H. Box containing list of communication within selected capture files

   I. Inspect selected imported capture file

   J. Toggle communication view to north/south (external), east/west (internal), or unfiltered traffic

   K. Future feature not yet enabled. Eventually to filter communication to only that "between" selected devices or any packets to/from "either" device but not necessarily between both

   L. Limit list of packets in communication box to the selected number

1. Create your first database:
   ![Create Database Button](/data/images/mudpd_main_create.png)
   ![Create Database](/data/images/mudpd_DB_create.png)

   * Connect to existing database:
     ![Connect to Database Button](/data/images/mudpd_main_connect.png)
     ![Connect to Database](/data/images/mudpd_DB_connect.png)

2. Import PCAP files:
   ![Import PCAP files](/data/images/mudpd_main_import.png)