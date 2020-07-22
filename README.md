# MUD-PD

A tool for characterizing the network behavior of IoT devices particularly for use with MUD (Manufacturer Usage Description)

MUD Specification: https://tools.ietf.org/html/rfc8520 


*Note well: This tool is still in the development phase, and has only been tested on Linux (Ubuntu 18+) and macOS (10.14).  Windows is currently **not** supported, but is in the works.*

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
     or
     ```sh
     shell> sudo apt-get install python3.8
     ```

2. MySQL
   1. MySQL Server

      Follow directions at: https://dev.mysql.com/downloads/mysql/

      Note: may need to create a new user and grant permissions using the following commands:
      ```sh
      shell> sudo mysql -u root -p
      mysql> CREATE USER '<new_user>'@'localhost' IDENTIFIED BY '<new_password>';
      mysql> GRANT ALL PRIVILEGES ON *.* TO '<new_user>'@'localhost';
      mysql> FLUSH PRIVILEGES;
      ```

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

5. Libpcap

   Used for generating packet captures to import into the database and tool 
   * Linux:
   ```sh
   shell> sudo apt-get install tcpdump
   ```
   * macOS: readily available by default
   * Windows: follow instructions at https://nmap.org/npcap/

***Important note about Wireshark:***

   If Wireshark is installed, one of the required Python libraries may conflict with the application. Thus, it is best to ensure that the version of Wireshark installed is 3.2.5 or later.

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

   <ol type="A">
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

1. Create your first database:
   ![Create Database Button](/data/images/mudpd_main_create.png)
   ![Create Database](/data/images/mudpd_DB_create.png)

   * Connect to existing database:
     ![Connect to Database Button](/data/images/mudpd_main_connect.png)
     ![Connect to Database](/data/images/mudpd_DB_connect.png)

2. Import PCAP files:
   ![Import PCAP files](/data/images/mudpd_main_import.png)

## NIST Software License

This software was developed by employees of the National Institute of Standards and Technology (NIST), an agency of the Federal Government and is being made available as a public service. Pursuant to title 17 United States Code Section 105, works of NIST employees are not subject to copyright protection in the United States.  This software may be subject to foreign copyright.  Permission in the United States and in foreign countries, to the extent that NIST may hold copyright, to use, copy, modify, create derivative works, and distribute this software and its documentation without fee is hereby granted on a non-exclusive basis, provided that this notice and disclaimer of warranty appears in all copies. 

THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
