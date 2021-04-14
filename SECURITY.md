<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Security Policy](#security-policy)
  - [Supported Versions](#supported-versions)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Security Policy


## Supported Tool Versions

We anticipate a majority of the applicable vulnerabilities will be the result of vulnerabilities with the APIs and/or 
Python packages used in MUD-PD, or within Python. That said, it is possible there are vulnerabilities within 
MUD-PD itself. The source-code is freely available, and MUD-PD is not intended to be used within a production 
environment in its current form, thus proper security precautions or acknowledgement of the above is expected from 
the user.

Below are the supporting tools used within MUD-PD. If applicable, the latest versions that have been tested and 
verified to work in MUD-PD are included. If vulnerabilities have been identified in any of the versions below, or a 
service has been compromised, please [report the vulnerability](#reporting-a-vulnerability) and include any relevant 
references or documentation.

| Version     | Tool, package, service, etc.                                                                           |
| ----------- | ----------------------------------------------------------------------------------------------------------------- |
| v1.0        | MUD-PD                                                                                                            |
| 3.8 / 3.9   | Python                                                                                                            |
| 8.0.22      | [MySQL Community Server](#https://dev.mysql.com/downloads/mysql/)                                                 |
| 8.0.22      | [mysql-connector-python](#https://dev.mysql.com/downloads/connector/python/)                                      |
| 3.4.4       | [Wireshark (tshark)](#https://www.wireshark.org/#download)                                                        |
| 0.4.3       | [pyshark](#https://pypi.org/project/pyshark/)                                                                     |
| 1434c38...  | [github.com/usnistgov/muddy](#https://github.com/usnistgov/muddy/commit/1434c380cdd49077b273c9aafdb2c7e0ef733636) |
| na          | [Fingerbank](#https://www.fingerbank.org)                                                                         |
| na          | [MA:CV:en:do:rs](#https://www.macvendors.com)                                                                     |
| 2.25.1      | requests                                                                                                          |
| 1.1         | overload                                                                                                          |
| 1.0         | IPy                                                                                                               |
| 1.0.2       | getversion                                                                                                        |
| 8.1.2       | Pillow                                                                                                            |


## Reporting a Vulnerability

Please report (suspected) security vulnerabilities or compromised services to
**[Paul Watrobski](mailto:paul.watrobski@nist.gov?subject=[GitHub]%20MUD-PD%20Vulnerability)**. You will receive a 
response from us within 48 hours. If the issue is confirmed, we will release a notice and patch as soon as 
possible depending on complexity.