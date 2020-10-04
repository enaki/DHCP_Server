# DHCP Server

The current project aimed to implement an application in the form of a one
API (application programming interface) running a DHCP server.

![DHCP FSM](https://github.com/enaky/DHCP_Server/blob/master/Documentation/images/dhcp_fsm.png)

The 2 basic mechanisms for DHCP allocation have been implemented
for assigning addresses:
- Dynamic allocation is the most commonly used method and works by that
each client rents an address from a DHCP server for a period of time.
The server chooses the address dynamically from a shared address group.
- Manual assignment assigns an address to a specific device, just as BOOTP does
it is normally used only for servers and other important permanent hosts.


In order for server to start, you need to set server lease time, address pool, and server name.

### How to run the project
* Go to App directory
* Run ```python3 main.py```

In order to test the dhcp client you can go to client_test folder and run ```python3 client_test.py```. That will simulate a client who is asking for an ip address.

## Technologies used for the front end
The graphical interface was implemented using the tkinter library in python. Application
contains 2 pages:
- page for server configuration (pool-address setting, lease-time,
server name)
- home page (monitoring server activity, static address setting,
forced release of an address, server information)

#### Server configuration page

Through this page, the user sets the address pool by entering an
ip address and a mask. The ip address does not have to be the address of the subnet, the pool
of addresses being chosen so as to contain the address entered.

To start the server, the user has to fill in all 3 of these fields:
setting address pool, 

![Server configuration page](https://github.com/enaky/DHCP_Server/blob/master/Documentation/images/server_configurations.png)

#### Server main page

Through this page, the user can see the general information about the server, the address pool as well as can monitor the activity
server, which has the ‘Save History’ option to save the activity history
in a dhcp_history.txt file.

By checking the ‘Show Packets’ option, the user can view the composition of the packages.

![Server configuration page](https://github.com/enaky/DHCP_Server/blob/master/Documentation/images/server_page.png)

### Dealing with data entry errors

The Messagebox element was used to display input errors data by the user, displaying an appropriate message.

![Error Handling](https://github.com/enaky/DHCP_Server/blob/master/Documentation/images/error_handling.png)

## Code analysis

The application works on 4 threads:
* the main thread for the graphical interface
* the thread on which the DHCP server is running
* the thread for updating the Address Pool Viewer in case an ip address has been taken or
released
* the thread for synchronizing the other threads and activating the Start button when stopped
server

The **DHCP_Packet** class is intended to encode packet fields and decode bytes
received package. To do this, it uses the **DHCP_Packet_Fields dictionary** list and
**DHCP_Options_Fields**, through which the packet can access the length and type of fields and
call the corresponding encoder functions of the Encoder class, respectively the decoding functions
from the Decoder class. For academic purposes, only 7 option fields out of the 255 that the server has
DHCP were treated in the application.

The **DHCP_Server** class is the one that implements the functionality of the DHCP server.
The implementation of the FSM (Finite State Machine) is performed in the *_analyze_data* method in which, at a
received package the followings are checked:
* if the ip address is in the server's address pool and is free.
* whether or not the client's MAC address has an IP address.
* if the server still has free addresses available, etc.

After these things are confirmed, depending on the type of message, the server calls the function
to send a corresponding specific package by the methods: **send_offer**, **send_acknowledge**,
**send_nacknowledge**.

The **DHCP_Server_GUI** class lists the server configuration page and the main page of the
server. The 2 pages, built on the tkinter widget. Frames are invoked by the method
tkinter.tkraise.

### Class Diagram

![Class Diagram](https://github.com/enaky/DHCP_Server/blob/master/Documentation/images/class_diagram.png)
