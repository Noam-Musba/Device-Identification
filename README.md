# Device-Identification
Device identification on a WIFI network using layer 2 active probing

# Background  
Wi-Fi devices are identified on the network by their MAC address. Over the past couple of years a number of vendors – mainly for mobile devices – implemented randomization of the MAC address upon connection to a new network. This feature assists in preserving a user’s privacy over the internet. However, it also makes it difficult for security solutions to track a device as it moves between different networks and apply the correct security policy. A number of research works describe methods of identifying wireless devices according to a unique “signature” taken from messages sent during connection establishment. These methods cannot be reliably applied in an environment where connection establishment may not be apparent for a security solution – i.e. when a security solution must scan multiple Wi-Fi channels (AKA channel hopping). We look to establish a method for identifying devices (or at least their type) by actively probing a device (represented by some MAC address) with layer 2 message and observing the response.  

We relied mainly on the next 3 articles:  
1. Wi-Fi tracking - Fingerprinting attacks and countermeasures: https://tel.archives-ouvertes.fr/tel-01921596/document
2. Passive Taxonomy of Wifi Clients using MLME Frame Contents:  https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/0b496b91d01a1c26b38b424c6f573803bd9d4398.pdf
3. Channel Switch and Quiet Attack: New DoS Attacks Exploiting the 802.11 Standard, https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.637.6662&rep=rep1&type=pdf

## Goals  
•	Select a set of layer 2 messages to use as probes: We chose [CSA](https://community.infineon.com/t5/Knowledge-Base-Articles/Channel-Switch-Announcement-CSA-in-WICED-KBA229053/ta-p/259344) (Channel Switch Announcement) inside a Beacon frame.  
•	Create code that sends the selected messages (CSA) to a specific MAC address and collect responses. Implemented inside **_attacking_better.py_** file.  
•	Create a “signature” vector for each MAC address based on the responses to the probes. We used the existing signature generator implemented [here](https://github.com/NetworkDeviceTaxonomy/wifi_taxonomy).  
•	Test the uniqueness and usefullness of the signature method. Sketches of the implementation needed for testing are inside **_sig_distribution.py_**.  

## Implementation:  
The scripts are built to work on a Linux enviroment.
### attacking_better.py:  
1. First, we sniff online and catch all the [SSID's](https://www.techtarget.com/searchmobilecomputing/definition/service-set-identifier) around our NIC interface, and save them.  
2. Second, we start looking for devices which we know their SSID, and send them a CSA.  
3. Lastly, another device keeps on listening (for example, with Wireshark) and if an answer has been answered - which should be a probe request - it saves it for the next steps.  

### sig_distribution.py  
1. First, we sniff offline the files we captured with the former step.  
2. Second, after compiling the signature generator mentioned above, we use it to generate a signature to all the devices capture.  
3. Lastly, we check the uniqueness of the signatures: We count the amount of devices with the same signature, for all the signatures. A unique signature barely has any devices (for example, less than 5 devices out of 200 devices overall). The results are printed out, we recommend to print it to a file when running the file.



