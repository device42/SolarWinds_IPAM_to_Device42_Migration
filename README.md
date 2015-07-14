[Device42](http://www.device42.com/) is a comprehensive data center inventory management and IP Address management software 
that integrates centralized password management, impact charts and applications mappings with IT asset management.

This repository contains sample script to take IPAM information from SolarWinds and sends it to Device42 appliance using the REST APIs.


### Requirements
-----------------------------
    * python 2.7.x
    * requests (you can install it with sudo pip install requests or sudo apt-get install python-requests)
    * allow remote connections to SolarWinds TCP port 17778

### Usage
-----------------------------
    * Rename or copy settings.conf.example to settings.conf
    	* add D42 URL/credentials
    	* add SolarWinds URL/credentials
    * Run the script (python swipam_d42.py)
    * If you have any questions - feel free to reach out to us at support at device42.com
    


