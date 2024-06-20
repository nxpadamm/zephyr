Zephyr Wi-Fi webconfig
==================

Overview
--------

This demo implements a simple web based Wi-Fi configuration utility for connecting the board to the local wireless network.

Initially, the board doesn't have the credentials to join the local network, so it starts its own Access Point with SSID: "webconfig_access_point" and password: "ap012345".

The user can connect their device to this SSID and access the Web UI. The board will scan for the nearby Wi-Fi networks and display a list of them on this page. By clicking on the entries, the user can choose their network, enter the credentials and connect. The board will attempt to join this Wi-Fi network as a client. If successful, the device will be reachable on that network at a given IP address.

The web UI allows the user to reset the board to AP mode. This will effectively call a wifi disconnect from the current network.

Requirement
-----------

Board with supported Wi-Fi networking.

Up-to-date web browser.

Building and running the application
-------------------------------

To build and run the application:

.. code-block:: bash

   $ west build -p auto -b <board_to_use> -t run samples/net/wifi_webconfig

Then follow instructions printed to Zephyr shell.

Use a web browser (Chrome, Edge...) to connect to the device's HTTP service, where the host name is the wifi uAP IP address.
