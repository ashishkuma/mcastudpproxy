Forwards IGMP traffic between external and internal interfaces. And retransmits UDP multicast traffic from external interface to unicast destination endpoint of the internal interface.

Program listens for IGMP messages on your LAN side and joins or leaves multicast group on IPTV VLAN side and then proxies all the multicast data from IPTV VLAN to WLAN in a UDP unicast form. You can't watch several channels at the time on the same computer.
MCastUdpProxy must be started with ADMINISTRATOR PRIVILEGES. In some cases Windows 7`s firewall prevents application to listen for IGMP messages.