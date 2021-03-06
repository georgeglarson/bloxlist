# georgeglarson/bloxlist 
# Gather major blocklists and block with ipset/iptables

- [Introduction](#introduction)
- [Notes](#notes)
- [References](#references)


# Introduction
The purpose of this project is to make a quick and easy solution to rapidly harden new servers by blocking IP addresses and ranges that are listed on major block lists.

The presence of 'ipset' and 'iptables' is (mostly) assumed.

# Notes
While testing this on VPSs, I'm finding that some report 'ipset v6.23: Kernel error received: Operation not permitted'.
OpenVZ/Virtuozzo.
-  https://bugs.openvz.org/browse/OVZ-4116 
-  https://github.com/dannysheehan/iptables-ipset-blacklists/issues/1  
-  https://lists.openvz.org/pipermail/users/2015-October/006550.html


# References
link to post, once it has been posted:  [http://j0rg3.com/](http://j0rg3.com/)



