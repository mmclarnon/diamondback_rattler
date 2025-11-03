# pwncat
This folder holds information about the pwncat platform. This was hinted by a 
customer and I determined it was useful for this platform as well. 

The first thing that tripped me up is the conflict of names between the 
following projects

* https://github.com/calebstewart/pwncat
* https://github.com/cytopia/pwncat/tree/master

Other websites and pages seem to indicate that the first link (previous) is
actually a fork of the second. If you visit either of these sites you will
see that neither project has recieved an update in at least three (3) years.

I will focus most of my research on the first project from GitHub and not the
second. 

## Installation
The very first thing I had to accomplish is the 

## Virtual RAT
A phrase that was used to describe pwncat to me was **virtual rat**. The 
principal reason for performing this research was to determine if this is 
possible. To interpret this in my own words, I am trying to determine if I can
create a stand-alone product (pwncat-cs) that can hide details about connecting
to a remote asset (victim) and present a Python interface to me from the same 
machine where I can write Python to actually send commands to/from a target 
in addition to retrieving files, gaining persistence and even adding user(s).

Example python found in this directory deals with a programmatic interface to
a pwncat instance for the purposes of controlling a remote target through
pwncat but from Python script(s).

# URLs
* https://pwncat.readthedocs.io/en/v0.3.1/api/victim.html#