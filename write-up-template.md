# HTB - Machine_Name

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

#### Useful thing 1

description with generic example

#### Useful thing 2

description with generic example

## Enumeration

### Nmap scan

Like always, I started my enumeration with an nmap scan of `<ip>`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the output with a filename of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally. 

## Initial Foothold

## Road to User

### Further enumeration

### Finding user creds


### User.txt

## Path to Power \(Gaining Administrator Access\)

### Enumeration as user `username`


### Getting a shell


### Root.txt

Thanks to [`<box_creator>`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
