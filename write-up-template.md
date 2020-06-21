# HTB - <Machine_Name>

## Overview

![](<machine>.infocard.png)

<Short description to include any strange things to be dealt with> 

## Useful Skills and Tools

#### <Useful thing 1>

<description with generic example>

#### <Useful thing 2>

<description with generic example>

## Enumeration

### Nmap scan

Like always, I started my enumeration with an nmap scan of `<ip>`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, `-oA <name>` saves all types of output \(`.nmap`,`.gnmap`, and `.xml`\) with filenames of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally. The scan only showed one port open during my initial scan so I ran it again to verify, and it came back with the same results.

## Initial Foothold

## Road to User

### Further enumeration

### Finding user creds


### User.txt

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User <username>


### Getting a shell


### Root.txt

Thanks to [`<box_creator>`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
