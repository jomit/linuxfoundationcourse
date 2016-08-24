Documentation (Man pages, GNU Info System, and the help command)
================================================================
$ man <topic>
$ man -f <topic>
$ man -k <topic>
$ man -a <topic>
$ <command> --help
$ <command> -h
$ info <topic>
$ help

http://linuxcommand.org/tlcl.php

$ uname -r 					(check kernel version)
$ cat /etc/redhat-release	(check RHEL version)

$ sudo su - root
$ yum -y update kernel		(update kernel, does not work in Azure)


Basic Operations
================================================================
$ which <application name>   (to location the location of application)
$ whereis <application name>   (to location the location of application)

$ pwd 		(present working directory)

$ ls -a 		(to view hidden files)

$ tree     	(if tree is not installed "yum install tree")
$ tree -d  	(only directories`)
$ tree -a   	(hidden files)

$ ln -s file1 file2   (create symbolic/soft links)
$ ls -li   		(to view files with object ids)

$ pushd, popd    (to retain directory browing history)


I/O Stream
------------------------
$ [do_something] < [inputfile]
$ [do_something] > [outputfile]
$ [do_something] 2> [errorfile]
$ [do_something] >& [all_outputfile]

Search Files
-----------------------------
$ locate zip | grep bin   (lists all files/directories with zip and bin in name)

(locate uses database from "updatedb")

$ find /usr -name gcc
$ find -name "*.swp"
$ find -name "*.swp" -exec rm {} ’;’    (find all files with .swp and remove them)

$ find / -size 0
$ find / -size +10M

$ find -ctime 1


View Files
------------------------------
$ cat, tac, less, tail, head

$ touch mytestfile1.txt						(create empty file)
$ touch -t 201503201600 mytestfile1.txt		(change timestamp of file 2015, March, 20, 4 pm)

$ rmdir test1   
$ rm -rf test1  						(remove directory with all its content)
$ rm -i test1.txt
$ rm -f test1.txt
$ mv  oldfile.txt newfilename.txt		(rename file)

$ echo $PS1

Install Apps
------------------------------
(Ubuntu - dpkg)

$ sudo apt-cache search lynx
$ sudo apt-get install lynx
$ sudo apt-cache policy lynx
$ sudo apt-get remove lynx 
$ sudo dpkg -l
$ sudo apt-get upgrade

(RHEL - rpm)
$ sudo yum search lynx
$ sudo yum install lynx
$ sudo yum info lynx
$ sudo yum remove lynx 
$ sudo yum list installed
$ sudo yum update


File System
--------------------------------
$ mount      (shows all mapped drives /dev/sd01, /dev/sd02 . . .)
$ less /etc/fstab   (shows file system table file)
$ df  -Th     (disk free utility)

$ less /proc/cpuinfo
$ less /proc/partitions
$ less /proc/meminfo

$ ps    (list all processes)

$ diff test1.txt test2.txt
$ diff3    
$ diff -Nur test2.txt test1.txt > patchfile.txt
$ patch test1.txt patchfile.txt or patch -p1 < patchfile

$ file test1.txt     (shows type of file)



Backing up and Compressing Data
------------------------------------
$ rync originalfile.txt newfile.txt
$ rync -r folder1 folder2         (backup folder1 to folder2)


$ gzip *
$ gzip -r folder1
$ gzip -d folder1/hello    (Decompress file named hello.gz inside folder1)

$ bzip2 *
$ bzip2 -d *.bz2

$ xz *
$ xz -d test.xz

(for viewing Windows Zip files)
$ zip backup *     
$ unzip backup.zip 

("tape archive")
$ tar -zcvf folder1.tar.gz folder1    (create the archive and compress with gzip)
$ tar -jcvf folder1.tar.bz2 folder1
$ tar -Jcvf folder1.tar.xz folder1
$ tar -xvf folder1.tar.gz       (extract all files in the archive in folder1 directory)
$ tar -xvf folder1.tar
$ tar zcvf abc.tar.tgz ~    (~ is for users home directory including sub directory)


$ dd if=/dev/sda of=/dev/sdb    (COPY ENTIRE DISK with MASTER BOOT RECORD TO ANOTHER DISK)



User Environment
================================================================

Accounts
-------------------------
$ who       (see all logged in users)
$ who -a
$ whoami
$ id
$ less /etc/passwd,  less /etc/group


$ sudo useradd turkey
$ sudo userdel turkey
$ sudo userdel -r turkey	  (removes home directory)

$ sudo /usr/sbin/groupadd mynewgroup
$ groups turkey
$ sudo /usr/sbin/usermod -G mynewgroup turkey 		(add user turkey to mynewgroup)
$ groups turkey

$ sudo /usr/sbin/usermod -G turkey turkey     (remove user from a group, bit tricker)
$ sudo /usr/sbin/groupdel mynewgroup


Startup Files
----------------------------------------------
(Sequence of files read and evaluated on your first login)
1) ~/.bash_profile
2) ~/.bash_login
3) ~/.profile 

.bashrc file
(The .bash_profile will have certain extra lines, which in turn will collect the required customization parameters from .bashrc.)

$ cat ~/.bashrc
$ cat ~/.bash_profile


Environment Variables
----------------------------
(3 ways to see environment variables)
$ set
$ env
$ export


$ echo $SHELL    (See value of specific variable)
$ export JOMIT=1    (export variable temporary)
$ nano ~/.bashrc    (export variable permanently)
  add this line "export JOMIT=1"

$ echo PATH
$ export PATH=$HOME/bin:$PATH		(add a bin directory to your path)

$ echo $PS1		(\u, \h, \w, \! and \d options to change the prompt)
$ echo $SHELL

$ history		(information of last used commands, stored in ~/.bash_history)
$ echo $HISTFILE $HISTFILESIZE $HISTSIZE

$ !1   (to run the first command from history)
$ !sl   (to run the first command that starts with 'sl')

Keyboard Shortcuts
----------------------------------------------
CTRL-L 	Clears the screen
CTRL-D 	Exits the current shell
CTRL-Z 	Puts the current process into suspended background
CTRL-C 	Kills the current process
CTRL-H 	Works the same as backspace
CTRL-A 	Goes to the beginning of the line
CTRL-W 	Deletes the word before the cursor
CTRL-U 	Deletes from beginning of line to cursor position
CTRL-E 	Goes to the end of the line
Tab 	Auto-completes files, directories, and binaries


$ alias 			(list all aliases)
$ alias gohome='cd /home/jomit'		(create new aliax 'gohome')


File Permissions
------------------------------------------
read (r), write (w), execute (x)
user/owner (u), group (g), and others (o)

$ ls -l		(list all files with permission details)
$ ls -l test1.txt

$ chmod uo+x,g-w test1.txt	(add execute(x) to user (u) and others (o) and remove write(w) from group (g))

read = 4, write = 2, execute = 1
755 = user (rwx), group(rx), other (rx)

$ chmod 755 test1.txt

$ sudo chown root test1.txt		(change file ownership)
$ sudo chgrp bin test1.txt		(change file group)


Text Editors
=============================================================
(create files without text editors)

$ echo line one > mynewfile
$ echo line two >> mynewfile
$ echo line three >> mynewfile

$ cat << EOF > mynewfile1			(type 'EOF' to end file editing)
$ nano mynewfile1

$ vimtutor		(to learn about "vi" commands)

("vi" commands)

vi myfile 		Start the vi editor and edit the myfile file
vi -r myfile 	Start vi and edit myfile in recovery mode from a system crash
:r file2 		Read in file2 and insert at current position
:w 				Write to the file
:w myfile 		Write out the file to myfile
:w! file2 		Overwrite file2
:x or :wq 		Exit vi and write out modified file
:q 				Quit vi
:q! 			Quit vi even though modifications have not been saved

:! 			(to run external commands)
:1 wc %		(word count of file)


Security Principles
===================================================================
4 types of accounts:  
--------------------
root
System
Normal
Network

$ last		(show who logged in last and help remove unused accounts)
$ sudo useadd jack
$ passwd jack

$ su and sudo 		(are very different)
$ sudo cat /etc/sudoers
$ sudo ls /etc/sudoers.d
$ sudo cat /etc/sudoers.d/waagent
	jomit 	ALL 	= (ALL) 		ALL
	(who) (where)	=  (as_whom)	(what)
	
$ sudo less /var/log/secure			(view security log)
$ sudo less /var/log/auth.log 		(view login attempt failures in Debian)
$ sudo less /var/log/messages 		(view login attempt failures in other distributions)

Process Isolation
---------------------------
cgroups, LXC

Hardware device access
---------------------------
$ ls -l /dev/sda1

Passwords store
---------------------------
$ /etc/passwd   		(uses SHA-512)
$ /etc/shadow			(encrypted password are stored here, uses SHA-512)
$ echo -n test | sha512sum		(create SHA of the string "test")

Use Password Authtentication Module (PAM) to verify strong passwords
pam_cracklib.so
pam_passwdqc.so

Use "John the Ripper password cracker" (http://www.openwall.com/john/) to detect weak password entries

$ chage   (sets days for password reset so if password is cracked it can only be used for limited time)
$ man chage   (use this to see documentation of "chage" command)


Requiring Boot Loader Passwords
--------------------------------
For GRUB 1.0
~~~~~~~~~
$ grub-md5-crypt	(copy the encrypted password)

then edit /boot/grub/grub.conf by adding the following line below the timeout entry:
password --md5 $1$Wnvo.1$qz781HRVG4jUnJXmdSCZ30

For GRUB 2.0
~~~~~~~~~
You edit system configuration files in /etc/grub.d
$ update-grub

more details => https://help.ubuntu.com/community/Grub2/Passwords.



Network Operations
===================================================================
Fundamentals:
~~~~~~~~~~~~~~~~~
Class A network 
- can have up to 16.7 million unique hosts on its network. 
- range of host address is from 1.0.0.0 to 127.255.255.255.

Class B network 
- can support a maximum of 65,536 unique hosts on its network. 
- range of host address is from 128.0.0.0 to 191.255.255.255.

Class C network 
- can support up to 256 (8-bits) unique hosts. 
- range of host address is from 192.0.0.0 to 223.255.255.255.


$ ipcalc 	(to ascertain the host range, works different in Fedora family of distributions)
$ hostname	(identity hostname of the machine)
$ cat /etc/hosts
$ cat /etc/resolv.conf
$ host linuxfoundation.org
$ nslookup linuxfoundation.org
$ dig linuxfoundation.org

$ ifconfig		(or /sbin/ifconfig)


Networking Configuration:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Debian
$ sudo cat /etc/network/interfaces
$ sudo /etc/init.d/networking start

Fedora/SUSE
$ sudo cat /etc/sysconfig/network
$ sudo cat /etc/sysconfig/network-scripts/ifcfg-eth0		(network config script)
$ sudo /etc/init.d/network start	(start the networking configuration)


$ /sbin/ip addr show		(new "ip" command to show ip address. "ifconfig" is old command)
$ /sbin/ip route show		(new "ip" command to show route)
$ ping jomit.net


$ route –n					(Show current routing table)
$ route add -net address	(Add static route)
$ route del -net address	(Delete static route)
$ traceroute jomit.net

$ sudo ethtool eth0				(Query network interfaces)
$ netstat -r					(display active connections and routing tables)
$ sudo nmap -sP 172.168.0.0/24	(scans open ports. $ sudo yum install nmap -y)
$ tcpdump		(dumps network traffic for analysis)
$ iptraf		(monitors network traffic in text mode)


Graphical and Non Graphical Browsers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Text based browsers
- lynx
- links or elinks
- w3m


$ wget linuxfoundation.org		(download file)
$ curl http://www.linuxfoundation.org
$ curl -o saved.html http://www.linuxfoundation.org

Command line FTP clients
- ftp
- sftp
- ncftp
- yafc   (Yet Another Ftp Client)

$ ftp -p aristotle.learningmate.com
ftp>get <filename>

$ ssh		(secure shell)
$ scp <localfile> <user@remotesystem>:/home/user/	(secure copy)




Manipulating Text
===========================================================
$ cat > file1			(new file, CTRL + D to exit)
$ cat > file2			(new file, CTRL + D to exit)
$ cat >> file1			(append file, CTRL + D to exit)
$ cat file1 file2
$ cat file1 file2 > newfile			(combine multiple files)
$ cat file >> existingfile			(append to existing file)

$ tac	(does what "cat" does but in reverse order)

$ echo $USER
$ echo "abcd"

sed = stream editor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$ sed s/is/are test1			(Substitute first occurrence of "is" with "are" in a line)
$ sed s/is/are/g test1			(Substitute all occurrences of "is" with "are" in a line)
$ sed s/is/are/g test1 > test2  (replace all occurrences of "is" with "are" in test1 and move the contents to test2)
$ mv test2 test1				(overwrite the original file1)

$ sed -i s/is/are/g test1	(Save changes for string substitution in the same file)


awk = 	(last name of authors: Alfred "A"ho, Peter "W"einberger, and Brian "K"ernighan)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Used for data extraction and reporting


$ awk '{ print $0 }' /etc/passwd
$ awk -F: '{ print $1 }' /etc/passwd		(print 1st field of every line)
$ awk -F: '{ print $1 $6 }' /etc/passwd		(print 1st and 6th field of every line)	



Utilities
~~~~~~~~~~~~~~~~~~~~~
$ sort test1
$ cat test1 test2 | sort
$ sort -r test1				(sort in reverse order)
$ sort -u test1 			(looks for unique values similar to "uniq")
$ sort test1 | uniq			(looks for unique values)
$ sort test1 | uniq	-c		(to cound duplicate values)

$ paste -d ':' file1 file2	(combile columns from multiple files with a delimeter)

$ join file1 file2	(only use space as the delimiter to join columns from multiple files)

$ split file1 dict	(splits file)

$ grep [pattern] file1		 	Search for a pattern in a file and print all matching lines
$ grep -v [pattern] file1 		Print all lines that do not match the pattern
$ grep [0-9] file1 				Print the lines that contain the numbers 0 through 9
$ grep -C 3 [pattern] file1 	Print context of lines (3 lines above and below the pattern) for matching the pattern.


$ cat file1 | tr a-z A-Z								(Translate from lowercase to uppercase in file1)	
$ tr '{}' '()' < inputfile > outputfile 				(Translate braces into parenthesis)
$ echo "This is for testing" | tr [:space:] '\t' 		(Translate white-space to tabs)
$ echo "This   is   for    testing" | tr -s [:space:]	(Squeeze repetition of characters using -s)
$ echo "the geek stuff" | tr -d 't' 					(Delete specified characters using -d option)
$ echo "my username is 432234" | tr -cd [:digit:] 		(Complement the sets using -c option)
$ tr -cd [:print:] < file.txt 							(Remove all non-printable character from a file)
$ tr -s '\n' ' ' < file.txt 							(Join all the lines in a file into a single line)

$ ls -l | tee newfile				("tee" it tees the output stream and saves it to file)

$ wc -l -c -w newfile		(display lines, bytes and words in the file)

$ ls -l | cut -d" " -f3		(use "cut" to extract columns from file)

$ less newfile
$ cat newfile | less

$ head –n 5 newfile		(display first 5 lines from newfile)
$ tail –n 5 newfile		(display last 5 lines from newfile)

$ strings book1.xls | grep test		(find string "test" in an excel file)

$ zcat compressed-file.txt.gz 		(To view a compressed file)
$ zless <filename>.gz
or
$ zmore <filename>.gz 				(To page through a compressed file)
$ zgrep -i less test-file.txt.gz 	(To search inside a compressed file)

$ zdiff filename1.txt.gz filename2.txt.gz

Regular expression/ Search Patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.(dot) 	(Match any single character)
a|z 	(Match a or z)
$ 		(Match end of string)
* 		(Match preceding item 0 or more times)

Example:  "the quick brown fox jumped over the lazy dog"
-------------------------------
a.. 	matches azy
b.|j. 	matches both br and ju
..$ 	matches og
l.* 	matches lazy dog
l.*y 	matches lazy
the.* 	matches the whole sentence



Bash Scripting
===============================================================
#!/bin/bash
find . -name "f*" -ls

$ cat /etc/shells


$ cat > exscript.sh
  #!/bin/bash
  echo "HELLO"
  echo "WORLD"
$ bash exscript.sh		or 
$ chmod 755 exscript.sh
$ ./exscript.sh

$ cat > ioscript.sh
	#!/bin/bash
	# comments here
	echo "Enter your name:"
	read name
	echo "Hello" $name
$ chmod +x ioscript.sh
$ ./ioscript.sh


Return Values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ ls /etc/passwd
$ echo $?			("$?" shows return value)


Long Commands in multiple lines:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ scp abc@server1.linux.com:\
/var/ftp/pub/userdata/custdata/read \
abc@server3.linux.co.in:\
/opt/oradba/master/abc/


Multiple Commands on a Single Line
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ make ; make install ; make clean			(will continue all commands even if one fails)
$ make && make install && make clean		(if one command fails, subsequent commands will fail)
$ cat file1 || cat file2 || cat file3		(continue until something succeeds, and then stop executing)


Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ cat > funcfile.sh
#!/bin/bash
display(){
	echo "this is the message from " $1
}
display "jack"
display "jomit"
display "jim"

Command Substitution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ cd /lib/modules/$(uname -r)/
$ cd /lib/modules/`uname -r`/



Exporting Variables
~~~~~~~~~~~~~~~~~~~~
By default, the variables created within a script are available only to the subsequent steps of that script. 
Any child processes (sub-shells) do not have automatic access to the values of these variables. 
To make them available to child processes, they must be promoted to environment variables using the export statement as in:

$ export VAR=value
or
$ VAR=value ; export VAR


Script Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ ./script.sh 100 200

$0 				(Script name)
$1 				(First parameter)
$2, $3, etc. 	(Second, third parameter, etc.)
$* 				(All parameters)
$# 				(Number of arguments)


Input Redirection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ free > /tmp/free.out
$ cat /tmp/free.out
$ wc -l < /tmp/free.out


if statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ cat > condition.sh
	#!/bin/bash
	file=$1
	if [ -f $file ]
	then
	  echo -e "The $file exists"
	else
	  echo -e "The $file does not exist"
	fi
$ chmod +x condition.sh
$ bash condition.sh file1

elif statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#!/bin/bash
echo "enter a number"
read number
if [ $number > 100 ]
then
	  echo "Cool"
elif [ $number > 50 ]
then
	  echo "Nice"
elif [ $number > 10 ]
then
	  echo "Good"
else
	  echo "Bad !!"
fi

File conditionals in Bash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if [ -f /etc/passwd ] ; then
    ACTION
fi

-e file 	Check if the file exists.
-d file 	Check if the file is a directory.
-f file 	Check if the file is a regular file (i.e., not a symbolic link, device node, directory, etc.)
-s file 	Check if the file is of non-zero size.
-g file 	Check if the file has sgid set.
-u file 	Check if the file has suid set.
-r file 	Check if the file is readable.
-w file 	Check if the file is writable.
-x file 	Check if the file is executable.

$ man 1 test		(View all conditionals)



Arithmetic functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$ let x=( 1 + 2 ); echo $x

$ expr 2 + 3


Advanced Bash Scripting
=================================================================================

String manipulation
~~~~~~~~~~~~~~~~~~~~~~~~
[[ string1 > string2 ]] 	Compares the sorting order of string1 and string2.
[[ string1 == string2 ]] 	Compares the characters in string1 with the characters in string2.
myLen1=${#string1} 			Saves the length of string1 in the variable myLen1.

$ export name="www.jomit.net"				(creates a variable)
$ subdomain=${name:0:3}; echo $subdomain	(prints "www")
$ domain=${name#*.}; echo $domain			(prints "jomit.net")


case statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#!/bin/bash
echo "enter alphabet"
read name
case "$name" in
	"a"|"A") echo "alpha";;
	"b"|"B") echo "beta";;
	*) echo "gamma";;
esac
exit 0
	

for statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#!/bin/bash
sum=0
for i in 1 2 3 4 5
do
	sum=$(($sum+$i))
done
echo "The sum of $i numbers is $sum"


while statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#!/bin/bash
echo "enter number"
read num
fact=1
i=1
while [ $i -le $num ]
do
	fact=$(($fact * $i))
	i=$(($i + 1))
done
echo "The factorial for $num is $fact"


Script Debugging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ bash -x whiletest.sh

set -x		(turns on debugging inside the bash script)
set +x		(turns off debugging inside the bash script)

stdin 	0	Standard Input, by default the keyboard/terminal for programs run from the command line
stdout 	1 	Standard output, by default the screen for programs run from the command line
stderr 	2 	Standard error, where output error messages are shown or saved

$ bash whiletest.sh 2> error.txt	(save stderr output in error.txt)


Creating Temporary files and directories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TEMP=$(mktemp /tmp/tempfile.XXXXXXXX) 
TEMPDIR=$(mktemp -d /tmp/tempdir.XXXXXXXX) 	


Discarding Output with /dev/null
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"/dev/null" file is also called the bit bucket or black hole.

$ find / > /dev/null

Random Numbers
~~~~~~~~~~~~~~~~~~~~~~~~~
Uses FIPS140 algorithm to generate random numbers (see http://en.wikipedia.org/wiki/FIPS_140-2)

$ echo $RANDOM

How the Kernel Generates Random Numbers

Some servers have hardware random number generators that take as input different types of noise signals, such as thermal noise and photoelectric effect. A transducer converts this noise into an electric signal, which is again converted into a digital number by an A-D converter.  This number is considered random. However, most common computers do not contain such specialized hardware and instead rely on events created during booting to create the raw data needed.

Regardless of which of these two sources is used, the system maintains a so-called entropy pool of these digital numbers/random bits. Random numbers are created from this entropy pool.

The Linux kernel offers the /dev/random and /dev/urandom device nodes which draw on the entropy pool to provide random numbers which are drawn from the estimated number of bits of noise in the entropy pool.

/dev/random is used where very high quality randomness is required, such as one-time pad or key generation, but it is relatively slow to provide vaules.   /dev/urandom is faster and suitable (good enough) for most cryptographic purposes.

Furthermore, when the entropy pool is empty, /dev/random is blocked and does not generate any number until additional environmental noise (network traffic, mouse movement, etc.) is gathered whereas /dev/urandom reuses the internal pool to produce more pseudo-random bits.



Processes and Process Attributes
=========================================================================
Interactive Processes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 	
Need to be started by a user, either at a command line or through a graphical interface such as an icon or a menu selection. 	e.g. => bash, firefox, top

Batch Processes 	
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Automatic processes which are scheduled from and then disconnected from the terminal. These tasks are queued and work on a FIFO (First In, First Out) basis. 	
e.g. =>  updatedb

Daemons 	
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Server processes that run continuously. Many are launched during system startup and then wait for a user or system request indicating that their service is required. 	
e.g. =>  httpd, xinetd, sshd

Threads 	
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Lightweight processes. These are tasks that run under the umbrella of a main process, sharing memory and other resources, but are scheduled and run by the system on an individual basis. An individual thread can end without terminating the whole process and a process can create new threads at any time. Many non-trivial programs are multi-threaded. 	
e.g. => gnome-terminal, firefox

Kernel Threads 	
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Kernel tasks that users neither start nor terminate and have little control over. These may perform actions like moving a thread from one CPU to another, or making sure input/output operations to disk are completed. 	
e.g. => kswapd0, migration, ksoftirqd



Process ID's and Priority
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Process ID (PID)
Parent Process ID (PPID)
Thread ID (TID)

User ID (UID)
Real User ID (RUID) 
Effective UID (EUID)
Real Group ID (RGID)
Effective Group ID (EGID)

Set the priority for a process by specifying a "nice value", or "niceness"
The lower the nice value, the higher the priority.
e.g. => -20  is the highest priority and 19 is the lowest priority

There is also assign "real-time priority" to time sensitive tasks.
This is different from "hard real time", which is used to make sure a job gets done within a time window


$ ps 
$ ps -u jomit
$ ps -ef			(view processes with all attributes)
$ ps -eLf			(view processes with all attributes and threads)
$ ps aux
$ ps axo stat,priority,pid,pcpu,comm

$ top		(shows realtime processes with memory and cpu consumption)
$ pstree

$ kill -9 <PID>
$ kill -SIGKILL <PID>


$ w				(to find out load average)
$ uptime		(to find out load average)

$ <command> &		(to run a job in background)
$ updatedb &

$ sleep 1000
$ CTRL + Z				(suspend foreground process)		
$ bg
$ jobs -l			(view background processes)

Use "bg" or "fg" to bring process to background or foreground



Scheduling Future Processes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ at now + 2 days			(specificies that task needs to be performed after 2 days)
at> cat file1				(actual task)
at> CTRL + D				(end of task)


$ crontab -e			(shows all exiting jobs or create new ones)

Examples:
1. The entry "* * * * * /usr/local/bin/execute/this/script.sh" will schedule a job to execute 'script.sh' every minute of every hour of every day of the month, and every month and every day in the week.

2. The entry "30 08 10 06 * /home/sysadmin/full-backup" will schedule a full-backup at 8.30am, 10-June irrespective of the day of the week.


$ sleep 1000s	(seconds, its the default)
$ sleep 1000m	(minutes)
$ sleep 1000h	(hours)
$ sleep 1000d	(days)

("sleep" and "at" are quite different; sleep delays execution for a specific period while at starts execution at a later time)





















































