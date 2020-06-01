#!/bin/bash

		#17 Set Sticky Bit on All World-Writable Directories
find / -perm -002 -type f -ls 2>/dev/null | egrep -v proc | awk '{print $NF}' | xargs chmod a+t
		#18 Disable Mounting of cramfs Filesystems
		#19 Disable Mounting of freevxfs Filesystems
		#20 Disable Mounting of jffs2 Filesystems
		#21 Disable Mounting of hfs Filesystems
		#22 Disable Mounting of hfsplus Filesystems
		#23 Disable Mounting of squashfs Filesystems
		#24 Disable Mounting of udf Filesystems
    
cat > /etc/modprobe.d/CIS.conf <<END1
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install vfat /bin/true
options ipv6 disable=1
END1

	#1.2 Configure Software Updates
		#1 Configure Connection to the RHN RPM Repositories - For AWS by default register
		#2 Verify Red Hat GPG Key is Installed - For AWS by default the gpg keys are imported
		#3 Verify that gpgcheck is Globally Activated
VALGPG=`grep -i gpg /etc/yum.conf | grep -v ^# | awk -F= '{print $NF}'`
if [ -z $VALGPG ]; then VALGPG=3; fi
if [ $VALGPG -ne 1 ]
then
echo y |cp -p /etc/yum.conf /etc/yum.conf.bak
VALGPG1=`grep -i gpg /etc/yum.conf`
sed 's/'$VALGPG1'/'gpgcheck=1'/g' /etc/yum.conf > /tmp/.harden/yum.conf
echo y | cp /tmp/.harden/yum.conf /etc/yum.conf
fi
		#4 Disable the rhnsd Daemon
systemctl disable rhnsd
		#5 Obtain Software Package Updates with yum - Info only
		#6 Verify Package Integrity Using RPM - Info only
	
	#1.3 Advanced Intrusion Detection Environment (AIDE)
		#1 Install AIDE - (NA)
		yum install aide -y
		#2 Implement Periodic Execution of File Integrity - (NA)
		if [ -f /var/spool/cron/root ]
		then
		VALAID=`grep aide /var/spool/cron/root`
                if [ $VALAID -ne 0 ]
                then
                echo "0 5 * * * /usr/sbin/aide --check" |(EDITOR="tee -a" crontab -e)
                fi
		else
		echo "0 5 * * * /usr/sbin/aide --check" |(EDITOR="tee -a" crontab -e)
		fi
	#1.4 1.4 Configure SELinux (NA)
		#1 Enable SELinux at boot time in /etc/grub.conf - (NA)
		#2 Set SELinux to enable when the system is booted - (NA)
		#3 Set the SELinux Policy - (NA)
		#4 Remove SETroubleshoot especially if X Windows is disabled
#chkconfig setroubleshoot off
yum erase setroubleshoot -y
		#5 Remove MCS Translation Service (mcstrans)
yum erase mcstrans -y
		#6 Check for Unconfined Daemons - Manual Check only
		
	#1.5 Secure Boot Settings
		#1 Set the owner and group of /etc/grub.conf to the root user
		#2 Set permission on the /etc/grub.conf file to read and write for root only
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
		#3 Set Boot Loader Password - (NA)
		#4 Require Authentication for Single-User Mode
		#5 Disable Interactive Boot
grep SINGLE /etc/sysconfig/init
		if [ $? -ne 0 ]
		then
		echo "SINGLE=/sbin/sulogin" >> /etc/sysconfig/init 
		fi
grep PROMPT /etc/sysconfig/init
		if [ $? -ne 0 ]
		then
		echo "PROMPT=no" >> /etc/sysconfig/init 
		fi
sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init

cat > /usr/lib/systemd/system/rescue.service <<end10
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Rescue Shell
Documentation=man:sulogin(8)
DefaultDependencies=no
Conflicts=shutdown.target
After=sysinit.target plymouth-start.service
Before=shutdown.target

[Service]
Environment=HOME=/root
WorkingDirectory=/root
ExecStartPre=-/bin/plymouth quit
ExecStartPre=-/bin/echo -e 'Welcome to rescue mode! Type "systemctl default" or ^D to enter default mode.\\nType "journalctl -xb" to view system logs. Type "systemctl reboot" to reboot.'
ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"
ExecStopPost=-/usr/bin/systemctl --fail --no-block default
Type=idle
StandardInput=tty-force
StandardOutput=inherit
StandardError=inherit
KillMode=process
IgnoreSIGPIPE=no
SendSIGHUP=yes
end10

cat > /usr/lib/systemd/system/emergency.service <<end11
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Emergency Shell
Documentation=man:sulogin(8)
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Environment=HOME=/root
WorkingDirectory=/root
ExecStartPre=-/bin/plymouth quit
ExecStartPre=-/bin/echo -e 'Welcome to emergency mode! After logging in, type "journalctl -xb" to view\\nsystem logs, "systemctl reboot" to reboot, "systemctl default" to try again\\nto boot into default mode.'
ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"
ExecStopPost=/usr/bin/systemctl --fail --no-block default
Type=idle
StandardInput=tty-force
StandardOutput=inherit
StandardError=inherit
KillMode=process
IgnoreSIGPIPE=no
SendSIGHUP=yes
end11
	
	#1.6 Process Hardening 
		#1 Restrict Core Dumps
		#2 Configure ExecShield
		#3 Enable Randomized Virtual Memory Region Placement
echo y | cp -p /etc/security/limits.conf /etc/security/limits.conf.bak
echo y | cp -p /etc/sysctl.conf /etc/sysctl.conf.bak
cat /etc/security/limits.conf | grep -i hard | grep -v ^# | grep 0
if [ $? -ne 0 ]
then
echo "* hard core 0" >> /etc/security/limits.conf
fi
cat /etc/sysctl.conf | grep -i fs.suid | grep 0
if [ $? -ne 0 ]
then
echo "fs.suid_dumpable = 0" >>  /etc/sysctl.conf
fi
cat /etc/sysctl.conf | grep -i kernel.exec-shield | grep 1
if [ $? -ne 0 ]
then
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
fi
cat /etc/sysctl.conf | grep -i kernel.randomize_va_space | grep 2
if [ $? -ne 0 ]
then
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
fi

cat > /etc/dconf/profile/gdm <<end12
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
end12

cat > /etc/dconf/db/gdm.d/01-banner-message <<end13
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='This computer system is for authorized users only. Activities on this system may be logged and are regularly checked by system administrators. Using this system without authority or in excess of your authority may cause you to be in breach of the law. By entering the userid and/or password, you consent to these terms of use of this system.'
end13
		
	#1.7 Use the Latest OS release - Info only
	
	#Disable automounting
systemctl disable autofs


############################################################################
#2 OS Services
############################################################################

#2.1 Remove Legacy Services
#1 Remove telnet-server
#2 Remove telnet Clients
#3 Remove rsh-server
#4 Remove rsh
#5 Remove NIS Client
#6 Remove NIS Server
#7 Remove tftp
#8 Remove tftp-server
#9 Remove talk
#10 Remove talk-server
#11 Remove xinetd
yum erase rsh rsh-server talk talk-server telnet telnet-server tftp tftp-server xinetd ypbind ypserv prelink -y
#12 Disable chargen-dgram
#13 Disable chargen-stream
#14 Disable daytime-dgram
#15 Disable daytime-stream
#16 Disable echo-dgram
#17 Disable echo-stream
#18 Disable tcpmux-server
#19 Disable discard-dgram
#20 Disable discard-stream
#21 Disable time-dgram
#22 Disable time-stream
#for each in chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server discard-dgram discard-stream time-dgram time-stream; do  systemctl disable $each off; done
systemctl disable chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server discard-dgram discard-stream time-dgram time-stream

############################################################################
#3 Special Purpose services
############################################################################
 #1 Set Daemon umask to 027
echo "umask 027" >> /etc/sysconfig/init
 #2 Remove X Windows
#VAL=`cat /etc/inittab | grep -i initdefault | grep -v ^# | awk -F: '{print $2}'`
#if [ $VAL -ne 3 ]; then cat /etc/inittab | egrep -v ^id:5:initdefault: > /tmp/.harden/inittab; cat /etc/inittab | grep -i initdefault | grep -v ^# | sed s/5/3/g >> /tmp/.harden/inittab; fi
#echo y | cp /tmp/.harden/inittab /etc/inittab
	#yum groupremove "X Window System" -y
	yum remove xorg-x11* -y
 #3 Disable Avahi Server
 systemctl disable avahi-daemon
 #4 Disable Print Server - CUPS
systemctl disable cups
 #5 Remove DHCP Server
yum erase dhcp -y
 #6 Configure Network Time Protocol (NTP)
 yum install ntp -y
 systemctl disable chronyd
 systemctl enable ntpd
 
cp -p /etc/ntp.conf /etc/ntp.conf.bak
echo y |cp -p /etc/ntp.conf /tmp/.harden/ntp.conf
egrep -v '(restrict default|restrict -6 default)' /tmp/.harden/ntp.conf > /etc/ntp.conf
echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf

echo "OPTIONS="-u ntp:ntp"" > /etc/sysconfig/ntpd 

systemctl start ntpd
 #7 Remove LDAP
yum erase openldap-clients openldap-servers -y
 #8 Disable NFS and RPC
#for each in nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd; do systemctl disable $each; done
systemctl disable nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd
 #9 Remove DNS Server 
 #10 Remove FTP Server 
 #11 Remove HTTP Server 
 #12 Remove Dovecot (IMAP and POP3 services)
 #13 Remove Samba 
 #14 Remove HTTP Proxy Server
 #15 Remove SNMP Server
 #16 Configure Mail Transfer Agent (MTA) for Local-Only Mode
yum erase bind vsftpd httpd dovecot samba squid net-snmp ypbind rsh talk telnet -y
 #17 Configure Mail Transfer Agent (MTA) for Local-Only Mode
grep -v ^inet_interfaces /etc/postfix/main.cf > /tmp/.harden/main.cf
echo "inet_interfaces = localhost" >> /tmp/.harden/main.cf
echo y | cp /tmp/.harden/main.cf /etc/postfix/main.cf

systemctl disable dhcpd slapd named dovecot smb snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd 

############################################################################
#4 Network Configuration
############################################################################
 #4.1 Modify Network Parameters
	#1 Disable IP Forwarding
	#2 Disable Send Packet Redirects
 #4.2 Modify Network Parameters (Host and Router)
	#1 Disable source Routed Packet Acceptance
	#2 Disable ICMP Redirect Acceptance
	#3 Disable Secure ICMP Redirect Acceptance
	#4 Log Suspicious Packets
	#5 Enable Ignore Broadcast Requests
	#6 Enable Bad Error Message Protection
	#7 Enable RFC-recommended Source Route Validation
	#8 Enable TCP SYN Cookies
 #4.3 Wireless Networking
 #4.4 IPv6
	#4.4.1 Configure IPv6
		#1 Disable IPv6 Router Advertisements
		#2 Disable IPv6 Redirect Acceptance
echo "options ipv6 disable=1" > /etc/modprobe.d/ipv6.conf

cat > /tmp/.harden/sysctl.conf_1 <<end111
# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296
fs.suid_dumpable = 0
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Disable IP Forwarding
net.ipv4.ip_forward = 0

# Disable Send Packet Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

#Disable source Routed Packet Acceptance
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable Secure ICMP Redirect Acceptance
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log Suspicious Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable Ignore Broadcast Requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable Bad Error Message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable RFC-recommended Source Route Validation
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Enable TCP SYN Cookies
net.ipv4.tcp_syncookies = 1
#Disable IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
#Disable IPv6 Redirect Acceptance
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
end111
cat /tmp/.harden/sysctl.conf_1 >> /tmp/.harden/sysctl.conf
echo y | cp /tmp/.harden/sysctl.conf /etc/sysctl.conf

#sed -i 's/IPV6INIT=yes/IPV6INIT=no/g' /etc/sysconfig/network

 #4.5 TCP Wrappers
	#1 Install TCP Wrappers
yum install tcp_wrappers -y
	#2 Create /etc/hosts.allow
	#3 Set Permissions on /etc/hosts.allow file to 064
/bin/chmod 644 /etc/hosts.allow
	#4 Create /etc/hosts.deny
	#5 Set Permissions on /etc/hosts.deny to 064
/bin/chmod 644 /etc/hosts.deny
 
  #4.6 Uncommon Network Protocols
	#1 Disable DCCP
	#2 Disable SCTP
	#3 Disable RDS
	#4 Disable TIPC
if [ -f /etc/modprobe.d/uncommon.conf ]
then
rm -rf /etc/modprobe.d/uncommon.conf 
fi
cat > /etc/modprobe.d/uncommon.conf <<end112
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
end112
	#4.7 Enable IPtables
		#1 Enable iptables
	#4.8 Enable IP6tables
		#1 Enable ip6tables
		
############################################################################
#5 Logging and Auditing
############################################################################
	#5.1
		#1 Install the rsyslog package
yum install rsyslog -y
		#2 Activate the rsyslog Service
#chkconfig syslog off 
#chkconfig rsyslog on
systemctl enable rsyslog syslog-ng
		#3 configure /etc/rsyslog.conf
		#4 Create and set Permission on rsyslog log files
		#5 configure rsyslog to Send Logs to a Remote Log Host
cp -p /etc/rsyslog.conf /etc/rsyslog.conf.bak
VAL1=`cat /etc/rsyslog.conf  | grep -i messages | grep -v ^# | awk '{print $1}'`
VAL2=`cat /etc/rsyslog.conf  | grep -i kern.log | grep -v ^# | awk '{print $1}'`
VAL3=`cat /etc/rsyslog.conf  | grep -i daemon.log | grep -v ^# | awk '{print $1}'`
VAL4=`cat /etc/rsyslog.conf  | grep -i syslog | grep -v ^# | awk '{print $1}'| grep -i syslog`
VAL5=`cat /etc/rsyslog.conf  | grep -i localmessages | grep -v ^# | awk '{print $1}'`


if [ -z $VAL1 ]; then VAL1=A; fi
if [ -z $VAL2 ]; then VAL2=A; fi
if [ -z $VAL3 ]; then VAL3=A; fi
if [ -z $VAL4 ]; then VAL4=A; fi
if [ -z $VAL5 ]; then VAL5=A; fi

if [ $VAL1 != "auth,user.*" ]
then
echo "auth,user.* /var/log/messages" >> /etc/rsyslog.conf
fi
if [ $VAL2 != "kern.*" ]
then
echo "kern.* /var/log/kern.log" >> /etc/rsyslog.conf
fi
if [ $VAL3 != "daemon.*" ]
then
echo "daemon.* /var/log/daemon.log" >> /etc/rsyslog.conf
fi
if [ $VAL4 != "syslog.*" ]
then
echo "syslog.* /var/log/syslog" >> /etc/rsyslog.conf
fi
if [ $VAL5 != "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*" ]
then
echo "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/localmessages" >> /etc/rsyslog.conf
fi
		#6 Accept Remote rsyslog Messages Only on Designated Log Hosts
sed 's/#$ModLoad/$ModLoad/g' /etc/rsyslog.conf > /tmp/.harden/rsyslog.conf
sed 's/#$UDPServerRun/$UDPServerRun/g' /tmp/.harden/rsyslog.conf > /tmp/.harden/rsyslog.conf1
echo y | cp /tmp/.harden/rsyslog.conf1 /etc/rsyslog.conf

if [ ! -f /var/log/messages ]; then touch /var/log/messages; fi
if [ ! -f  /var/log/kern.log ]; then touch /var/log/kern.log; fi
if [ ! -f /var/log/daemon.log ]; then touch /var/log/daemon.log; fi
if [ ! -f  /var/log/syslog ]; then touch /var/log/syslog; fi
if [ ! -f  /var/log/localmessages ]; then touch /var/log/localmessages; fi

chown root:root /var/log/messages /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod 600 /var/log/messages /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

find /var/log -type f -exec chmod g-wx,o-rwx {} \;

#grep "172.31.1.172" /etc/rsyslog.conf
#if [ $? -ne 0 ]
#then
#echo "*.* @172.31.1.172:514" >> /etc/rsyslog.conf
#fi

grep FileCreateMode /etc/rsyslog.conf
if [ $? -ne 0 ]
then
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
fi

pkill -HUP rsyslogd

	#5.2 Configure System Accounting
		#5.2.1 Configure Data Retnetion
			#1 Configure Audit Log Storage Size
			#2 'Disable System on Audit Log Full
			#3 Keep All Auditing Information
cp -p /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed 's/space_left_action = SYSLOG/space_left_action = email/g'  /etc/audit/auditd.conf > /tmp/.harden/auditd.conf
cat  /tmp/.harden/auditd.conf > /etc/audit/auditd.conf
		#5.2.2 Enable auditd Service
			#1 Enable auditd service
systemctl enable auditd
		#5.2.3  Enable Auditing for Processes That Start Prior to auditd
			#1  Enable Auditing for Processes That Start Prior to auditd

VAL=`dmidecode -s system-product-name | grep -v \# | awk '{print $NF}'`
VAL1='domU'
if [ ! $VAL == $VAL1 ]
then
{
grep "^\s*linux" /boot/grub2/grub.cfg | grep -i "audit=1"
if [ $? -ne 0 ]
then 
echo y | cp -p /etc/default/grub /etc/default/grub.bak
sed "/GRUB_CMDLINE_LINUX/ s/\"//g" /etc/default/grub > /tmp/.harden/grub
sed "/GRUB_CMDLINE_LINUX/ s/$/ audit=1/" /tmp/.harden/grub > /tmp/.harden/grub1
sed "/GRUB_CMDLINE_LINUX/ s/GRUB_CMDLINE_LINUX=/GRUB_CMDLINE_LINUX=\"/g" /tmp/.harden/grub1 > /tmp/.harden/grub2
sed "/GRUB_CMDLINE_LINUX/ s/$/\"/" /tmp/.harden/grub2 > /tmp/.harden/grub3
echo y | cp /tmp/.harden/grub3 /etc/default/grub
fi

grub2-mkconfig > /boot/grub2/grub.cfg
}
fi

		#5.2.4 Record Events That Modify Date and Time Information
			#1 Record Events That Modify Date and Time Information
		#5.2.6 Record Events That Modify the System's Network Environment
		#5.2.7 Record Events That Modify the System's Mandatory Access Controls
		#5.2.8 Collect Login and Logout Events
		#5.2.9 Collect Session Initiation Information
		#5.2.10 Collect Discretionary Access Control Permission Modification Events
		#5.2.12 Collect Use of Privileged Commands
		#5.2.13 Collect Successful File System Mounts
		#5.2.14 Collect File Deletion Events by User
		#5.2.15 Collect Changes to System Administration Scope
		#5.2.16 Collect System Administrator Actions (sudolog))
		#5.2.17 Collect Kernel Module Loading and Unloading
		#5.2.18 Make the Audit Configuration Immutable
		
echo y | mv /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak
cat > /etc/audit/rules.d/audit.rules <<END113
# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 320

# Feel free to add below this line. See auditctl man page

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change


-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillock -p wa -k logins
-w /var/log/lastlog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access


-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules



-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/cgclassify -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/cgexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/Xorg -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/fusermount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/mount.nfs -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/lockdev -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/qemu-bridge-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

-e 2
END113

echo y | cp /etc/audit/rules.d/audit.rules /etc/audit/audit.rules
echo y | cp /usr/lib/systemd/system/auditd.service  /etc/systemd/system/auditd.service
systemctl enable auditd
systemctl daemon-reload

		#5.3 Configure logrotate
echo y | mv /etc/logrotate.d/syslog  /etc/logrotate.d/syslog.bak
cat > /etc/logrotate.d/syslog <<END114
/var/log/cron
/var/log/kern.log
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
/var/log/boot.log
{
    dateext
    dateformat -%Y-%m-%d
    sharedscripts
    rotate 3
    postrotate
    compress
        /bin/kill -HUP \`cat /var/run/syslogd.pid 2> /dev/null\` 2> /dev/null || true
    endscript
}
END114
chmod 644 /etc/logrotate.d/syslog
		 
############################################################################
#6 System Access, Authentication and Authorization
############################################################################	
#6.1
	#1 Enable anacron Daemon
yum install cronie-anacron -y
	#2 Enable crond Daemonx
systemctl enable crond
	#3 Set User/Group Owner and Permission on /etc/anacrontab
chown root:root /etc/anacrontab 
chmod og-rwx /etc/anacrontab
	#4 Set User/Group Owner and Permission on /etc/crontab
chown root:root /etc/crontab 
chmod og-rwx /etc/crontab
	#5 Set User/Group Owner and Permission on /etc/cron.hourly
chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly
	#6 Set User/Group Owner and Permission on /etc/cron.daily
chown root:root /etc/cron.daily 
chmod og-rwx /etc/cron.daily
	#7 Set User/Group Owner and Permission on /etc/cron.weekly
chown root:root /etc/cron.weekly 
chmod og-rwx /etc/cron.weekly
	#8 Set User/Group Owner and Permission on /etc/cron.monthly
chown root:root /etc/cron.monthly 
chmod og-rwx /etc/cron.monthly
	#9 Set User/Group Owner and Permission on /etc/cron.d
chown root:root /etc/cron.d 
chmod og-rwx /etc/cron.d
	#10 Restrict at Daemon
rm -f /etc/at.deny 
touch /etc/at.allow 
chown root:root /etc/at.allow 
chmod og-rwx /etc/at.allow
	#11 Restrict at/cron to Authorized Users
rm -f /etc/cron.deny 
rm -f /etc/at.deny 
touch /etc/cron.allow  /etc/at.allow
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow 
chown root:root /etc/at.allow

	#6.2 Configure SSH
		#1 Set SSH Protocol to 2
echo y |cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

VALSSH=`grep Protocol /etc/ssh/sshd_config | grep -v ^# | awk '{print $NF}'`
if [ -z $VALSSH ]; then echo "Protocol 2" >> /etc/ssh/sshd_config; VALSSH=2; fi
if [ $VALSSH -ne 2 ]
then

VALSSH1=`grep Protocol /etc/ssh/sshd_config`
sed "s/$VALSSH1/Protocol 2/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

		#2 Set LogLevel to INFO
VALSSH=`grep LogLevel /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}'`
if [ -z $VALSSH ]; then VALSSH=A; fi
if [ $VALSSH != INFO ]
then
VALSSH1=`grep LogLevel /etc/ssh/sshd_config`
sed "s/$VALSSH1/LogLevel INFO/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

		#3 Set Permissions on /etc/ssh/sshd_config
/bin/chown root:root /etc/ssh/sshd_config
/bin/chmod 600 /etc/ssh/sshd_config
		#4 Disable SSH X11 Forwarding
sed -i "/X11Forwarding/s/yes/no/" /etc/ssh/sshd_config
		#5 Set SSH MaxAuthTries to 4 or Less
VALSSH=`grep "MaxAuthTries" /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=5; fi
if [ $VALSSH -ne 4 ]
then
VALSSH1=`grep "MaxAuthTries" /etc/ssh/sshd_config`
sed "s/$VALSSH1/MaxAuthTries 4/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi
		#6 Set SSH IgnoreRhosts to Yes
VALSSH=`grep IgnoreRhosts /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=A; fi
if [ $VALSSH != yes ]
then
VALSSH1=`grep IgnoreRhosts /etc/ssh/sshd_config`
sed "s/$VALSSH1/IgnoreRhosts yes/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi
		#7 Set SSH HostbasedAuthentication to No
VALSSH=`grep "HostbasedAuthentication no" /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=A; fi
if [ $VALSSH != no ]
then
VALSSH1=`grep "HostbasedAuthentication no" /etc/ssh/sshd_config`
sed "s/$VALSSH1/HostbasedAuthentication no/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi
		#8 Disable SSH Root Login
VALSSH=`grep "PermitRootLogin" /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=a ; fi
if [ $VALSSH != no ]
then
VALSSH1=`grep "#PermitRootLogin" /etc/ssh/sshd_config`
sed "s/$VALSSH1/PermitRootLogin no/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

		#9 Set SSH PermitEmptyPasswords to No
VALSSH=`grep PermitEmptyPasswords /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=a ; fi
if [ $VALSSH != no ]
then
VALSSH1=`grep "PermitEmptyPasswords no" /etc/ssh/sshd_config`
sed "s/$VALSSH1/PermitEmptyPasswords no/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

		#10 Do Not Allow Users to Set Environment Options
VALSSH=`grep PermitUserEnvironment /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then VALSSH=a ; fi
if [ $VALSSH != no ]
then
VALSSH1=`grep "PermitUserEnvironment" /etc/ssh/sshd_config`
sed "s/$VALSSH1/PermitUserEnvironment no/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

		#11 Use Only Approved Cipher in Counter Mode
cat /etc/ssh/sshd_config | grep "Ciphers  aes256-ctr,aes192-ctr,aes128-ctr" | grep -v ^#
if [ $? -ne 0 ]
then
echo "Ciphers  aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config 
fi

		#12 Set Idle Timeout Interval for User Login
grep "ClientAliveInterval 300" /etc/ssh/sshd_config
if [ $? -ne 0 ]
then
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
fi
grep "ClientAliveCountMax 0"  /etc/ssh/sshd_config
if [ $? -ne 0 ]
then
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi
		#13 Limit Access via SSH -(NA)
		
		#14 Set SSH Banner
grep Banner /etc/ssh/sshd_config | grep -v ^# | grep -v none
if [ $? != 0 ]
then
sed -i "/#Banner/s/none/\/etc\/issue.net/" /etc/ssh/sshd_config 
sed -i "/#Banner/s/#Banner/Banner/" /etc/ssh/sshd_config
fi

cat /etc/ssh/sshd_config | grep "MACs  hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" | grep -v ^#
if [ $? -ne 0 ]
then
echo "MACs  hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"  >> /etc/ssh/sshd_config
fi

		#LoginGraceTime
VALSSH=`grep "LoginGraceTime" /etc/ssh/sshd_config | grep -v ^#| awk '{print $NF}' | uniq`
if [ -z $VALSSH ]; then echo "LoginGraceTime 60" >> /etc/ssh/sshd_config; VALSSH=60; fi
if [ $VALSSH -ne 60 ]
then
VALSSH1=`grep "LoginGraceTime" /etc/ssh/sshd_config`
sed "s/$VALSSH1/LoginGraceTime 60/g" /etc/ssh/sshd_config > /tmp/.harden/sshd_config
echo y | cp /tmp/.harden/sshd_config  /etc/ssh/sshd_config
fi

	#6.3 Configure PAM (Pluggable Authentication Modules)
		#1 Upgrade Password Hashing Algorithm to SHA-512
authconfig --passalgo=sha512 --update
		#2 Set Password Creation Requirement Parameters Using pam_cracklib
echo y | cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

		#3 Set Lockout for Failed Password Attempts
echo y | cp -p /etc/pam.d/password-auth /etc/pam.d/password-auth.bak
echo y | cp -p /etc/security/pwquality.conf /etc/security/pwquality.conf.bak



cat > /etc/pam.d/system-auth <<END121
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3
password    sufficient    pam_unix.so sha512 try_first_pass
password    required      pam_deny.so
password sufficient pam_unix.so remember=6

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so

auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
END121

cat > /etc/pam.d/password-auth <<END122
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3
password    sufficient    pam_unix.so sha512 try_first_pass
password    required      pam_deny.so
password sufficient pam_unix.so remember=6

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so

auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
END122

cat > /etc/security/pwquality.conf <<END110
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
END110

cat > /etc/pam.d/su <<END123
#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth            required        pam_wheel.so use_uid
auth            substack        system-auth
auth            include         postlogin
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         include         postlogin
session         optional        pam_xauth.so
END123
yum install sudo -y
usermod -G wheel sysadm
echo "sysadm ALL=(ALL:ALL) ALL" | (EDITOR="tee -a" visudo)
useradd -g wheel -c "Test User" -d /home/test -m test
echo test | passwd --stdin test
#echo ec2user | passwd --stdin ec2user

	#7 User Accounts and Environment
		#1 Set Password Expirantion Days
		#2 Set Password Change Minimum Number of Days
		#3 Set Password Expiring Warning Days
echo y | mv /etc/login.defs /etc/login.defs.bak
cat > /etc/login.defs <<END115
#
# Please note that the parameters in this configuration file control the
# behavior of the tools from the shadow-utils component. None of these
# tools uses the PAM mechanism, and the utilities that use PAM (such as the
# passwd command) should therefore be configured elsewhere. Refer to
# /etc/pam.d/system-auth for more information.
#

# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR      Maildir
MAIL_DIR        /var/spool/mail
#MAIL_FILE      .mail

# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_MIN_LEN    Minimum acceptable password length.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   60
PASS_MIN_DAYS   7
PASS_MIN_LEN    8
PASS_WARN_AGE   7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN                   500
UID_MAX                 60000

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN                   500
GID_MAX                 60000

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD    /usr/sbin/userdel_local

#
# If useradd should create home directories for users by default
# On RH systems, we do. This option is overridden with the -m flag on
# useradd command line.
#
CREATE_HOME     yes

# The permission mask is initialized to this value. If not specified,
# the permission mask will be initialized to 022.
UMASK           077

# This enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

# Use SHA512 to encrypt password.
ENCRYPT_METHOD SHA512

MD5_CRYPT_ENAB no
END115
chmod 644 /etc/login.defs 
	#7.2 Disable system accounts
		#1 Disable system accounts
echo y | cp /etc/passwd /etc/passwd.bak
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do 
if [ $user != "root" ] 
then 
   /usr/sbin/usermod -L $user 
   if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ] 
   then 
      /usr/sbin/usermod -s /sbin/nologin $user 
      fi 
    fi 
done
	#7.3 Set Default Group for root Account
usermod -g 0 root
	#7.4 Set Default umask for Users
grep "umask 027" /etc/profile
if [ $? -ne 0 ]
then
#VALUMASK=`cat /etc/profile | grep -v ^# | grep -i umask | tail -1 | awk '{print $2}'`
sed -i 's/umask 002/umask 027/g' /etc/profile
sed -i 's/umask 022/umask 027/g' /etc/profile
fi

grep "umask 027" /etc/bashrc
if [ $? -ne 0 ]
then
#VALUMASK=`cat /etc/profile | grep -v ^# | grep -i umask | tail -1 | awk '{print $2}'`
sed -i 's/umask 002/umask 027/g' /etc/bashrc
sed -i 's/umask 022/umask 027/g' /etc/bashrc
fi

cat > /tmp/.harden/UMASK <<END125
/etc/profile.d/colorls.sh
/etc/profile.d/cvs.csh
/etc/profile.d/cvs.sh
/etc/profile.d/glib2.csh
/etc/profile.d/glib2.sh
/etc/profile.d/lang.csh
/etc/profile.d/lang.sh
/etc/profile.d/less.csh
/etc/profile.d/less.sh
/etc/profile.d/qt.csh
/etc/profile.d/qt.sh
/etc/profile.d/vim.csh
/etc/profile.d/vim.sh
/etc/profile.d/which2.sh
END125

for each in ` cat /tmp/.harden/UMASK`
do
grep "umask 077" $each
if [ $? -ne 0 ]
then
echo "umask 077" >> $each
fi
done
	#7.5 Lock Inactive User Accounts - INFO
	
	#8 Warning Bannners
		#1 Set Warning Banner for Standard Login Services
cat > /etc/issue.net <<END120
Unauthorized users are prohibited. This system and equipment is property of GRAB. The use of the system and equipment is restricted to authorized users only. Any unauthorized access, use, or modification of this system or of the data contained herein or in transit to/from this system is strictly prohibited. This system and equipment are to be used for business purposes only and any use for personal reasons is strictly prohibited. GRAB reserves the right to enter, search and monitor the computer files and system of any employee without advance notice, for business purposes such as investigating theft, disclosure of confidential business or proprietary information, investigating breaches of personal data, personal abuse of the system, or monitoring work flow or productivity. Violations will be addressed under appropriate disciplinary policy procedures for employees, with sanctions up to or including termination.
END120

echo y | cp /etc/issue.net /etc/issue
echo y | cp /etc/issue.net /etc/motd
chown root:root /etc/motd 
chmod 644 /etc/motd 
chown root:root /etc/issue 
chmod 644 /etc/issue 
chown root:root /etc/issue.net 
chmod 644 /etc/issue.net
		#2 Remove OS Information from Login Warning Banners
		#3 'Set GNOME Warning Banner (Not Scored) - (NA)
	#9 System Maintence
	#9.1
		#1 Verify system File Permission
#rpm -Va --nomtime --nosize --nomd5 --nolinkto
		#2 Verify Permissions on /etc/passwd
/bin/chmod 644 /etc/passwd*
		#3 Verify Permissions on /etc/shadow
/bin/chmod 000 /etc/shadow
		#4 Verify Permissions on /etc/gshadow
/bin/chmod 000 /etc/gshadow*
		#5 Verify Permissions on /etc/group
/bin/chmod 644 /etc/group*
		#6 Verify User/Group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd*
		#7 Verify User/Group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow*
		#8 Verify User/Group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow*
		#9 Verify User/Group Ownership on /etc/group
/bin/chown root:root /etc/group*

/bin/chmod 600 /etc/group-
/bin/chmod 600 /etc/passwd-
/bin/chmod 600 /etc/gshadow-
/bin/chmod 600 /etc/shadow-
}

MANUALL ()
{
		#9 #9.1 #10 Find World Writable Files
find / -perm -002 -type f -ls |egrep -v proc | grep -v T > /tmp/.harden/man_worldwritable
if [ $? -eq 0 ]
then
bold
echo "Kindly change the permission of the following world writable files"
unbold
echo ""
cat /tmp/.harden/man_worldwritable
fi
		#9 #9.1	#11 Find Un-owned Filed and directories
		#9 #9.1	#12 Find Un-grouped Files and Directories
find / \( -nouser -o -nogroup \) -print > /tmp/.harden/man_orphanfiles
if [ $? -eq 0 ]
then
echo "Kindly change the owenership of the following orphan files"
echo ""
cat /tmp/.harden/man_orphanfiles
fi		

		#9 #9.1	#13 Find SUID System Executables
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -ls > /tmp/.harden/man_suid
if [ $? -eq 0 ]
then
echo ""
bold
echo "Kindly verify SUID Executables files"
unbold
echo ""
cat /tmp/.harden/man_suid
fi	

		#9 #9.1	#14 Find SGID System Executables 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -ls > /tmp/.harden/man_sgid
if [ $? -eq 0 ]
then
echo ""
bold
echo "Kindly verify SGID Executables files"
unbold
echo ""
cat /tmp/.harden/man_sgid
fi
	#9.2 Review User and Group settings
		#1 Ensure Password Fields are Not Empty
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password;Kindly set password. "}'
		#2 Verify No Legacy "+" Entries Exist in /etc/passwd File
/bin/grep '^+:' /etc/passwd > /tmp/.harden/man_passwd
if [ $? -eq 0 ]
then
echo ""
bold
echo "Kindly verify "+" Entries Exist in /etc/passwd File"
unbold
echo ""
cat /tmp/.harden/man_passwd
fi
		#3 Verify No Legacy "+" Entries Exist in /etc/shadow File
/bin/grep '^+:' /etc/shadow > /tmp/.harden/man_shadow
if [ $? -eq 0 ]
then
echo ""
bold
echo "Kindly verify "+" Entries Exist in /etc/shadow File"
unbold
echo ""
cat /tmp/.harden/man_shadow
fi
		#4 Verify No Legacy "+" Entries Exist in /etc/group File
/bin/grep '^+:' /etc/ > /tmp/.harden/man_group
if [ $? -eq 0 ]
then
echo ""
bold
echo "Kindly verify "+" Entries Exist in /etc/group File"
unbold
echo ""
cat /tmp/.harden/man_group
fi
		#5 Verify No UID 0 Accounts Exist Other Than root
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' | grep -v root > /tmp/.harden/man_passwdroot
if [ -f /tmp/.harden/man_passwdroot ]
then
echo ""
bold
echo "Kindly change the UID of the following ID"
unbold
echo ""
cat /tmp/.harden/man_passwdroot
fi
		#6 Ensure root PATH Integrity
echo ""
bold
echo "Checking root PATH Integrity"
echo "Each directory DIR in the path should not equal to a single . character. There should also be no “empty” elements in the path. Write permissions are disabled for group and other. Correct or justify any item discovered by the below Script."
unbold
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | /bin/grep :$`" != "" ]; then
    echo "Trailing : in PATH"
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
        if [ "$1" = "." ]; then
            echo "PATH contains ."
            shift
            continue
        fi
if [ -d $1 ]; then
             dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d"" ""`
             if [ `echo $dirperm | /bin/cut -c6 ` != ""-"" ]; then
                 echo ""Group Write permission set on directory $1""
             fi
             if [ `echo $dirperm | /bin/cut -c9 ` != ""-"" ]; then
                 echo ""Other Write permission set on directory $1""
             fi
                 dirown=`ls -ldH $1 | awk '{print $3}'`
        if [ ""$dirown"" != ""root"" ] ; then
             echo $1 is not owned by root
        fi
        else
             echo $1 is not a directory
        fi
        shift
done
		#8 Check user Dot File Permissions
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/sbin/nologin"){print $6}'`
do
for file in $dir/.[A-Za-z0-9]*; do

            if [ ! -h ""$file"" -a -f ""$file"" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d"" ""`

            if [ `echo $fileperm | /bin/cut -c6 ` != ""-"" ]; then
                echo ""Group Write permission set on file $file"" >> /tmp/.harden/man_dotgroup
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != ""-"" ]; then
                echo ""Other Write permission set on file $file"" >> /tmp/.harden/man_dotfile
            fi
      fi
      done
done
if [  -f /tmp/.harden/man_dotgroup ] || [ -f  /tmp/.harden/man_dotfile ]
then
echo ""
bold
echo "Ensure that User Dot-Files are not Group-writable or World-writable.Repair the permissions based on the results generated by the below script"
unbold
echo ""
cat /tmp/.harden/man_dotgroup /tmp/.harden/man_dotfile 2>&1
fi

		#9 Check Permissions on User .netrc Files
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | awk -F: '($8 != "/sbin/nologin") { print $6 }'`; do
for file in $dir/.netrc; do
   if [ ! -h ""$file"" -a -f ""$file"" ]; then
           fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d"" ""`
           if [ `echo $fileperm | /bin/cut -c5 ` != ""-"" ]
           then
               echo ""Group Read set on $file"" >> /tmp/.harden/man_dotnetrcgroupread
           fi
           if [ `echo $fileperm | /bin/cut -c6 ` != ""-"" ]
           then
               echo ""Group Write set on $file"" >> /tmp/.harden/man_dotnetrcgroupwrite
           fi
           if [ `echo $fileperm | /bin/cut -c7 ` != ""-"" ]
           then
               echo ""Group Execute set on $file"" >> /tmp/.harden/man_dotnetrcgroupexec
           fi
           if [ `echo $fileperm | /bin/cut -c8 ` != ""-"" ]
           then
               echo ""Other Read set on $file"" >> /tmp/.harden/man_dotnetrcotherread
           fi
           if [ `echo $fileperm | /bin/cut -c9 ` != ""-"" ]
           then
               echo ""Other Write set on $file"" >> /tmp/.harden/man_dotnetrcotherwrite
           fi
           if [ `echo $fileperm | /bin/cut -c10 ` != ""-"" ]
           then
               echo ""Other Execute set on $file"" >> /tmp/.harden/man_dotnetrcotherexecute
           fi
    fi
  done
done
if [  -f  /tmp/.harden/man_dotnetrcgroupread ] || [ ! -f  /tmp/.harden/man_dotnetrcgroupwrite ] || [ ! -f  /tmp/.harden/man_dotnetrcgroupexec ] || [ ! -z /tmp/.harden/man_dotnetrcotherread ] || [ ! -z /tmp/.harden/man_dotnetrcotherwrite ] || [ ! -z /tmp/.harden/man_dotnetrcotherexecute ]
then
echo ""
bold
echo "Check Permissions on User .netrc Files; Change the following Permission"
unbold
echo ""
cat /tmp/.harden/man_dotnetrcgroupread /tmp/.harden/man_dotnetrcgroupwrite /tmp/.harden/man_dotnetrcgroupexec /tmp/.harden/man_dotnetrcotherread  /tmp/.harden/man_dotnetrcotherwrite /tmp/.harden/man_dotnetrcotherexecute 2>&1
fi
		
		#10 Check for Presence of User .rhosts Files
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
      for file in $dir/.rhosts; do
            if [ ! -h "$file" -a -f "$file" ]; then
               echo ".rhosts file in $dir" >> /tmp/.harden/man_dotrhosts
            fi done
done
if [ ! -z /tmp/.harden/man_dotrhosts ] 
then
echo ""
bold
echo "Remove the following .rhosts file"
unbold
echo ""
cat /tmp/.harden/man_dotrhosts 2>&1
fi

		#11 Check for Groups in /etc/passwd
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P ""^.*?:x:$i:"" /etc/group
if [ $? -ne 0 ]; then
echo ""Group $i is referenced by /etc/passwd but does not exist in /etc/group"" >> /tmp/.harden/man_nogrouppasswd
fi
done
if [ ! -z /tmp/.harden/man_dotrhosts ] 
then
echo ""
bold
echo "Verify the following GID used in /etc/passwd file"
unbold
echo ""
cat /tmp/.harden/man_dotrhosts 2>&1
fi

		#12 Check That Users Are Assigned Home Directories
echo ""
bold
echo "Checking That Users Are Defined Home Directories is"
echo ""
unbold
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon"
cat /etc/passwd | awk -F: '{ print $1 " " $6 }'| while read user dir
     do
             found=0
             for n in $defUsers
             do
                    if [ "$user" = "$n" ]
                        then
                           found=1
                           break
                    fi
             done
             if [ $found -eq 0 ]
                then
             if [ -z "$dir" ]
                then
                    echo ""User $user has no home directory.""
             fi
          fi
     done
		#13 Check User Home Directory Ownership
echo ""
bold
echo "Checking User Home Directory Ownership"
echo ""
unbold
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon"
/bin/cat /etc/passwd |  awk -F: '{ print $1 " " $6 }' | while read user dir; do
             found=0
             for n in $defUsers
             do
                 if [ "$user" = "$n" ]
                 then
                     found=1
                     break
                 fi
             done
             if [ $found -eq "0" ]
                then
             if [ -d ${dir} ]
                then
                 owner=`ls -ld $dir | awk '{print $3}'`
                 if [ "$owner" != "$user" ]

                 then
                     echo ""Home directory for $user owned by $owner""
                 fi
             fi
         fi
done


		#14 Check for Duplicate UIDs
echo ""
bold
echo "Checking for Duplicate UIDs"
echo ""
unbold
/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
           users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2  /etc/passwd | /usr/bin/xargs`
           echo "Duplicate UID ($2): ${users}"
         fi
done
		#15 Check for Duplicate GIDs
echo ""
bold
echo "Checking for Duplicate GIDs"
echo ""
unbold
/bin/cat /etc/group | /bin/cut -f3 -d"":"" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
           grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2  /etc/group | xargs`
           echo "Duplicate GID ($2): ${grps}"
         fi
done
		#16 Check for Duplicate User Names
echo ""
bold
echo "Checking for Duplicate User Names"
echo ""
unbold
cat /etc/passwd | cut -f1 -d"":"" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
         uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2  /etc/passwd | xargs`
         echo "Duplicate User Name ($2): ${uids}"
    fi
done
		#17 Check for Duplicate Group Names
echo ""
bold
echo "Checking for Duplicate Group Names"
echo ""
unbold
cat /etc/group | cut -f1 -d"":"" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
     [ -z "${x}" ] && break
     set - $x
     if [ $1 -gt 1 ]; then
          gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
          echo "Duplicate Group Name ($2): ${gids}"
     fi
done
		#18 Check for Presence of User .netrc Files
echo ""
bold
echo "Checking for Presence of User .netrc Files"
echo ""
unbold
for dir in `/bin/cat /etc/passwd |/bin/awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
echo ".netrc file $dir/.netrc exists"
fi
done
		#19 Check for Presence of User .forward Files
echo ""
bold
echo "Checking for Presence of User .forward Files"
echo ""
unbold
for dir in `/bin/cat /etc/passwd | /bin/awk -F: '{ print $6 }'`; do
       if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
           echo ".forward file $dir/.forward exists"
       fi
done

chmod 750 /etc/abrt
find /var/log -type f -exec chmod g-wx,o-rwx {} \;
echo y | cp -p /lib/tmpfiles.d/var.conf /lib/tmpfiles.d/var.conf.bak
sed -i s_"log\/wtmp 0664"_"log\/wtmp 0644"_g /lib/tmpfiles.d/var.conf
}

CLEAN > /dev/null 2>&1
VARIABLE
checkroot
checksystem
BANNER
echo "Do you want to continue to harden the server $hostname1 [Y|N][N]: "
status
if [ $status = "Y" ]
then
echo "Hardening will take Minutes; Please wait"
HARDEN > /dev/null 2>&1
echo ""
bold
echo "Kindly refer to the file /var/tmp/Manual_check. If there is any non-complaint, this has to be fixed manually"
unbold
MANUALL > /tmp/.harden/manuall 2>&1
echo ""
cat /tmp/.harden/manuall | grep -v "No such file or directory" > /var/tmp/Manual_check
bold
echo "Hardening is completed successfully"
echo "Kindly reboot the server. Thanks"
unbold
fi
CLEAN > /dev/null 2>&1
EXIT
