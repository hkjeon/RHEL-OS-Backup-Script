#!/bin/bash

########################################################################
# Etech-System RHEL OS check Script
# Ver 20230331 by hkjeon@etechsystem.co.kr
#   - First Release
# Ver 20230407 by hkjeon@etechsystem.co.kr
#   - multipath.conf Add
# Ver 20230417 by hkjeon@etechsystem.co.kr
#   - PCF_EMS01.xml and PCF_EMS02.xml info Add
...
########################################################################

HOSTNAME=`hostname`
 

line() 
{ 
 	eval printf %.0s\= '{1..'${COLUMNS:-$(tput cols)}'}'; echo    
 	#eval printf %.0s\= '{1..'${COLUMNS:-80}'}'; echo    
} 

section()
{ 
	line 
    printf "%*s\n" $(((${#1}+$(tput cols))/2)) "$1" 
    #printf "%*s\n" $(((${#1}+80)/2)) "$1" 
	line 
}
	
title()
{    
    eval printf %.0s\# '{1..'${COLUMNS:-$(tput cols)}'}'; echo    
    echo -e "" 
    section "RedHat LINUX SERVER STATUS Backup & CHECK"
    echo -e "#### Version    : v1.1" 
    echo -e "#### Release    : 2024. 03. 13." 
    echo -e "#### Package    : RHOSP Bash Scripts Package"
    echo -e "#### Require    : Root Permission"
    echo -e "#### copyright  : 2023, All rights Reserved Etechsystem."
    echo -e ""
    eval printf %.0s\# '{1..'${COLUMNS:-$(tput cols)}'}'; echo  
}

cur_date()
{ 
	echo `date`
} 

syschk()
{  
	echo "HOSTNAME   : " `hostname`  
	echo "CHECK DATE : " `date`  
	echo "SYSTEM     : " `uname -a`
	echo "RH INFO    : " `cat /etc/redhat-release`
} 

pmchk()
{ 
	PMDATE=180
	UPTIME=`awk '{print int($1)}' /proc/uptime`  
	PMTIME=$((UPTIME / 86400)) 
	line
	echo 'UPTIME SINCE LAST REBOOT : ' ${PMTIME} 'days'

} 

kernelchk()
{
	section 'Kernel RPM List'
	rpm -qa | grep kernel
}

fdiskchk()
{
	section 'File System Info'
	sudo fdisk -l
	section '/etc/fstab info'
	sudo cat /etc/fstab
	section 'File System Info and Type (Human)'
	sudo df -Th
	section 'Block Device Info'
	sudo lsblk
}

cpuchk()
{
	section 'CPU Info'
	lscpu
	section 'CPU Usage Info'
	index=0	 

	mpstat -P ALL > ./cpu.txt 

	while read line; do 
		if [ $index -gt 1 ]; then  
			echo "$line"
		fi
		index=$(($index+1)) 
	done < ./cpu.txt
	rm ./cpu.txt
}

memorychk()
{
	section 'Memory Info (Human)'
	free -h
	section 'Memory Usage'
	TOTAL=`free | grep ^Mem | awk '{print $2}'`
	USED1=`free | grep ^Mem | awk '{print $3}'`
	USED2=`free | grep ^-/+ | awk '{print $3}'`
	NOMINAL=$((100*USED1/TOTAL))
	ACTUAL=$((100*USED2/TOTAL))
	echo NOMINAL=${NOMINAL}% ACTUAL=${ACTUAL}% 
}


basicinfo()
{
	cur_date
	syschk
	pmchk
	kernelchk
	fdiskchk
	cpuchk
	memorychk
}

limitchk()
{
	section '/etc/security/limits.conf Info'
	sudo cat /etc/security/limits.conf
	section '/etc/security/limits.d/ Info'
	LIST1=`ls -al /etc/security/limits.d/ | awk '{print $9}' | egrep -i conf`
	for i in $LIST1; do echo -e "`readlink -f /etc/security/limits.d/$i`" && sudo cat /etc/security/limits.d/$i; done
}

sysctlchk()
{
	section '/etc/sysctl.conf Info'
	sudo cat /etc/sysctl.conf
	section '/etc/sysctl.d/ Info'
	LIST2=`ls -al /etc/sysctl.d/ | awk '{print $9}' | egrep -i conf`
	for i in $LIST2; do echo -e "`readlink -f /etc/sysctl.d/$i`" && sudo cat /etc/sysctl.d/$i; done
}

selinuxchk()
{
	section 'SELINUX and locale.conf and logrotate.conf Info'
	sudo cat /etc/selinux/config | egrep -v '^#'
	sudo cat /etc/locale.conf
	sudo cat /etc/logrotate.conf | egrep -v '^#'
}

rsyslogchk()
{
	section '/etc/rsyslog.conf Info'
	sudo cat /etc/rsyslog.conf | egrep -iv '#|^$'
	section '/etc/rsyslog.d/ Info'
	LIST3=`ls -al /etc/rsyslog.d/ | awk '{print $9}' | egrep -i conf`
	for i in $LIST3; do echo -e "`readlink -f /etc/rsyslog.d/$i`" && sudo cat /etc/rsyslog.d/$i; done
}

sysstatchk()
{
	section '/etc/cron.d/sysstat Info'
	sudo cat /etc/cron.d/sysstat
}

hostschk()
{
	section '/etc/hosts Info'
	sudo cat /etc/hosts
}

networkchk()
{
	section '/etc/sysconfig/network Info'
	sudo cat /etc/sysconfig/network
	section 'Host Bonding Info'
	BONDING=$(sudo ls /proc/net/bonding/)
	for i in $BONDING
	do
	sudo cat /proc/net/bonding/$i; done
	section 'Network Interface Info'
	LIST6=`ls -l --color /etc/sysconfig/network-scripts | egrep -iv "ifup|ifdown|init|function" | awk '{print $9}'`
	for i in $LIST6; do echo -e "`readlink -f /etc/sysconfig/network-scripts/$i`" && sudo cat /etc/sysconfig/network-scripts/$i; echo; done
	section 'Network IP Address'
	sudo ip -4 a
	section 'Network Link status'
	sudo ip link show
	section 'Network Route table'
	sudo route -n
}

sshdconfigchk()
{
	section '/etc/ssh/sshd_config Info'
	sudo cat /etc/ssh/sshd_config | egrep -iv '#|^$'
}

kdumpchk()
{
	section '/etc/kdump.conf Info'
	sudo cat /etc/kdump.conf | egrep -iv '#|^$'
}

grubchk()
{
	section '/etc/default/grub Info'
	sudo cat /etc/default/grub
}

rclocalchk()
{
	section '/etc/rc.d/rc.local'
	sudo cat /etc/rc.d/rc.local | egrep -iv '#|^$'
}

ntpchk()
{
	section '/etc/ntp.conf Info'
	sudo cat /etc/ntp.conf | egrep -iv '#|^$'
}

rulesdchk()
{
	section '/etc/udev/rules.d Info'
	LIST4=`ls -al /etc/udev/rules.d/ | awk '{print $9}' | egrep -i rules`
	for i in $LIST4; do echo -e "`readlink -f /etc/udev/rules.d/$i`" && sudo cat /etc/udev/rules.d/$i; done
}

issuechk()
{
	section '/etc/issue Info'
	sudo cat /etc/issue
	section '/etc/issue.net Info'
	sudo cat /etc/issue.net
}

motdchk()
{
	section '/etc/motd'
	sudo cat /etc/motd
}

sudoersdchk()
{
	section '/etc/sudoers.d/ Info'
	LIST5=`ls /etc/sudoers.d`
	for i in $LIST5; do echo -e "`readlink -f /etc/sudoers.d/$i`" && sudo cat /etc/sudoers.d/$i; done
}

userexpirechk()
{
	section 'User Expire data check Info'
	sudo chage -l skroot
	sudo chage -l suser
	sudo chage -l stack
	section 'PAM Tally Failures check info'
	sudo pam_tally2 -u skroot
	sudo pam_tally2 -u suser
	sudo pam_tally2 -u stack
}

pamdchk()
{
	section '/etc/pam.d/su Info'
	sudo cat /etc/pam.d/su
	section '/etc/pam.d/system-auth-ac Info'
	sudo cat /etc/pam.d/system-auth-ac
	section '/etc/pam.d/password-auth-ac Info'
	sudo cat /etc/pam.d/password-auth-ac
}

dmidecodechk()
{
	section 'Dmidecode Info'
	sudo dmidecode -t system
	sudo dmidecode | grep -s system-serial-number
}

cmdlinechk()
{
	section 'cmdline Info'
	sudo cat /proc/cmdline
	section 'meminfo Info'
	sudo cat /proc/meminfo
}

thpchk()
{
	section '/sys/kernel/mm/transparent_hugepage/enabled Info'
	sudo cat /sys/kernel/mm/transparent_hugepage/enabled
}

multipathdchk()
{
	section 'multipathd Status Info'
	sudo systemctl status multipathd
}

multipathllchk()
{
	section 'multipath -ll Info'
	sudo multipath -ll
}

multipathconfchk()
{
        section '/etc/multipath.conf Info'
        sudo cat /etc/multipath.conf
}

ntpstatuschk()
{
	section 'NTP Status Info'
	sudo ntpq -np
}

numachk()
{
	section 'NUMA Topology Info'
	sudo numactl --hardware
	sudo numactl --show
}

tunedchk()
{
	section 'Active Tuned Profile Info'
	sudo tuned-adm list
}

crontabchk()
{
	section 'crontab Info'
	sudo crontab -l
}

vbmclistchk()
{
	section 'vbmc list Info'
	sudo vbmc list
}

vmlistchk()
{
	section 'Virtual Machine List Info'
	sudo virsh list --all
}

repochk()
{
	section 'Host Repository Info'
	sudo cat /etc/yum.repos.d/*.repo
}

xmlchk()
{
        section 'XML file list for Virtual Machine'
        sudo find /etc/libvirt/qemu/ -type f -name "*.xml" -exec echo {} \;
        section 'XML Info for Virtual Machine'
        sudo find /etc/libvirt/qemu/ -type f -name "*.xml" -exec sh -c 'echo "File: $0"; eval printf %.0s\= '{1..'${COLUMNS:-$(tput cols)}'}'; echo; cat "$0"; eval printf %.0s\= '{1..'${COLUMNS:-$(tput cols)}'}'; echo' {} \;
}

rpmlistchk()
{
	section 'Host RPM List Info'
	sudo rpm -qa | sort -u
	section 'Host RPM Count Info'
	sudo rpm -qa | wc -l
}

errorchk()
{
	section '/var/log/messages error Info'
	sudo grep -i error /var/log/messages
	section '/var/log/messages warning Info'
	sudo grep -i warn /var/log/messages
	section '/var/log/messages fail Info'
	sudo grep -i fail /var/log/messages
}

dmesgchk()
{
	section 'dmesg error Info'
	sudo dmesg | grep -i error
	section 'dmesg warn Info'
	sudo dmesg | grep -i warn
	section 'dmesg fail Info'
	sudo dmesg | grep -i fail
}

osinfo()
{
	limitchk
	sysctlchk
	selinuxchk
	rsyslogchk
	sysstatchk
	hostschk
	networkchk
	sshdconfigchk
	kdumpchk
	grubchk
	rclocalchk
	ntpchk
	rulesdchk
	issuechk
	motdchk
	sudoersdchk
	userexpirechk
	pamdchk
	dmidecodechk
	cmdlinechk
	thpchk
	multipathdchk
	multipathllchk
	multipathconfchk
	ntpstatuschk
	numachk
	tunedchk
	crontabchk
	vbmclistchk
	vmlistchk
	repochk
	xmlchk
	rpmlistchk
	errorchk
	dmesgchk
}



usage()
{ 
	echo "Usage   : etech-os-backup.sh [--save {filename}  |  --print] " 
	echo "Options : \"--save filename\" will save log to filename"
	echo "          \"--save \" will save log to {Hostname}_{TODAY}.log"
	echo "          \"--print\" will print log on screen"
	echo "          \"--help\" show this help screen"
}

if [ "$#" -lt 1 ]; then  
	usage
else
	case $1 in  
		"--save" )   
			if [ -z $2 ]; then   
				filedate=`date +"%Y%m%d-%H%M%S"`
				file=${HOSTNAME}'_'${filedate}'.log' 
			elif [ -f $2 ]; then
				usage
				echo "Already exists "$2		
			else  
				file=$2	 
			fi 
		
			title >> ${file} 2>&1
			basicinfo >> ${file} 2>&1
			osinfo >> ${file} 2>&1
		;; 
		"--print" ) 
			title
			basicinfo
			osinfo
		;; 
		"--help" ) 
			usage 
			exit
		;;
	esac  
fi 

