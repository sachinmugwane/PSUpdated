#!/bin/bash

#set -x

## *******************************************************************************************************************************************************************************

##Password Policies

## *******************************************************************************************************************************************************************************


## Policy from login.defs

r_awx_pwd_expiry="90"
c_awx_pwd_expiry=$(cat /etc/login.defs | grep ^PASS_MAX_DAYS | awk '{print $2}')
if [ $r_awx_pwd_expiry == $c_awx_pwd_expiry  ]; then
        c_awx_pwd_expiry_all=$(cat /etc/login.defs | grep ^PASS_MAX_DAYS)
        s_awx_pwd_expiry="Compliant"
else
        c_awx_pwd_expiry_all=$(cat /etc/login.defs | grep ^PASS_MAX_DAYS)
        s_awx_pwd_expiry="Non-Compliant"
fi

#-----

r_awx_pwd_min_length="8"
c_awx_pwd_min_length=$(cat /etc/login.defs | grep ^PASS_MIN_LEN | awk '{print $2}')
if [ $r_awx_pwd_min_length == $c_awx_pwd_min_length  ]; then
        c_awx_pwd_length_all=$(cat /etc/login.defs | grep ^PASS_MIN_LEN)
        s_awx_pwd_length="Compliant"
else
        c_awx_pwd_length_all=$(cat /etc/login.defs | grep ^PASS_MIN_LEN)
        s_awx_pwd_length="Non-Compliant"
fi

#-----

r_awx_pwd_encryption="SHA512"
c_awx_pwd_encryption=$(cat /etc/login.defs |grep ^ENCRYPT_METHOD | awk '{print $2}')
if [ $r_awx_pwd_encryption == $c_awx_pwd_encryption ];then
   c_awx_pwd_encryption_all=$(cat /etc/login.defs |grep ^ENCRYPT_METHOD)
   s_awx_pwd_encryption_all="Compliant"
else
   c_awx_pwd_encryption_all=$(cat /etc/login.defs |grep ^ENCRYPT_METHOD)
   s_awx_pwd_encryption_all="Compliant"
fi

### Policy in PAM.D

r_awx_pwd_complex_difok="difok=2"
c_awx_pwd_complex_difok=$(cat /etc/pam.d/common-password | egrep -Eo "difok=2")

r_awx_pwd_complex_dcredit="dcredit=-1"
c_awx_pwd_complex_dcredit=$(cat /etc/pam.d/common-password | egrep -Eo "dcredit=-1")

r_awx_pwd_complex_ucredit="ucredit=-1"
c_awx_pwd_complex_ucredit=$(cat /etc/pam.d/common-password | egrep -Eo "ucredit=-1")

r_awx_pwd_complex_ocredit="ocredit=-1"
c_awx_pwd_complex_ocredit=$(cat /etc/pam.d/common-password | egrep -Eo "ocredit=-1")

r_awx_pwd_complex_lcredit="lcredit=-1"
c_awx_pwd_complex_lcredit=$(cat /etc/pam.d/common-password | egrep -Eo "lcredit=-1")

r_awx_account_lockout="deny=5"
c_awx_account_lockout=$(cat /etc/pam.d/common-auth | egrep -Eo "deny=5" | wc -l)
c_awx_account_lockout_all=$(cat /etc/pam.d/common-auth | egrep -Eo "deny=5" | head -n1)

r_awx_pwd_policy="Password Policy to be configured as below: <br/><br/>$r_awx_pwd_complex_difok<br/>$r_awx_pwd_complex_dcredit<br/>$r_awx_pwd_complex_ucredit<br/>$r_awx_pwd_complex_ocredit<br/>$r_awx_pwd_complex_lcredit<br/>$r_awx_account_lockout"

if [ $c_awx_pwd_complex_lcredit ] && [ $c_awx_pwd_complex_ocredit ] && [ $c_awx_pwd_complex_ucredit ] && [ $c_awx_pwd_complex_dcredit  ] && [ $c_awx_pwd_complex_difok ] && [ $c_awx_account_lockout -gt 0 ]; then
  c_awx_pwd_policy="Below Policy has been applied: <br/><br/>$c_awx_pwd_complex_difok<br/>$c_awx_pwd_complex_dcredit<br/>$c_awx_pwd_complex_ucredit<br/>$c_awx_pwd_complex_ocredit<br/>$c_awx_pwd_complex_lcredit<br/>$c_awx_account_lockout_all"
  s_awx_pwd_policy="Compliant"
else
  c_awx_pwd_policy="Below/None Policy has been applied: <br/><br/>$c_awx_pwd_complex_difok<br/>$c_awx_pwd_complex_dcredit<br/>$c_awx_pwd_complex_ucredit<br/>$c_awx_pwd_complex_ocredit<br/>$c_awx_pwd_complex_lcredit<br/>$c_awx_account_lockout_all"
  s_awx_pwd_policy="Non-Compliant"
fi




## *******************************************************************************************************************************************************************************

## SSHD Hardening

## *******************************************************************************************************************************************************************************




# SSH Harden PermitRootLogin

r_awx_ssh_permitrootlogin="no"
c_awx_ssh_permitrootlogin=$(cat /etc/ssh/sshd_config | grep -i ^PermitRootLogin | awk '{print $2}')
c_awx_ssh_permitrootlogin_all=$(cat /etc/ssh/sshd_config | grep -i ^PermitRootLogin)
if [ $r_awx_ssh_permitrootlogin == $c_awx_ssh_permitrootlogin  ];then
        s_awx_ssh_permitrootlogin="Compliant"
else
        s_awx_ssh_permitrootlogin="Non-Compliant"
fi


# SSH Harden PermitEmptyPasswords

r_awx_ssh_permitemptypasswords="no"
c_awx_ssh_permitemptypasswords=$(cat /etc/ssh/sshd_config | grep -i ^PermitEmptyPasswords | awk '{print $2}')
c_awx_ssh_permitemptypasswords_all=$(cat /etc/ssh/sshd_config | grep -i ^PermitEmptyPasswords)
if [ $r_awx_ssh_permitemptypasswords == $c_awx_ssh_permitemptypasswords  ];then
        s_awx_ssh_permitemptypasswords="Compliant"
else
        s_awx_ssh_permitemptypasswords="Non-Compliant"
fi



## SSH Harden UsePAM

r_awx_ssh_usepam="yes"
c_awx_ssh_usepam=$(cat /etc/ssh/sshd_config | grep -i ^UsePAM | awk '{print $2}')
c_awx_ssh_usepam_all=$(cat /etc/ssh/sshd_config | grep -i ^UsePAM)
if [ $r_awx_ssh_usepam == $c_awx_ssh_usepam  ];then
        s_awx_ssh_usepam="Compliant"
else
        s_awx_ssh_usepam="Non-Compliant"
fi


## SSH Harden X11Forwarding

r_awx_ssh_x11forward="yes"
c_awx_ssh_x11forward=$(cat /etc/ssh/sshd_config | grep -i "^X11Forwarding" | awk '{print $2}')
c_awx_ssh_x11forward_all=$(cat /etc/ssh/sshd_config | grep -i "^X11Forwarding")
if [ $r_awx_ssh_x11forward == $c_awx_ssh_x11forward  ];then
        s_awx_ssh_x11forward="Compliant"
else
        s_awx_ssh_x11forward="Non-Compliant"
fi


## SSH Harden IgnoreRhosts

r_awx_ssh_ignorerhosts="yes"
c_awx_ssh_ignorerhosts=$(cat /etc/ssh/sshd_config | grep -i ^IgnoreRhosts | awk '{print $2}')
c_awx_ssh_ignorerhosts_all=$(cat /etc/ssh/sshd_config | grep -i ^IgnoreRhosts)
if [ $r_awx_ssh_ignorerhosts == $c_awx_ssh_ignorerhosts  ];then
        s_awx_ssh_ignorerhosts="Compliant"
else
        s_awx_ssh_ignorerhosts="Non-Compliant"
fi




## *******************************************************************************************************************************************************************************

## SYSCTL Hardening

## *******************************************************************************************************************************************************************************



## SYSCTL Disable IPv6

r_awx_sysctl_disable_ipv6="1"
c_awx_sysctl_disable_ipv6=$(cat /etc/sysctl.conf | grep ^net.ipv6.conf.all.disable_ipv6 | awk -F"=" '{print $2}')
c_awx_sysctl_disable_ipv6_all=$(cat /etc/sysctl.conf | grep ^net.ipv6.conf.all.disable_ipv6)
if [ $r_awx_sysctl_disable_ipv6 == $c_awx_sysctl_disable_ipv6  ];then
        s_awx_sysctl_disable_ipv6="Compliant"
else
        s_awx_sysctl_disable_ipv6="Non-Compliant"
fi


## SYSCTL Disable IPv4 Forwarding

docker_installed=$(docker ps -a | wc -l)
kubernetes_installed=$(kubectl get nodes -o wide | sed 1d | wc -l)
r_awx_sysctl_disable_ipv4_forwarding_docker="0"
r_awx_sysctl_disable_ipv4_forwarding="0"
c_awx_sysctl_disable_ipv4_forwarding=$(cat /etc/sysctl.conf |grep "^net.ipv4.ip_forward=" | awk -F= '{print $2}')
c_awx_sysctl_disable_ipv4_forwarding_all=$(cat /etc/sysctl.conf |grep "^net.ipv4.ip_forward=")
if [ $r_awx_sysctl_disable_ipv4_forwarding == $c_awx_sysctl_disable_ipv4_forwarding ];then
        s_awx_sysctl_disable_ipv4_forwarding="Compliant"
elif [ $docker_installed -ge 1 ]; then
        s_awx_sysctl_disable_ipv4_forwarding="Compliant"
elif [ $kubernetes_installed -ge 1 ]; then
        s_awx_sysctl_disable_ipv4_forwarding="Compliant"
else
        s_awx_sysctl_disable_ipv4_forwarding="Non-Compliant"
fi






## *******************************************************************************************************************************************************************************

## AUDIT Hardening Configurations

## *******************************************************************************************************************************************************************************



## Audit Hardening Sudoers Actions

r_awx_audit_sudoers_action="-w /etc/sudoers -p wa -k actions"
c_awx_audit_sudoers_action=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_sudoers_action")

if [[ $r_awx_audit_sudoers_action == $c_awx_audit_sudoers_action ]]; then
        s_awx_audit_sudoers_action="Compliant"
else
        s_awx_audit_sudoers_action="Non-Compliant"
fi


## Audit Hardening Session Initiation Information

r_awx_audit_utmp="-w /var/run/utmp -p wa -k session"
r_awx_audit_btmp="-w /var/log/btmp -p wa -k session"
r_awx_audit_wtmp="-w /var/log/wtmp -p wa -k session"

c_awx_audit_utmp=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_utmp")
c_awx_audit_btmp=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_btmp")
c_awx_audit_wtmp=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_wtmp")



if [[ $r_awx_audit_utmp == $c_awx_audit_utmp ]] && [[ $r_awx_audit_btmp == $c_awx_audit_btmp ]] && [[ $r_awx_audit_wtmp == $c_awx_audit_wtmp ]]; then
        s_awx_audit_utmp_btmp_wtmp="Compliant"
else
        s_awx_audit_utmp_btmp_wtmp="Non-Compliant"
fi

## Audit Hardening Unauth Access Files EACCESS

r_awx_audit_unauth_access_files_1="-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES ....."
c_awx_audit_unauth_access_files_1=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_unauth_access_files_1")
c_awx_audit_unauth_access_files_1_count=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_unauth_access_files_1" | wc -l )

if [ $c_awx_audit_unauth_access_files_1_count -eq 1 ]; then
        s_awx_audit_unauth_access_files_1="Compliant"
else
        s_awx_audit_unauth_access_files_1="Non-Compliant"
fi



## Audit Hardening Unauth Access Files EPERM


r_awx_audit_unauth_access_files_2="-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM ....."
c_awx_audit_unauth_access_files_2=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_unauth_access_files_2")
c_awx_audit_unauth_access_files_2_count=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_unauth_access_files_2" | wc -l )
if [ $c_awx_audit_unauth_access_files_2_count -eq 1 ]; then
        s_awx_audit_unauth_access_files_2="Compliant"
else
        s_awx_audit_unauth_access_files_2="Non-Compliant"
fi



## Audit Hardening Login & Logout sessions

r_awx_audit_faillog="-w /var/log/faillog -p wa -k logins"
r_awx_audit_lastlog="-w /var/log/lastlog -p wa -k logins"

c_awx_audit_faillog=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_faillog")
c_awx_audit_lastlog=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_lastlog")



if [[ $r_awx_audit_faillog == $c_awx_audit_faillog ]] && [[ $r_awx_audit_lastlog == $c_awx_audit_lastlog ]]; then
        s_awx_audit_faillog_lastlog="Compliant"
else
        s_awx_audit_faillog_lastlog="Non-Compliant"
fi


## Audit Hardening Root Commands 64

r_awx_audit_root_commands_64="-a exit,always -F arch=b64 -F euid=0 -S execve -k root-commands"
c_awx_audit_root_commands_64=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_root_commands_64")

if [[ $r_awx_audit_root_commands_64 == $c_awx_audit_root_commands_64 ]]; then
        s_awx_audit_root_commands_64="Compliant"
else
        s_awx_audit_root_commands_64="Non-Compliant"
fi

## Audit Hardening Root Commands 32

r_awx_audit_root_commands_32="-a exit,always -F arch=b32 -F euid=0 -S execve -k root-commands"
c_awx_audit_root_commands_32=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_root_commands_32")

if [[ $r_awx_audit_root_commands_32 == $c_awx_audit_root_commands_32 ]]; then
        s_awx_audit_root_commands_32="Compliant"
else
        s_awx_audit_root_commands_32="Non-Compliant"
fi


## Audit Hardening Delete All Rules

r_awx_audit_delete_all_rules="-D"
c_awx_audit_delete_all_rules=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_delete_all_rules")

if [[ $r_awx_audit_delete_all_rules == $c_awx_audit_delete_all_rules ]]; then
        s_awx_audit_delete_all_rules="Compliant"
else
        s_awx_audit_delete_all_rules="Non-Compliant"
fi

## Audit Hardening Buffer Limits

r_awx_audit_buffer_size="-b {buffer_size}"
c_awx_audit_buffer_size=$(cat /etc/audit/rules.d/audit.rules | grep -Eo "^-b [0-9]{1,9}")
c_awx_audit_buffer_size_count=$(cat /etc/audit/rules.d/audit.rules | grep -Eo "^-b [0-9]{1,9}" | wc -l)

if [ $c_awx_audit_buffer_size_count -eq 1 ]; then
        s_awx_audit_buffer_size="Compliant"
else
        s_awx_audit_buffer_size="Non-Compliant"
fi

## Audit Hardening for Immutable

r_awx_audit_immutable="-e 2"
c_awx_audit_immutable=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_immutable")

if [[ $r_awx_audit_immutable == $c_awx_audit_immutable ]]; then
        s_awx_audit_immutable="Compliant"
else
        s_awx_audit_immutable="Non-Compliant"
fi

## Audit Hardening Backlog Wait Time

r_awx_audit_backlog_wait_time="--backlog_wait_time {time in ms}"
c_awx_audit_backlog_wait_time=$(cat /etc/audit/rules.d/audit.rules | grep "^--backlog_wait_time")

c_awx_audit_backlog_wait_time_count=$(cat /etc/audit/rules.d/audit.rules | grep "^--backlog_wait_time" | wc -l)

if [ $c_awx_audit_backlog_wait_time_count -eq 1 ]; then
        s_awx_audit_backlog_wait_time="Compliant"
else
        s_awx_audit_backlog_wait_time="Non-Compliant"
fi


## Audit Hardening for Failure Mode

r_awx_audit_failure_mode="-f 1"
c_awx_audit_failure_mode=$(cat /etc/audit/rules.d/audit.rules | grep "^$r_awx_audit_failure_mode")

if [[ $r_awx_audit_failure_mode == $c_awx_audit_failure_mode ]]; then
        s_awx_audit_failure_mode="Compliant"
else
        s_awx_audit_failure_mode="Non-Compliant"
fi



## *******************************************************************************************************************************************************************************

## Password & Shadow Files Permissions

## *******************************************************************************************************************************************************************************



## Password & Shadow File Permissions "/etc/passwd"


c_awx_passwd_perm_all=`(stat -c %a /etc/passwd ; stat -c %U /etc/passwd ; stat -c %G /etc/passwd) | tr '\n' '\t'`
r_awx_passwd_perm_all="644     root    root"
c_awx_passwd_perm=$(stat -c %a /etc/passwd)
c_awx_passwd_user=$(stat -c %U /etc/passwd)
c_awx_passwd_group=$(stat -c %G /etc/passwd)


if [[ $c_awx_passwd_perm == "644" ]] && [[ $c_awx_passwd_user == "root" ]] && [[ $c_awx_passwd_group == "root" ]]; then
    s_awx_passwd_perm="Compliant"
else
    s_awx_passwd_perm="Non-Compliant"
fi

## Password & Shadow File Permissions "/etc/shadow"

c_awx_shadow_perm_all=`(stat -c %a /etc/shadow ; stat -c %U /etc/shadow ; stat -c %G /etc/shadow) | tr '\n' '\t'`
r_awx_shadow_perm_all="640  root  shadow"
c_awx_shadow_perm=$(stat -c %a /etc/shadow)
c_awx_shadow_user=$(stat -c %U /etc/shadow)
c_awx_shadow_group=$(stat -c %G /etc/shadow)


if [[ $c_awx_shadow_perm == "640" ]] && [[ $c_awx_shadow_user == "root" ]] && [[ $c_awx_shadow_group == "shadow" ]]; then
    s_awx_shadow_perm="Compliant"
else
    s_awx_shadow_perm="Non-Compliant"
fi


## Password & Shadow File Permissions "/etc/gshadow"


c_awx_gshadow_perm_all=`(stat -c %a /etc/gshadow ; stat -c %U /etc/gshadow ; stat -c %G /etc/shadow) | tr '\n' '\t'`
r_awx_gshadow_perm_all="640  root  shadow"
c_awx_gshadow_perm=$(stat -c %a /etc/gshadow)
c_awx_gshadow_user=$(stat -c %U /etc/gshadow)
c_awx_gshadow_group=$(stat -c %G /etc/gshadow)


if [[ $c_awx_gshadow_perm == "640" ]] && [[ $c_awx_gshadow_user == "root" ]] && [[ $c_awx_gshadow_group == "shadow" ]]; then
    s_awx_gshadow_perm="Compliant"
else
    s_awx_gshadow_perm="Non-Compliant"
fi


## Password & Shadow File Permissions "/etc/passwd-"


c_awx_passwd_hyphen_perm_all=`(stat -c %a /etc/passwd- ; stat -c %U /etc/passwd- ; stat -c %G /etc/passwd-) | tr '\n' '\t'`
r_awx_passwd_hyphen_perm_all="644  root  root"
c_awx_passwd_hyphen_perm=$(stat -c %a /etc/passwd-)
c_awx_passwd_hyphen_user=$(stat -c %U /etc/passwd-)
c_awx_passwd_hyphen_group=$(stat -c %G /etc/passwd-)


if [[ $c_awx_passwd_hyphen_perm == "644" ]] && [[ $c_awx_passwd_hyphen_user == "root" ]] && [[ $c_awx_passwd_hyphen_group == "root" ]]; then
    s_awx_passwd_hyphen_perm="Compliant"
else
    s_awx_passwd_hyphen_perm="Non-Compliant"
fi

## Password & Shadow File Permissions "/etc/shadow-"

c_awx_shadow_hyphen_perm_all=`(stat -c %a /etc/shadow- ; stat -c %U /etc/shadow- ; stat -c %G /etc/shadow-) | tr '\n' '\t'`
r_awx_shadow_hyphen_perm_all="640  root  shadow"
c_awx_shadow_hyphen_perm=$(stat -c %a /etc/shadow-)
c_awx_shadow_hyphen_user=$(stat -c %U /etc/shadow-)
c_awx_shadow_hyphen_group=$(stat -c %G /etc/shadow-)


if [[ $c_awx_shadow_hyphen_perm == "640" ]] && [[ $c_awx_shadow_hyphen_user == "root" ]] && [[ $c_awx_shadow_hyphen_group == "shadow" ]]; then
    s_awx_shadow_hyphen_perm="Compliant"
else
    s_awx_shadow_hyphen_perm="Non-Compliant"
fi


## Password & Shadow File Permissions "/etc/gshadow-"


c_awx_gshadow_hyphen_perm_all=`(stat -c %a /etc/gshadow- ; stat -c %U /etc/gshadow- ; stat -c %G /etc/shadow-) | tr '\n' '\t'`
r_awx_gshadow_hyphen_perm_all="640  root  shadow"
c_awx_gshadow_hyphen_perm=$(stat -c %a /etc/gshadow-)
c_awx_gshadow_hyphen_user=$(stat -c %U /etc/gshadow-)
c_awx_gshadow_hyphen_group=$(stat -c %G /etc/gshadow-)


if [[ $c_awx_gshadow_hyphen_perm == "640" ]] && [[ $c_awx_gshadow_hyphen_user == "root" ]] && [[ $c_awx_gshadow_hyphen_group == "shadow" ]]; then
    s_awx_gshadow_hyphen_perm="Compliant"
else
    s_awx_gshadow_hyphen_perm="Non-Compliant"
fi



## *******************************************************************************************************************************************************************************

## Validate if Required services are disabled and removed from server

## *******************************************************************************************************************************************************************************



r_awx_packages_all="Remove/Disable below Services<br/><br/>telnet<br/>telnetd<br/>vsftpd<br/>ftp<br/>tftp<br/>rsh_server<br/>rsh"
r_awx_nfs_server_status="NFS-Server service should be in in-active state"
r_awx_ufw_status="UFW Service status should be in in-active state"
r_sestatus="Selinux Status should be in disabled state"


c_awx_telnet=`(apt list --installed telnet | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_telnet_server=`(apt list --installed telnetd  | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_vsftpd=`(apt list --installed vsftpd  | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_ftp=`(apt list --installed  ftp | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_tftp=`(apt list --installed tftp  | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_nfs_server=$(systemctl is-active nfs-server)
c_awx_ufw=$(systemctl is-active ufw.service)
c_awx_rsh_server=`(apt list --installed rsh-server  | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`
c_awx_rsh=`(apt list --installed rsh  | grep -v Listing | awk '{split($0, a, "/"); print a[1]}') 2> /dev/null`


if [ $c_awx_telnet ] || [ $c_awx_telnet_server  ] || [ $c_awx_vsftpd ] || [ $c_awx_ftp ] || [ $c_awx_tftp  ] || [ $c_awx_rsh_server ] || [ $c_awx_rsh_server  ]; then
   echo "Some packages are Installed on server<br/><br/>$c_awx_telnet<br/>$c_awx_telnet_server<br/>$c_awx_vsftpd<br/>$c_awx_ftp<br/>$c_awx_tftp<br/>$c_awx_rsh_server<br/>$c_awx_rsh"
   echo Non-Compliant
else
   echo "None of the Packages are Installed on Server"
   echo "Compliant"
fi





if [ $c_awx_telnet ] || [ $c_awx_telnet_server ] || [ $c_awx_vsftpd ] || [ $c_awx_tftp ] || [ $c_awx_rsh_server ] || [ $c_awx_rsh_server ]; then
   c_awx_packages_all=`echo "Some packages are Installed on server<br/><br/>$c_awx_telnet<br/>$c_awx_telnet_server<br/>$c_awx_vsftpd<br/>$c_awx_tftp<br/>$c_awx_tftp<br/>$c_awx_rsh_server<br/>$c_awx_rsh"`
   s_awx_packages_all="Non-Compliant"
else
   c_awx_packages_all="None of the Packages are Installed on Server"
   s_awx_packages_all="Compliant"
fi



if [ $c_awx_nfs_server == "active" ]; then
   c_awx_nfs_server_status="nfs-server service is -- $c_awx_nfs_server"
   s_awx_nfs_server_status="Non-Compliant"
else
   c_awx_nfs_server_status="nfs-server service is -- $c_awx_nfs_server"
   s_awx_nfs_server_status="Compliant"
fi


if [ $c_awx_ufw == "active" ]; then
   c_awx_ufw_status="UFW service is -- $c_awx_ufw"
   s_awx_ufw_status="Non-Compliant"
else
   c_awx_ufw_status="UFW service is -- $c_awx_ufw"
   s_awx_ufw_status="Compliant"
fi


if [ `dpkg --list  |grep policycoreutils` ]; then
c_sestatus=$(sestatus | grep "^SELinux status:" | awk -F: '{print $2}' | awk '{$1=$1};1')
   if [ $c_sestatus != "disabled" ]; then
      c_awx_selinux_status="Selinux Status is -- $c_sestatus"
      s_awx_selinux_status="Non-Compliant"
   else
      c_awx_selinux_status="Selinux Status is -- $c_sestatus"
      s_awx_selinux_status="Compliant"
   fi
else
   c_awx_selinux_status="Selinux related Package is not Installed -- policycoreutils, Hence Disabled"
   s_awx_selinux_status="Compliant"
fi



## *******************************************************************************************************************************************************************************

## Validate Syslog Configurations

## *******************************************************************************************************************************************************************************

### Syslog Configuration for Logs creation

r_awx_syslog_syslog="/var/log/syslog"
r_awx_syslog_auth="/var/log/auth.log"
r_awx_syslog_cron="/var/log/cron.log"
r_awx_syslog_kern="/var/log/kern.log"
r_awx_syslog_cmdlog="/var/log/cmdlog"


if [ -f /etc/rsyslog.conf ];then

c_awx_syslog_syslog=$(cat /etc/rsyslog.conf | grep "/var/log/syslog" | wc -l)
c_awx_syslog_auth=$(cat /etc/rsyslog.conf | grep "/var/log/auth.log" | wc -l)
c_awx_syslog_cron=$(cat /etc/rsyslog.conf | grep "/var/log/cron.log" | wc -l)
c_awx_syslog_kern=$(cat /etc/rsyslog.conf | grep "/var/log/kern.log" | wc -l)
c_awx_syslog_cmdlog=$(cat /etc/rsyslog.conf | grep "/var/log/cmdlog" | wc -l)

r_awx_syslog_all="auth,authpriv.*                                         /var/log/auth.log
cron.*                                                  /var/log/cron.log
*.*;auth,authpriv.none                                  -/var/log/syslog
kern.*                                                  -/var/log/kern.log
local6.notice                                        /var/log/cmdlog"


        if [ $c_awx_syslog_syslog -gt 0 ] && [ $c_awx_syslog_auth -gt 0 ] && [ $c_awx_syslog_cron -gt 0 ] && [ $c_awx_syslog_kern -gt 0 ] && [ $c_awx_syslog_cmdlog -gt 0 ]; then
                c_awx_syslog_all=$(cat /etc/rsyslog.conf | grep "/var/log")
                s_awx_syslog_all="Compliant"
        else
                c_awx_syslog_all=$(cat /etc/rsyslog.conf | grep "/var/log")
                s_awx_syslog_all="Non-Compliant"
        fi

else
    c_awx_syslog_all="Syslog Package is not Installed or file not available"
    s_awx_syslog_all="Non-Compliant"
fi



### Syslog forwarding to Qradar



r_awx_syslog_qradar="Configuration Should be something like below: <br/><br/>*.* @@{IP-Address}:514"
c_awx_syslog_qradar_count=$(cat /etc/rsyslog.conf | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}:514\b"| wc -l)
c_awx_syslog_qradar=$(cat /etc/rsyslog.conf | grep "^*.*@@" | grep ":514")

if [ $c_awx_syslog_qradar_count -gt 0 ];then
  s_awx_syslog_qradar="Compliant"
else
  s_awx_syslog_qradar="Non-Compliant"
fi



## *******************************************************************************************************************************************************************************

## History & Timestamp

## *******************************************************************************************************************************************************************************


## Configrure Commands History Timestamp and Size

r_awx_history_ts="HISTTIMEFORMAT={Any TimeStamp Format}"
r_awx_history_size="HISTSIZE={Number of History Commands}"


if [ -f /etc/profile.d/history.sh ]; then
  c_awx_history_ts=$(cat /etc/profile.d/history.sh | grep ^HISTTIMEFORMAT)
  c_awx_history_ts_count=$(cat /etc/profile.d/history.sh | grep ^HISTTIMEFORMAT | wc -l)
  c_awx_history_size=$(cat /etc/profile.d/history.sh | grep ^HISTSIZE)
  c_awx_history_size_count=$(cat /etc/profile.d/history.sh | grep ^HISTSIZE | wc -l)
  if [ $c_awx_history_size_count -eq 1 ] && [ $c_awx_history_ts_count -eq 1 ]; then
     s_awx_history_ts_size="Compliant"
  else
     s_awx_history_ts_size="Non-Compliant"
  fi
elif [ -f /etc/profile ]; then
  c_awx_history_ts=$(cat /etc/profile | grep "^export HISTTIMEFORMAT")
  c_awx_history_ts_count=$(cat /etc/profile | grep "^ export HISTTIMEFORMAT" | wc -l)
  c_awx_history_size=$(cat /etc/profile | grep ^HISTSIZE)
  c_awx_history_size_count=$(cat /etc/profile | grep ^HISTSIZE | wc -l)
  if [ $c_awx_history_size_count -eq 1 ] && [ $c_awx_history_ts_count -eq 1 ]; then
     s_awx_history_ts_size="Compliant"
  else
     s_awx_history_ts_size="Non-Compliant"
  fi
else
  c_awx_history_size="No History Size Configured under Profile"
  c_awx_history_ts="No History Timestamp Configured under Profile"
  s_awx_history_ts_size="Non-Compliant"
fi


## *******************************************************************************************************************************************************************************

## Login Banner

## *******************************************************************************************************************************************************************************


r_awx_banner="Banner should be configured similar to below with file /usr/local/bin/dynmotd<br/><br/>
 *****************************************************************************************
 *                            Welcome to Bajaj Finance Limited                           *
 *****************************************************************************************
 *             YOU MAY USE THIS SYSTEM ONLY IF YOU ARE AUTHORIZED USER                   *
 *****************************************************************************************
 *                                                                                       *
 *     This computer system is owned by Bajaj Finance Limited(BFL) and is intended       *
 *        intended to be used solely for BFL's business purpose. As such, BFL            *
 *         reserves the right to monitor all user activities and information             *
 *        present on all the BFL provided equipments and services. Use of the            *
 *        BFL provided information systems and networks in violation of BFL's            *
 *        Information Security Policy will result in disciplinary action. For            *
 *         further details please refer to BFL's Information Security Policy.            *
 *                                                                                       *
 *****************************************************************************************
"

if [ -f /usr/local/bin/dynmotd ] && [ -s /usr/local/bin/dynmotd ]; then
   if [ `stat -c %s /usr/local/bin/dynmotd` == "1396" ] && [ `cat /usr/local/bin/dynmotd | grep "YOU MAY USE THIS SYSTEM ONLY IF YOU ARE AUTHORIZED USER" | wc -l` == "1" ]; then
      c_awx_banner=$(cat /usr/local/bin/dynmotd | grep -v "[0-9]")
      s_awx_banner="Compliant"
   else
      c_awx_banner=`echo "Configured with Different Banner as shown below. Need as per required parameter<br/><br/>" ; cat /usr/local/bin/dynmotd | grep -v "[0-9]"`
      s_awx_banner="Non-Compliant"
   fi
else
      c_awx_banner="Banner is not configured via dynmotd /usr/local/bin/dynmotd"
      s_awx_banner="Non-Compliant"
fi


## *******************************************************************************************************************************************************************************

## Validate Cron & AT Deamons

## *******************************************************************************************************************************************************************************



r_awx_cron_at="/etc/cron.deny /etc/at.allow /etc/at.deny Should not available.<br>And Just /etc/cron.allow should available with allowed Users only."
if [ ! -f /etc/cron.deny ] && [ ! -f /etc/at.allow ] && [ ! -f /etc/at.deny ] && [ -f /etc/cron.allow ]; then
    c_awx_cron_at="/etc/cron.deny /etc/at.allow /etc/at.deny Absent on server<br/>/etc/cron.allow present on server to only allow required users. <br/><br/>`ls -l /etc/cron.allow /etc/cron.deny /etc/at.deny /etc/at.allow`"
    s_awx_cron_at="Compliant"
else
    c_awx_cron_at="Any or All of the /etc/cron.deny /etc/at.allow /etc/at.deny present on server<br/>Or /etc/cron.allow absent on server."
    s_awx_cron_at="Non-Compliant"
fi


## *******************************************************************************************************************************************************************************

## Validate NTP/Chrony Configurations

## *******************************************************************************************************************************************************************************



r_ntp_config="server {NTP Server IPAddress}"
if [ -f  /etc/ntp.conf ] && [ `systemctl is-active ntpd` == "active" ]; then
ntp_count=$(cat /etc/ntp.conf | grep -i "^server" | wc -l)
  if [ $ntp_count -gt 0 ]; then
     c_ntp_config=`echo "NTP Configuration is being done in /etc/ntp.conf<br/><br/>"; cat /etc/ntp.conf | grep "^server"`
     s_ntp_config="Compliant"
  else
     c_ntp_config="NTP Configuration is Not done in /etc/ntp.conf"
     s_ntp_config="Non-Compliant"
  fi
elif [ -f  /etc/chrony/chrony.conf ] && [ `systemctl is-active chronyd` == "active" ]; then

#### Example - cat /etc/chrony.conf | egrep -i "^server|^pool" | awk '{print $2}' | grep -Eo "([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*"

chrony_count=$(cat /etc/chrony/chrony.conf | egrep -i "^server|^pool" | wc -l)
  if [ $chrony_count -gt 0 ]; then
     c_ntp_config=`echo "NTP Configuration is being done in /etc/chrony/chrony.conf<br/><br/>"; cat /etc/chrony/chrony.conf | egrep -i "^server|^pool"`
     s_ntp_config="Compliant"
  else
     c_ntp_config="NTP Configuration is Not done in /etc/chrony/chrony.conf"
     s_ntp_config="Non-Compliant"
  fi
else
  c_ntp_config="NTP Configuration is Not done in /etc/chrony/chrony.conf"
  echo "Not configured in NTP or CHRONY"
fi



## *******************************************************************************************************************************************************************************

## No Users should Have Empty Passwords

## *******************************************************************************************************************************************************************************



## Check for No user should have Empty Password


c_awx_empty_user_pwd_count=$(awk -F":" '($2 == "" ) {print $1}' /etc/shadow | wc -l)
r_awx_empty_user_pwd="No user should be present with Empty Password"
if [ $c_awx_empty_user_pwd_count -gt 0 ]; then
  s_awx_empty_user_pwd="Non-Compliant"
  c_awx_empty_user_pwd=$(echo "Below Users available with Empty password<br/><br/>" ; awk -F":" '($2 == "" ) {print $1}' /etc/shadow)
else
  s_awx_empty_user_pwd="Compliant"
  c_awx_empty_user_pwd="No user available with Empty Password"
fi



## *******************************************************************************************************************************************************************************

## Sticky bit not set for /tmp, /var/tmp & other world writable directories

## *******************************************************************************************************************************************************************************



c_awx_sticky_bit_tmp="1777  root  root"
r_awx_sticky_bit_var_tmp="1777  root  root"

c_awx_sticky_bit_tmp=`(stat -c %a /tmp ; stat -c %U /tmp ; stat -c %G /tmp ) | tr '\n' '\t'`
c_awx_sticky_bit_var_tmp=`(stat -c %a /var/tmp ; stat -c %U /var/tmp ; stat -c %G /var/tmp ) | tr '\n' '\t'`

c_awx_sticky_bit_vartmp_perm=$(stat -c %a /var/tmp)
c_awx_sticky_bit_vartmp_user=$(stat -c %U /var/tmp)
c_awx_sticky_bit_vartmp_group=$(stat -c %G /var/tmp)

c_awx_sticky_bit_tmp_perm=$(stat -c %a /tmp)
c_awx_sticky_bit_tmp_user=$(stat -c %U /tmp)
c_awx_sticky_bit_tmp_group=$(stat -c %G /tmp)


if [[ $c_awx_sticky_bit_vartmp_perm == "1777" ]] && [[ $c_awx_sticky_bit_vartmp_user == "root" ]] && [[ $c_awx_sticky_bit_vartmp_group == "root" ]] && [[ $c_awx_sticky_bit_tmp_perm == "1777" ]] && [[ $c_awx_sticky_bit_tmp_user == "root" ]] && [[ $c_awx_sticky_bit_tmp_group == "root" ]]; then
    s_awx_stickybit_tmp_vartmp_perm="Compliant"
else
    s_awx_stickybit_tmp_vartmp_perm="Non-Compliant"
fi



## *******************************************************************************************************************************************************************************

## Active user files must be restricted to root ownership /var/log/utmpx

## *******************************************************************************************************************************************************************************


if [ -f /var/log/utmpx ]; then
   c_awx_utmpx_perm_all=`(stat -c %a /var/log/utmpx ; stat -c %U /var/log/utmpx ; stat -c %G /var/log/utmpx) | tr '\n' '\t'`
   r_awx_utmpx_perm="644  root  bin -- If file Present"
   c_awx_utmpx_perm=$(stat -c %a /var/log/utmpx)
   c_awx_utmpx_user=$(stat -c %U /var/log/utmpx)
   c_awx_utmpx_group=$(stat -c %G /var/log/utmpx)
   if [[ $c_awx_utmpx_perm == "644" ]] && [[ $c_awx_utmpx_user == "root" ]] && [[ $c_awx_utmpx_group == "bin" ]]; then
      s_awx_utmpx_perm="Compliant"
   else
      s_awx_utmpx_perm="Non-Compliant"
   fi
else
   r_awx_utmpx_perm="644  root  bin -- If file is Present"
   c_awx_utmpx_perm_all="No /var/log/utmpx file present on server"
   s_awx_utmpx_perm="Compliant"
fi






