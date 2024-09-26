#!/bin/bash

path=/tmp
name=harden_validate.html
harden=$path/$name
cat /dev/null > $harden




## *************************************************************************************************************************************************************

source /tmp/hardening_validation_script.sh > /tmp/out.txt

## *************************************************************************************************************************************************************


echo "
<html>
<head>
<style>
#servers {
  font-family: Arial, Helvetica, sans-serif;
  width: 100%;
}

table {
  border-collapse: collapse;
}

td, th {
  border: 1px solid #ccc;
  padding: 8px;
  text-align: left;
}

#servers tr:hover {background-color: #eee;}

#servers th {
  padding-top: 12px;
  padding-bottom: 12px;
  text-align: left;
  background-color: #800000;
  color: White;
}

h3 {
  padding-top: 15px;
  padding-bottom: 15px;
  text-align: center;
}
</style>
</head>
<title>`hostname` - `hostname -i | awk '{print $1}'`</title>
<body>
<h3>Linux Server Hardening Validation</h3>
" >> $harden


## *************************************************************************************************************************************************************

## Table for Compliance Headers

## *************************************************************************************************************************************************************


echo "

<table id="servers">
  <tr>
    <th>Hostname of Server</th>
    <th>`hostname` - `hostname -i | awk '{print $1}'`</th>
  <tr>
    <td>Date & Timestamp of Script Output</td>
    <td>`date`</td>
  </tr>
  <tr>
    <td>OS Version</td>
    <td>`cat /etc/os-release | grep ^NAME | awk -F= '{print $2}' | cut -c2- | rev | cut -c2- | rev` `cat /etc/os-release | grep ^VERSION_ID | awk -F= '{print $2}' | cut -c2- | rev | cut -c2- | rev`</td>
  </tr>
</table>
<br/>
<br/>
" >> $harden


## *************************************************************************************************************************************************************

## Table for Compliance Checks

## *************************************************************************************************************************************************************


echo "

<table id="servers">
  <tr>
    <th>Main Parameters</th>
    <th>Underlying Parameters</th>
    <th>Required Paramaters</th>
    <th>Configured Paramaters</th>
    <th>Compliance Status</th>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Password Policies

## *************************************************************************************************************************************************************
-->


  <tr>
    <td rowspan="4">Password Policies</td>
    <td>Complex Password Policy</td>
    <td>$r_awx_pwd_policy</td>
    <td>$c_awx_pwd_policy</td>
    <td>$s_awx_pwd_policy</td>
  </tr>
  <tr>
    <td>Password Encryption Setting</td>
    <td>ENCRYPT_METHOD  $r_awx_pwd_encryption</td>
    <td>$c_awx_pwd_encryption_all</td>
    <td>$s_awx_pwd_encryption_all</td>
  </tr>
  <tr>
    <td>Minimum Password Length</td>
    <td>PASS_MIN_LEN  $r_awx_pwd_min_length</td>
    <td>$c_awx_pwd_length_all</td>
    <td>$s_awx_pwd_length</td>
  </tr>
  <tr>
    <td>Maximum Days for Password Expiry</td>
    <td>PASS_MAX_DAYS  $r_awx_pwd_expiry</td>
    <td>$c_awx_pwd_expiry_all</td>
    <td>$s_awx_pwd_expiry</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## SSH Configuration Hardening

## *************************************************************************************************************************************************************
-->


  <tr>
    <td rowspan="5">SSH Hardening</td>
    <td>PermitRootLogin</td>
    <td>PermitRootLogin $r_awx_ssh_permitrootlogin</td>
    <td>$c_awx_ssh_permitrootlogin_all</td>
    <td>$s_awx_ssh_permitrootlogin</td>
  </tr>
  <tr>
    <td>UsePAM Config</td>
    <td>UsePAM $r_awx_ssh_usepam</td>
    <td>$c_awx_ssh_usepam_all</td>
    <td>$s_awx_ssh_usepam</td>
  </tr>
  <tr>
    <td>Disable PermitEmptyPasswords</td>
    <td>PermitEmptyPasswords $r_awx_ssh_permitemptypasswords</td>
    <td>$c_awx_ssh_permitemptypasswords_all</td>
    <td>$s_awx_ssh_permitemptypasswords</td>
  </tr>
  <tr>
    <td>IgnoreRhosts</td>
    <td>IgnoreRhosts $r_awx_ssh_ignorerhosts</td>
    <td>$c_awx_ssh_ignorerhosts_all</td>
    <td>$s_awx_ssh_ignorerhosts</td>
  </tr>
  <tr>
    <td>X11 Forwarding</td>
    <td>X11Forwarding $r_awx_ssh_x11forward</td>
    <td>$c_awx_ssh_x11forward_all</td>
    <td>$s_awx_ssh_ignorerhosts</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## SYSCTL Kernel Hardening

## *************************************************************************************************************************************************************
-->



  <tr>
    <td rowspan="2">SYSCTL Hardening</td>
    <td>Disable IPv6</td>
    <td>net.ipv6.conf.all.disable_ipv6=$r_awx_sysctl_disable_ipv6</td>
    <td>$c_awx_sysctl_disable_ipv6_all</td>
    <td>$s_awx_sysctl_disable_ipv6</td>
  </tr>
  <tr>
    <td>Disable IPv4 Forwarding</td>
    <td>net.ipv4.ip_forward=$r_awx_sysctl_disable_ipv4_forwarding<br/>net.ipv4.ip_forward=1 (For Docker Installed Systems)</td>
    <td>$c_awx_sysctl_disable_ipv4_forwarding_all</td>
    <td>$s_awx_sysctl_disable_ipv4_forwarding</td>
  </tr>



<!--
## *************************************************************************************************************************************************************

## AUDIT Hardening

## *************************************************************************************************************************************************************
-->


  <tr>
    <td rowspan="12">AUDIT Rules Hardening</td>
    <td>Sudoers Actions</td>
    <td>$r_awx_audit_sudoers_action</td>
    <td>$c_awx_audit_sudoers_action</td>
    <td>$s_awx_audit_sudoers_action</td>
  </tr>
  <tr>
    <td>Root Commands 64 Arch</td>
    <td>$r_awx_audit_root_commands_64</td>
    <td>$c_awx_audit_root_commands_64</td>
    <td>$s_awx_audit_root_commands_64</td>
  </tr>
  <tr>
    <td>Root Commands 32 Arch</td>
    <td>$r_awx_audit_root_commands_32</td>
    <td>$c_awx_audit_root_commands_32</td>
    <td>$s_awx_audit_root_commands_32</td>
  </tr>
  <tr>
    <td>Delete All Rules</td>
    <td>$r_awx_audit_delete_all_rules</td>
    <td>$c_awx_audit_delete_all_rules</td>
    <td>$s_awx_audit_delete_all_rules</td>
  </tr>
  <tr>
    <td>Set Buffer Limits</td>
    <td>$r_awx_audit_buffer_size</td>
    <td>$c_awx_audit_buffer_size</td>
    <td>$s_awx_audit_buffer_size</td>
  </tr>
  <tr>
    <td>Login and Logout Sessions</td>
    <td>$r_awx_audit_faillog<br>$r_awx_audit_lastlog</td>
    <td>$c_awx_audit_faillog<br>$c_awx_audit_lastlog</td>
    <td>$s_awx_audit_faillog_lastlog</td>
  </tr>
  <tr>
    <td>Audit Session informations</td>
    <td>$r_awx_audit_utmp<br>$r_awx_audit_btmp<br>$r_awx_audit_wtmp</td>
    <td>$c_awx_audit_utmp<br>$c_awx_audit_btmp<br>$c_awx_audit_wtmp</td>
    <td>$s_awx_audit_utmp_btmp_wtmp</td>
  </tr>
  <tr>
    <td>Unauth Access Files EACCESS</td>
    <td>$r_awx_audit_unauth_access_files_1</td>
    <td>$c_awx_audit_unauth_access_files_1</td>
    <td>$s_awx_audit_unauth_access_files_1</td>
  </tr>
  <tr>
    <td>Unauth Access Files EPERM</td>
    <td>$r_awx_audit_unauth_access_files_2</td>
    <td>$c_awx_audit_unauth_access_files_2</td>
    <td>$s_awx_audit_unauth_access_files_2</td>
  </tr>
  <tr>
    <td>Immutable Audit Config</td>
    <td>$r_awx_audit_immutable</td>
    <td>$c_awx_audit_immutable</td>
    <td>$s_awx_audit_immutable</td>
  </tr>
  <tr>
    <td>Backlog Wait Time</td>
    <td>$r_awx_audit_backlog_wait_time</td>
    <td>$c_awx_audit_backlog_wait_time</td>
    <td>$s_awx_audit_backlog_wait_time</td>
  </tr>
  <tr>
    <td>Audit Failure Mode</td>
    <td>$r_awx_audit_failure_mode</td>
    <td>$c_awx_audit_failure_mode</td>
    <td>$s_awx_audit_failure_mode</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Password & Shadow File Permissions

## *************************************************************************************************************************************************************
-->


  <tr>
    <td rowspan="6">Password & Shadow Files Permissions</td>
    <td>Permission of /etc/passwd</td>
    <td>$r_awx_passwd_perm_all</td>
    <td>$c_awx_passwd_perm_all</td>
    <td>$s_awx_passwd_perm</td>
  </tr>
  <tr>
    <td>Permission of /etc/passwd-</td>
    <td>$r_awx_passwd_hyphen_perm_all</td>
    <td>$c_awx_passwd_hyphen_perm_all</td>
    <td>$s_awx_passwd_hyphen_perm</td>
  </tr>
  <tr>
    <td>Permission of /etc/shadow</td>
    <td>$r_awx_shadow_perm_all</td>
    <td>$c_awx_shadow_perm_all</td>
    <td>$s_awx_shadow_perm</td>
  </tr>
  <tr>
    <td>Permission of /etc/shadow-</td>
    <td>$r_awx_shadow_hyphen_perm_all</td>
    <td>$c_awx_shadow_hyphen_perm_all</td>
    <td>$s_awx_shadow_hyphen_perm</td>
  </tr>
  <tr>
    <td>Permission of /etc/gshadow</td>
    <td>$r_awx_gshadow_perm_all</td>
    <td>$c_awx_gshadow_perm_all</td>
    <td>$s_awx_gshadow_perm</td>
  </tr>
  <tr>
    <td>Permission of /etc/gshadow-</td>
    <td>$r_awx_gshadow_hyphen_perm_all</td>
    <td>$c_awx_gshadow_hyphen_perm_all</td>
    <td>$s_awx_gshadow_hyphen_perm</td>
  </tr>



<!--
## *************************************************************************************************************************************************************

## Verify Unwanted services are Disabled

## *************************************************************************************************************************************************************
-->



  <tr>
    <td rowspan="4">Disable Unwanted Service(s)</td>
    <td>Remove/Disable unwanted Packages</td>
    <td>$r_awx_packages_all</td>
    <td>$c_awx_packages_all</td>
    <td>$s_awx_packages_all</td>
  </tr>
  <tr>
    <td>Disable NFS Server Service</td>
    <td>$r_awx_nfs_server_status</td>
    <td>$c_awx_nfs_server_status</td>
    <td>$s_awx_nfs_server_status</td>
  </tr>
  <tr>
    <td>Disable Firewalld Service</td>
    <td>$r_awx_firewalld_status</td>
    <td>$c_awx_firewalld_status</td>
    <td>$s_awx_firewalld_status</td>
  </tr>
  <tr>
    <td>Disable Selinux</td>
    <td>$r_sestatus</td>
    <td>$c_awx_selinux_status</td>
    <td>$s_awx_selinux_status</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Validate Syslog Configurations

## *************************************************************************************************************************************************************
-->


  <tr>
    <td rowspan="2">Syslog Configuration</td>
    <td>Syslog Logs Configs</td>
    <td><pre>$r_awx_syslog_all</pre></td>
    <td><pre>$c_awx_syslog_all</pre></td>
    <td>$s_awx_syslog_all</td>
  </tr>
  <tr>
    <td>Syslog Logs Forwarding to QRadar</td>
    <td>$r_awx_syslog_qradar</td>
    <td>$c_awx_syslog_qradar</td>
    <td>$s_awx_syslog_qradar</td>
  </tr>
  <tr>


<!--
## *************************************************************************************************************************************************************

## History Timestamp & Size

## *************************************************************************************************************************************************************
-->



  <tr>
    <td>History Timestamp & Size</td>
    <td>Validate History Timestamp & Size in Default Profiles</td>
    <td>$r_awx_history_ts<br/>$r_awx_history_size</td>
    <td>$c_awx_history_ts<br/>$c_awx_history_size</td>
    <td>$s_awx_history_ts_size</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Login Banner with Dynamic Script motd

## *************************************************************************************************************************************************************
-->

  <tr>
    <td>Login Banner</td>
    <td>Configure banner via /usr/local/bin/dynmotd</td>
    <td><pre>$r_awx_banner</pre></td>
    <td><pre>$c_awx_banner</pre></td>
    <td>$s_awx_banner</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Validate Cron & AT Daemons

## *************************************************************************************************************************************************************
-->


  <tr>
    <td>Validate Crons & AT Daemon</td>
    <td>Allow only cron.allow and deny rest cron and at file</td>
    <td>$r_awx_cron_at</td>
    <td>$c_awx_cron_at</td>
    <td>$s_awx_cron_at</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## NTP Configurations

## *************************************************************************************************************************************************************
-->


  <tr>
    <td>NTP/Chrony Configurations</td>
    <td>NTP Clients should be configured to point to NTP Server</td>
    <td>$r_ntp_config</td>
    <td>$c_ntp_config</td>
    <td>$s_ntp_config</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Users With No Empty Passwords

## *************************************************************************************************************************************************************
-->


  <tr>
    <td>Users With No Empty Password</td>
    <td>No Empty Password in /etc/shadow for any users</td>
    <td>$r_awx_empty_user_pwd</td>
    <td>$c_awx_empty_user_pwd</td>
    <td>$s_awx_empty_user_pwd</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Sticky Bit Validation on /tmp & /var/tmp

## *************************************************************************************************************************************************************
-->

  <tr>
    <td>Sticky bit set for world writable directories</td>
    <td>Sticky Bit on /tmp & /var/tmp</td>
    <td>$c_awx_sticky_bit_tmp<br/>$r_awx_sticky_bit_var_tmp</td>
    <td>$c_awx_sticky_bit_tmp<br/>$c_awx_sticky_bit_var_tmp</td>
    <td>$s_awx_stickybit_tmp_vartmp_perm</td>
  </tr>


<!--
## *************************************************************************************************************************************************************

## Active user files must be restricted to root ownership "/var/log/utmpx"

## *************************************************************************************************************************************************************
-->


  <tr>
    <td>Active user files must be restricted to root ownership</td>
    <td>Permission of /var/log/utmpx</td>
    <td>$r_awx_utmpx_perm</td>
    <td>$c_awx_utmpx_perm_all</td>
    <td>$s_awx_utmpx_perm</td>
  </tr>





<!--
######  END OF SCRIPT
-->



</table>
</body>
</html>


" >> $harden
