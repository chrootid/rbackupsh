# RBackup SH
RBackup SH is a very suitable bash script for servers that do not have enough free space to store backup data in their local disk space.

1. Create cPanel/WHM Additional Destination Backup
<br />WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination

Destination Name: your_backup_destination_name <br />
Backup Directory: your_backup_default_dir <br />
Remote Host: your_remote_backup_server_ip_host <br />
Port: your_remote_port <br />
Remote Account Username: your_account_username <br />
Authentication Type: Key Authentication / Password Authentication <br />
Password: your_password_if_password_auth <br />
Private Key: your_ssh_private_key_full_path_file_if_keyauth <br />
Save and Validate Destination <br />
Enable it <br />

For Example: <br /> 
 Destination Name               : server_remote_backup_01 <br />
 Backup Type                    : SFTP <br /> 
 Remote Host                    : rbackup.chrootid.com <br /> 
 Backup Directory               : leave blank or relative path <br /> 
 Port                           : 6789 <br /> 
 Remote Account Username        : vm1 <br /> 
 Authentication Type            : Key Authentication <br /> 
 Private Key                    : /root/.ssh/vm1_to_rbackup_id_rsa <br /> 
 
2. Download the script
```
# wget -qc rbackupsh.chrootid.com -O /usr/bin/rbackupsh
# chmod 700 /usr/bin/rbackupsh
```

3. Run
```
# /usr/bin/rbackupsh 
```

4. Command Output
```
-----------------------------------------------------------------------
   Script   : RBackup - Split Homedir
   By       : Adit Thaufan <adit@chrootid.com>
   Docs     : https://github.com/chrootid/rbackupsh
   Download : wget -qc rbackupsh.chrootid.com -O /usr/bin/rbackupsh
-----------------------------------------------------------------------
 Additional Destination Config  : /var/cpanel/backups/toremote_sshkey_UID_M4oKjW5jo2plRVDg753R9fR1.backup_destination
 Destination Name               : server_remote_backup_01
 Backup Type                    : SFTP
 Remote Host                    : rbackup.chrootid.com
 Backup Directory               : ~
 Port                           : 6789
 Remote Account Username        : vm1
 Authentication Type            : Key Authentication
 Private Key                    : /root/.ssh/vm1_to_rbackup_id_rsa
 SSH Connection Test            : Successful
-----------------------------------------------------------------------
 Local Backup Status            : Disabled
 Remote Backup Status           : Enabled
 Total cPanel Account           : 1 Account
 cPmove Backup                  : ✔ Done
 cPhomedir Backup               : ✔ Done
 cPsystem Backup                : ✔ Done
 Total cPmove Backup            : 1 Complted, 0 Failed
 Total cPhomedir Backup         : 1 Complted, 0 Failed
 Total Backup Size              : 457M  /remotebackup/vm1/2022-02-15
-----------------------------------------------------------------------
 Total Process Time             : 27 Seconds
 Date Time                      : 2022-02-15 04:47:35
----------------------------------------------------------------------- 
```
