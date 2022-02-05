#!/bin/bash

# Script: Remote cPmove Backup Split Homedir
# Author: Adit Thaufan <adi@chrootid.com>

# SFTP Remote Backup Setting
# WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination
 
# Destination Name: cpanel remote backup split homedir
# Backup Directory: your_sftp_default_userdir
# Remote Host: your_remote_backup_sftp_server_ip
# Port: your_remote_backup_ssh_port
# Remote Account Username: your_sftp_username
# Authentication Type: Key Authentication
# Private Key: your_ssh_private_key_full_path_file
# Save and Validate Destination
# Enable
clear;
BACKUPDIR=$(date +%F)

# Backup Running Process
function running_process {
    if [[ -n $($SSHRCE "pgrep -f $USERNAME|xargs ps|grep -Ev '(sshd:|pgrep|COMMAND)'") ]];then
        echo "Running Process Check          : Already running. Please wait!"
		exit
    fi
}

# Authentication Type
function authentication_key {
	AUTHTYPE=$(awk '/authtype:/ {print $2}' "$DSTBACKUPCONFIG")
    if [[ $AUTHTYPE == "password" ]];then
        echo "Authentication Type            : Password"
		echo ""
		echo "This script only works for Key Authentication Type"
		exit
    elif [[ $AUTHTYPE == "key" ]];then
		echo "Authentication Type            : SSH Key"
        SSHRCE="ssh -i $SSHKEY -p $RSSHPORT $USERNAME@$RBACKUP"
    fi
}

# Remote Backup Host
function remote_backup_host {
	RBACKUP=$(awk '/host:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -n $RBACKUP ]];then
		echo "Remote Backup Host             : $RBACKUP"
	fi
}

# SFTP Additional Destination Backup Type
function sftp_type {
	TYPE=$(grep -w "type:" "$DSTBACKUPCONFIG"|awk '{print $2}')
    if [[ $TYPE == "SFTP" ]];then
		echo "Backup Type                    : $TYPE"
	else
		echo "Backup Type                    : $TYPE"
		echo ""
        echo "This script only works for SFTP Destination Type"
		exit
    fi
}

# Additional Destination Backup Setting 
function additional_destination_backup {
	DSTBACKUPCONFIG=$(grep -lir "type: SFTP" /var/cpanel/backups/*.backup_destination|head -n1)
    if [[ -f $DSTBACKUPCONFIG ]];then
		echo "Additional Destination Config  : $DSTBACKUPCONFIG"
    else
		echo "Additional Destination Config  : Not Found"
		echo ""
        echo "There is no active additional destinations backup setting in WHM Backup."
        echo "Please enable it from WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination"
        exit
    fi
}

# Path Directory
function path_dir {
	RBACKUPDIR=$(awk '/path:/ {print $2}' "$DSTBACKUPCONFIG"|sed "s/'//g")
	if [[ -z $RBACKUPDIR ]];then
		RBACKUPDIR="~"
		echo "Path Directory                 : $RBACKUPDIR"
	else
		echo "Path Directory                 : $RBACKUPDIR"
	fi
}

# SSH Port
function ssh_port {
	RSSHPORT=$(awk '/port:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -z $RSSHPORT ]];then
		RSSHPORT="22"
		echo "SSH Port                       : $RSSHPORT"
	else
		echo "SSH Port                       : $RSSHPORT"
	fi
}

# SSH Private Key
function ssh_private_key {
	SSHKEY=$(awk '/privatekey:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -f $SSHKEY ]];then
		echo "SSH Private Key                : $SSHKEY"
	else
		echo "SSH Private Key                : not found"
		echo ""
		echo "Check your SSH Private Key file"
		exit
	fi
}

# SFTP Username
function sftp_username {
	USERNAME=$(awk '/username:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -n $USERNAME ]];then
		echo "Username                       : $USERNAME"
	elif [[ -z $USERNAME ]];then
		echo "Username                       : Not found"
		echo ""
		exit
	fi
}

# SSH Connection Test
function ssh_connection_test {
	EXITVALUE=$(ssh -i "$SSHKEY" -q -o BatchMode=yes  -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$RSSHPORT" "$USERNAME"@"$RBACKUP" 'exit 0');
	if [[ $EXITVALUE -eq 0 ]];then
		echo "SSH Connection Test            : Successful"
	elif [[ $EXITVALUE -eq 255 ]];then
		echo "SSH Connection Test            : Connection failed"
		exit
	else
		echo "SSH Connection Test            : Connection failed"
		exit
	fi
}

# Local Backup Config
	function local_backup_config {
	LOCALBACKUP=$(awk '/BACKUPENABLE:/ {print $2}' /var/cpanel/backups/config|sed "s/'//g")
	if [[ $LOCALBACKUP == "yes" ]];then
		echo "Local Backup Status            : Enabled. Should be disabled to prevent disk usage full"
	elif [[ $LOCALBACKUP == "no" ]];then
		echo "Local Backup Status            : Disabled"
	elif [[ $LOCALBACKUP == "no" ]];then
		echo "Local Backup Status            : Unknown"
	fi
}

# Additional Backup Status 
function additional_backup_status {
	DESTINATIONSTATUS=$(awk '/disabled:/ {print $2}' /var/cpanel/backups/*.backup_destination)
	if [[ $DESTINATIONSTATUS -eq 0 ]];then
		echo "Remote Backup Status           : Enabled"
	elif [[ $DESTINATIONSTATUS -eq 1 ]];then
		echo "Remote Backup Status           : Disabled"
		echo ""
		echo "Please enable it from WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination"
		exit
	fi
}

# Create Backup Directory
function create_backup_dir {
    if [[ $($SSHRCE "ls $RBACKUPDIR" 2>/dev/null) != $(date +%F) ]];then
        $SSHRCE "mkdir -p $BACKUPDIR/accounts";
        $SSHRCE "mkdir -p $BACKUPDIR/homedir";
    fi
}

# cPmove Backup Skip Homedir
function cpmove_backup_skip_homedir {
    cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
	if [[ $($SSHRCE "ls $BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" ]];then
		if [[ ! -f /home/cpmove-$CPUSER.tar.gz ]];then
			/scripts/pkgacct --skiphomedir "$CPUSER" >/dev/null 2>&1
			rsync -avHP --remove-source-files /home/cpmove-"$CPUSER".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/accounts >/dev/null 2>&1
        fi
    fi
    done
}

# Backup Homedir
function backup_homedir {
    cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
    HOMEDIR=$(grep "$CPUSER" /etc/passwd|cut -d: -f6)
	if [[ $($SSHRCE "ls $BACKUPDIR/homedir/$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/homedir/$CPUSER.tar.gz" ]];then
	    rsync -avHP "$HOMEDIR" -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/homedir/ >/dev/null 2>&1
		$SSHRCE "tar -czf $BACKUPDIR/homedir/$CPUSER.tar.gz $BACKUPDIR/homedir/$CPUSER --remove-files" >/dev/null 2>&1
    fi
    done
}

# Backup System
function backup_system {
	UPLOADBACKUPSYSTEM=$(awk '/upload_system_backup:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ $UPLOADBACKUPSYSTEM -eq 1 ]];then
		backup_system_dirs
		backup_system_files
	fi
	
}
# Backup System Dirs
function backup_system_dirs {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/dirs"|awk '{print $9}' 2>/dev/null) != "$BACKUPDIR/system/dirs" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/dirs"
	fi
	
    SYSTEM_DIRS=(/etc/cpanel /etc/mail /etc/pki/tls/certs /etc/proftpd /etc/ssl /etc/valiases /etc/vdomainaliases /etc/vfilters /usr/local/cpanel/3rdparty/mailman /var/cpanel /var/lib/mysql/ /var/lib/rpm /var/named /var/spool/cron)
    for DIR in "${!SYSTEM_DIRS[@]}";do
        if [[ -d "${SYSTEM_DIRS[$DIR]}" ]];then
            BACKUPSYSTEMDIR=$(echo "${SYSTEM_DIRS[$DIR]}"|sed "s/\//_/g")
			if [[ $($SSHRCE "ls $BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" 2>/dev/null) != "$BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" ]];then
                tar -czf "$BACKUPSYSTEMDIR".tar.gz "${SYSTEM_DIRS[$DIR]}" 2>/dev/null
				rsync -avHP --remove-source-files "$BACKUPSYSTEMDIR".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/dirs >/dev/null 2>&1
			fi
		fi
    done
}

# Backup System Files
function backup_system_files {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/files"|awk '{print $9}' 2>/dev/null) != "$BACKUPDIR/system/files" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/files"
	fi
	
    SYSTEM_FILES=(/etc/apache2/conf/httpd.conf /etc/cpanel/exim/system/filter /etc/dovecot/sni.conf /etc/exim.conf /etc/exim.conf.localopts /etc/fstab /etc/group /etc/ips /etc/localdomains /etc/mailips /etc/manualmx /etc/my.cnf /etc/named.conf /etc/passwd /etc/pure-ftpd.conf /etc/remotedomains /etc/secondarymx /etc/senderverifybypasshosts /etc/shadow /etc/spammeripblocks /etc/spammers /etc/wwwacct.conf /root/.my.cnf /var/cpanel/greylist/greylist.sqlite /var/cpanel/mysql/remote/profiles/profiles.json)
    for FILE in "${!SYSTEM_FILES[@]}";do
        if [[ -f "${SYSTEM_FILES[$FILE]}" ]];then
            BACKUPSYSTEMFILE=$(echo "${SYSTEM_FILES[$FILE]}"|sed "s/\//_/g")
	    if [[ $($SSHRCE "ls $BACKUPDIR/system/files/$BACKUPSYSTEMFILE.tar.gz" 2>/dev/null) != "$BACKUPDIR/system/files/$BACKUPSYSTEMFILE.tar.gz" ]];then
	        tar -czf "$BACKUPSYSTEMFILE".tar.gz "${SYSTEM_FILES[$FILE]}" 2>/dev/null
	        rsync -avHP --remove-source-files "$BACKUPSYSTEMFILE".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/files >/dev/null 2>&1
	    fi
	fi
    done
}

# Print Intro
function print_intro {
	echo "#########################################################"
	echo "##   cPRBackup - Split Homedir"
	echo "##   2022 - Adit Thaufan <adit@chrootid.com>"
	echo "##   https://github.com/chrootid/cprbackup-split-homedir"
	echo "#########################################################"
	echo "..."
}

print_intro
additional_destination_backup
sftp_type
remote_backup_host
path_dir
ssh_port
ssh_private_key
sftp_username
authentication_key
ssh_connection_test
local_backup_config
additional_backup_status
running_process

create_backup_dir
cpmove_backup_skip_homedir
backup_homedir
backup_system
