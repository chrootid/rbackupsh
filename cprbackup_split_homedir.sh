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

function linestip {
	echo "----------------------------------------------------------------"
}

# Backup Running Process
function running_process {
    if [[ -n $($SSHRCE "pgrep -f $USERNAME|xargs ps|grep -Ev '(sshd:|pgrep|COMMAND)'") ]];then
        echo " Running Process Check          : Already running. Please wait!"
		linestip
		exit
    fi
}

# Authentication Type
function authentication_key {
	AUTHTYPE=$(awk '/authtype:/ {print $2}' "$DSTBACKUPCONFIG")
    if [[ $AUTHTYPE == "password" ]];then
        echo " Authentication Type            : Password"
		linestip
		echo " NOTE: This script only works for Key Authentication Type"
		linestip
		exit
    elif [[ $AUTHTYPE == "key" ]];then
		echo " Authentication Type            : SSH Key"
        SSHRCE="ssh -i $SSHKEY -p $RSSHPORT $USERNAME@$RBACKUP"
    fi
}

# Remote Backup Host
function remote_backup_host {
	RBACKUP=$(awk '/host:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -n $RBACKUP ]];then
		echo " Remote Backup Host             : $RBACKUP"
	fi
}

# SFTP Additional Destination Backup Type
function sftp_type {
	TYPE=$(grep -w "type:" "$DSTBACKUPCONFIG"|awk '{print $2}')
    if [[ $TYPE == "SFTP" ]];then
		echo " Backup Type                    : $TYPE"
	else
		echo " Backup Type                    : $TYPE"
		linestip
        echo " NOTE: This script only works for SFTP Destination Type"
		linestip
		exit
    fi
}

# Additional Destination Backup Setting 
function additional_destination_backup {
	DSTBACKUPCONFIG=$(grep -lir "type: SFTP" /var/cpanel/backups/*.backup_destination 2>/dev/null|head -n1)
    if [[ -f $DSTBACKUPCONFIG ]];then
		echo " Additional Destination Config  : $DSTBACKUPCONFIG"
    else
		echo " Additional Destination Config  : Not Found"
		linestip
        echo " NOTE: There is no active additional destinations backup setting "
		echo " in WHM Backup. Please enable it from WHM -> Backup -> Backup "
		echo " Configuration -> Additional Destinations -> Destination Type: "
		echo " SFTP -> Create New Destination"
		linestip
        exit
    fi
}

# Path Directory
function path_dir {
	RBACKUPDIR=$(awk '/path:/ {print $2}' "$DSTBACKUPCONFIG"|sed "s/'//g")
	if [[ -z $RBACKUPDIR ]];then
		RBACKUPDIR="~"
		echo " Path Directory                 : $RBACKUPDIR"
	else
		echo " Path Directory                 : $RBACKUPDIR"
	fi
}

# SSH Port
function ssh_port {
	RSSHPORT=$(awk '/port:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -z $RSSHPORT ]];then
		RSSHPORT="22"
		echo " SSH Port                       : $RSSHPORT"
	else
		echo " SSH Port                       : $RSSHPORT"
	fi
}

# SSH Private Key
function ssh_private_key {
	SSHKEY=$(awk '/privatekey:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -f $SSHKEY ]];then
		echo " SSH Private Key                : $SSHKEY"
	else
		echo " SSH Private Key                : not found"
		linestip
		echo " NOTE: Please check your SSH Private Key file"
		linestip
		exit
	fi
}

# SFTP Username
function sftp_username {
	USERNAME=$(awk '/username:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ -n $USERNAME ]];then
		echo " Username                       : $USERNAME"
	elif [[ -z $USERNAME ]];then
		echo " Username                       : Not found"
		linestip
		echo " NOTE: There is no SSH/FTP/SFTP Account to connect"
		linestip
		exit
	fi
}

# SSH Connection Test
function ssh_connection_test {
	EXITVALUE=$(ssh -i "$SSHKEY" -q -o BatchMode=yes  -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$RSSHPORT" "$USERNAME"@"$RBACKUP" 'exit 0'; echo $?);
	if [[ $EXITVALUE -eq 0 ]];then
		echo " SSH Connection Test            : Successful"
	elif [[ $EXITVALUE -eq 255 ]];then
		echo " SSH Connection Test            : Connection failed"
		linestip
		echo " NOTE: Please check your SSH Connection settings. Username, Port,"
		echo " IP/Host and make sure if SSH Port was accepted from firewall"
		linestip
		exit
	else
		echo " SSH Connection Test            : Connection failed"
		linestip
		echo " NOTE: Please check your SSH Connection settings. Username, Port,"
		echo " IP/Host and make sure if SSH Port was accepted from firewall"
		linestip
		exit
	fi
}

# Local Backup Config
	function local_backup_config {
	LOCALBACKUP=$(awk '/BACKUPENABLE:/ {print $2}' /var/cpanel/backups/config|sed "s/'//g")
	if [[ $LOCALBACKUP == "yes" ]];then
		echo " Local Backup Status            : Enabled. Should be disabled to prevent disk usage full"
	elif [[ $LOCALBACKUP == "no" ]];then
		echo " Local Backup Status            : Disabled"
	elif [[ $LOCALBACKUP == "no" ]];then
		echo " Local Backup Status            : Unknown"
	fi
}

# Additional Backup Status 
function additional_backup_status {
	DESTINATIONSTATUS=$(awk '/disabled:/ {print $2}' $DSTBACKUPCONFIG)
	if [[ $DESTINATIONSTATUS -eq 0 ]];then
		echo " Remote Backup Status           : Enabled"
	elif [[ $DESTINATIONSTATUS -eq 1 ]];then
		echo " Remote Backup Status           : Disabled"
		linestip
		echo " NOTE: Please enable it from WHM -> Backup -> Backup "
		echo " Configuration -> Additional Destinations -> Destination Type: "
		echo " SFTP -> Create New Destination"
		linestip
		exit
	fi
}

# Total cPanel Account
function total_cpanel_account {
	TOTALCPANELACCOUNT=$(cut -d: -f1 /etc/trueuserowners|wc -l)
	if [[ $TOTALCPANELACCOUNT -eq 0 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Account"
		linestip
		echo " NOTE: There is no cPanel Account to be backuped"
		linestip
		exit
	elif [[ $TOTALCPANELACCOUNT -eq 1 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Account"
	elif [[ $TOTALCPANELACCOUNT -ge 2 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Accounts"
	fi
}

# cPmove Backup Status
function cpmove_backup_status {
	
	$SSHRCE "echo > $BACKUPDIR/logs/failed" 2>/dev/null
	TOTALCPANELACCOUNT=$(cut -d: -f1 /etc/trueuserowners|wc -l)
	
	# cPmove Backup Check
	cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
		if [[ $($SSHRCE "ls $BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" ]];then
			$SSHRCE "echo "failed: cpmove-"$CPUSER".tar.gz not found" >> $BACKUPDIR/logs/failed" 2>/dev/null
		fi
	done
	TOTALFAILEDCPMOVE=$($SSHRCE "grep cpmove-*.tar.gz $BACKUPDIR/logs/failed"|wc -l)
	TOTALCPANELCOMPLETEDCPMOVE=$(( TOTALCPANELACCOUNT - TOTALFAILEDCPMOVE ))
	echo " Total cPmove Backup            : $TOTALCPANELCOMPLETEDCPMOVE Complted, $TOTALFAILEDCPMOVE Failed"
	
	# cPuser Homedir Check
	cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
		if [[ $($SSHRCE "ls -ld $BACKUPDIR/homedir/$CPUSER 2>/dev/null"|awk '{print $9}') == "$BACKUPDIR/homedir/$CPUSER" ]];then
			$SSHRCE "echo "failed: "$CPUSER" homedir" >> $BACKUPDIR/logs/failed" 2>/dev/null
		fi
	done
	TOTALFAILEDCPHOME=$($SSHRCE "grep homedir $BACKUPDIR/logs/failed"|wc -l)
	TOTALCPANELCOMPLETEDCPHOME=$(( TOTALCPANELACCOUNT - TOTALFAILEDCPHOME ))
	echo " Total cPhomedir Backup         : $TOTALCPANELCOMPLETEDCPHOME Complted, $TOTALFAILEDCPHOME Failed"
	
	# Total Backup Size
	if [[ $($SSHRCE "ls -ld $BACKUPDIR 2>/dev/null"|awk '{print $9}') == "$BACKUPDIR" ]];then
		TOTALBACKUPSIZE=$($SSHRCE "du -sh $RBACKUPDIR/$BACKUPDIR")
	else
		echo " NOTE: Backup Dir not found"
		linestip
	fi
	echo " Total Backup Size              : $TOTALBACKUPSIZE"
}

# Create Backup Directory
function create_backup_dir {
    if [[ $($SSHRCE "ls $RBACKUPDIR" 2>/dev/null) != "$BACKUPDIR" ]];then
        $SSHRCE "mkdir -p $BACKUPDIR/accounts";
        $SSHRCE "mkdir -p $BACKUPDIR/homedir";
    fi
}

# cPmove Backup Skip Homedir
function cpmove_backup_skip_homedir {
	printf " cPmove Backup                  : Running "
    cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
	if [[ $($SSHRCE "ls $BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" ]];then
		if [[ ! -f /home/cpmove-$CPUSER.tar.gz ]];then
			/scripts/pkgacct --skiphomedir "$CPUSER" >/dev/null 2>&1
			rsync -avHP --remove-source-files /home/cpmove-"$CPUSER".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/accounts >/dev/null 2>&1
		elif [[ -f /home/cpmove-$CPUSER.tar.gz ]];then
			rsync -avHP --remove-source-files /home/cpmove-"$CPUSER".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/accounts >/dev/null 2>&1
        fi
    fi
	echo -e "\\r cPmove Backup                  : ${CHECK_MARK} Done       "
    done
}

# Backup Homedir
function backup_homedir {
	printf " cPhomedir Backup               : Running "
    cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
    HOMEDIR=$(grep "$CPUSER" /etc/passwd|cut -d: -f6)
	if [[ $($SSHRCE "ls $BACKUPDIR/homedir/$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/homedir/$CPUSER.tar.gz" ]];then
	    rsync -avHP "$HOMEDIR" -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/homedir/ >/dev/null 2>&1
		$SSHRCE "tar -czf $BACKUPDIR/homedir/$CPUSER.tar.gz $BACKUPDIR/homedir/$CPUSER --remove-files" >/dev/null 2>&1
    fi
    done
	echo -e "\\r cPhomedir Backup               : ${CHECK_MARK} Done       "
}

# Backup System
function backup_system {
	UPLOADBACKUPSYSTEM=$(awk '/upload_system_backup:/ {print $2}' "$DSTBACKUPCONFIG")
	if [[ $UPLOADBACKUPSYSTEM -eq 1 ]];then
	printf " cPsystem Backup                : Running "
		backup_system_dirs
		backup_system_files
	echo -e " \\r cPsystem Backup                : ${CHECK_MARK} Done       "
	fi
	
}

# Backup System Dirs
function backup_system_dirs {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/dirs 2>/dev/null"|awk '{print $9}') != "$BACKUPDIR/system/dirs" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/dirs"
	fi
	
    SYSTEM_DIRS=(/etc/cpanel /etc/mail /etc/pki/tls/certs /etc/proftpd /etc/ssl /etc/valiases /etc/vdomainaliases /etc/vfilters /usr/local/cpanel/3rdparty/mailman /var/cpanel /var/lib/mysql/ /var/lib/rpm /var/named /var/spool/cron)
    for DIR in "${!SYSTEM_DIRS[@]}";do
        if [[ -d "${SYSTEM_DIRS[$DIR]}" ]];then
            BACKUPSYSTEMDIR=$(echo "${SYSTEM_DIRS[$DIR]}"|sed "s/\//_/g")
			if [[ $($SSHRCE "ls $BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" 2>/dev/null) != "$BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" ]];then
                tar -czf "$BACKUPSYSTEMDIR".tar.gz "${SYSTEM_DIRS[$DIR]}" >/dev/null 2>&1
				rsync -avHP --remove-source-files "$BACKUPSYSTEMDIR".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/dirs >/dev/null 2>&1
			fi
		fi
    done
}

# Backup System Files
function backup_system_files {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/files 2>/dev/null"|awk '{print $9}') != "$BACKUPDIR/system/files" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/files"
	fi
	
    SYSTEM_FILES=(/etc/apache2/conf/httpd.conf /etc/cpanel/exim/system/filter /etc/dovecot/sni.conf /etc/exim.conf /etc/exim.conf.localopts /etc/fstab /etc/group /etc/ips /etc/localdomains /etc/mailips /etc/manualmx /etc/my.cnf /etc/named.conf /etc/passwd /etc/pure-ftpd.conf /etc/remotedomains /etc/secondarymx /etc/senderverifybypasshosts /etc/shadow /etc/spammeripblocks /etc/spammers /etc/wwwacct.conf /root/.my.cnf /var/cpanel/greylist/greylist.sqlite /var/cpanel/mysql/remote/profiles/profiles.json)
    for FILE in "${!SYSTEM_FILES[@]}";do
        if [[ -f "${SYSTEM_FILES[$FILE]}" ]];then
            BACKUPSYSTEMFILE=$(echo "${SYSTEM_FILES[$FILE]}"|sed "s/\//_/g")
	    if [[ $($SSHRCE "ls $BACKUPDIR/system/files/$BACKUPSYSTEMFILE.tar.gz" 2>/dev/null) != "$BACKUPDIR/system/files/$BACKUPSYSTEMFILE.tar.gz" ]];then
			gzip -c "${SYSTEM_FILES[$FILE]}" > "$BACKUPSYSTEMFILE".gz >/dev/null 2>&1
	        rsync -avHP --remove-source-files "$BACKUPSYSTEMFILE".gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/files >/dev/null 2>&1
	    fi
	fi
    done
}

# Print Intro
function print_intro {
	linestip
	echo "   Script  : cPRBackup - Split Homedir"
	echo "   By      : Adit Thaufan <adit@chrootid.com>"
	echo "   Docs    : https://github.com/chrootid/cprbackup-split-homedir"
	echo "   Usage   : wget -qO- cprbackupsh.chrootid.com|bash"
	linestip
}

# cPRBackup Logs
function cprbackup_logs {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/logs 2>/dev/null"|awk '{print $9}') != "$BACKUPDIR/logs" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/logs"
	fi
}

# Processing Time
# day convertion
function secondtoday {
        DAYSEC=86400
        if [[ $TIME -ge $DAYSEC ]];then
                DAY=$(( TIME / DAYSEC ))
                TIME=$(( TIME % DAYSEC ))
                if [[ $DAY -eq 1 ]];then
                        printf "%s Day " "$DAY"
                elif [[ $DAY -gt 1 ]];then
                        printf "%s Days " "$DAY"
                fi
        fi
}

# Hours convertion
function secondtohour {
        HOURSEC=3600
        if [[ $TIME -ge $HOURSEC ]];then
                HOUR=$(( TIME / HOURSEC ))
                TIME=$(( TIME % HOURSEC ))
                if [[ $HOUR -eq 1 ]];then
                        printf "%s Hour " "$HOUR"
                elif [[ $HOUR -gt 1 ]];then
                        printf "%s Hours " "$HOUR"
                fi
        fi
}

# Minute convertion
function secondtominute {
        MINUTESEC=60
        if [[ $TIME -ge $MINUTESEC ]];then
                MINUTE=$(( TIME / MINUTESEC ))
                TIME=$(( TIME % MINUTESEC ))
                if [[ $TIME -eq 0 ]];then
                        if [[ $MINUTE -eq 1 ]];then
                                printf "%s Minute " "$MINUTE"
                        elif [[ $MINUTE -gt 1 ]];then
                                printf "%s Minutes " "$MINUTE"
                        fi
                elif [[ $TIME -eq 1 ]];then
                        if [[ $MINUTE -eq 1 ]];then
                                printf "%s Minute %s Second" "$MINUTE" "$TIME"
                        elif [[ $MINUTE -gt 1 ]];then
                                printf "%s Minutes %s Second" "$MINUTE" "$TIME"
                        fi
                elif [[ $TIME -gt 1 ]] && [[ $TIME -le 59 ]];then
                        if [[ $MINUTE -eq 1 ]];then
                                printf "%s Minute %s Seconds" "$MINUTE" "$TIME"
                        elif [[ $MINUTE -gt 1 ]];then
                                printf "%s Minutes %s Seconnds" "$MINUTE" "$TIME"
                        fi
                fi
        elif [[ $TIME -eq 1 ]];then
                printf "%s Second" "$TIME"
        elif [[ $TIME -gt 1 ]] && [[ $TIME -lt $MINUTESEC ]];then
                printf "%s Seconds" "$TIME"
        fi
}

# Processing Time in Seconds Convertion
function secondtoconvert {
        secondtoday
        secondtohour
        secondtominute
}

function time_process () {
    	END_TIME=$(date +%s)
    	TIME=$(( END_TIME - START_TIME ))
    	echo " Total Process Time             : $(secondtoconvert)"
	DATE_TIME=$(date +%Y-%m-%d" "%H:%M:%S)
	echo " Date Time                      : $DATE_TIME"
}

clear;
BACKUPDIR=$(date +%F)
START_TIME=$(date +%s)
CHECK_MARK="\033[0;32m\xE2\x9C\x94\033[0m"

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
linestip
local_backup_config
additional_backup_status
total_cpanel_account
running_process

create_backup_dir
cprbackup_logs
cpmove_backup_skip_homedir
backup_homedir
backup_system

cpmove_backup_status
linestip
time_process
linestip
