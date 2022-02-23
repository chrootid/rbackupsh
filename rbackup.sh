#!/bin/bash

# Script: Remote cPmove Backup Split Homedir
# Author: Adit Thaufan <adi@chrootid.com>

# SFTP Remote Backup Setting
# WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination

# Destination Name: cpanel remote backup split homedir
# Backup Directory: your_sftp_default_userdir
# Remote Host: your_remote_backup_sftp_server_ip
# Port: your_remote_backup_ssh_port
# Remote Account Username: your_cpwhm_username
# Authentication Type: Key Authentication
# Private Key: your_ssh_private_key_full_path_file
# Save and Validate Destination
# Enable

function linerstrip {
	echo "-----------------------------------------------------------------------"
}

# Backup Running Process
function running_process {
    if [[ -n $($SSHRCE "pgrep -f $USERNAME|xargs ps|grep -Ev '(sshd:|pgrep|COMMAND)'") ]];then
        echo " Running Process Check          : Already running. Please wait!"
		linerstrip
		exit
    fi
}

# Authentication Type
function cpwhm_authtype {
	AUTHTYPE=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "authtype:"|awk '{print $2}')
	if [[ $AUTHTYPE == "password" ]];then
        	echo " Authentication Type            : Password Authentication"
		ssh_password
		SSHRCE="$SSHPASS -p $SSHPASSWORD ssh -p $RSSHPORT $USERNAME@$RBACKUP"
	elif [[ $AUTHTYPE == "key" ]];then
		echo " Authentication Type            : Key Authentication"
		ssh_private_key
		SSHRCE="ssh -i $SSHKEY -p $RSSHPORT $USERNAME@$RBACKUP"
	fi
}

# Remote Host
function cpwhm_host {
	RBACKUP=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "host:"|awk '{print $2}')
	if [[ -n $RBACKUP ]];then
		echo " Remote Host                    : $RBACKUP"
	fi
}

# SFTP Additional Destination Backup Type
function cpwhm_type {
	TYPE=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "type:"|awk '{print $2}')
	if [[ $TYPE == "SFTP" ]];then
		echo " Backup Type                    : $TYPE"
	else
		echo " Backup Type                    : $TYPE"
		linerstrip
		echo " NOTE: This script only works for SFTP Destination Type"
		linerstrip
		exit
	fi
}

# Backup Directory
function cpwhm_path {
	RBACKUPDIR=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "path:"|awk '{print $2}'|sed "s/'//g")
	if [[ -z $RBACKUPDIR ]];then
		RBACKUPDIR="~"
		echo " Backup Directory               : $RBACKUPDIR"
	else
		echo " Backup Directory               : $RBACKUPDIR"
	fi
}

# Port
function cpwhm_port {
	RSSHPORT=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "port:"|awk '{print $2}')
	if [[ -z $RSSHPORT ]];then
		RSSHPORT="22"
		echo " Port                           : $RSSHPORT"
	else
		echo " Port                           : $RSSHPORT"
	fi
}

# SSH Password
function ssh_password {
	SSHPASSWORD=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "password:"|awk '{print $2}')
	SSHPASS=$(which sshpass 2>/dev/null)
	if [[ -n $SSHPASSWORD ]];then
		if [[ -f $SSHPASS ]];then
			SSHPASS=$(which sshpass)
		else
			yum install -y sshpass >/dev/null 2>&1
			SSHPASS=$(which sshpass)
		fi
		echo " Password                       : $SSHPASSWORD"
	elif [[ -z $SSHPASSWORD ]];then
		echo " Password                       : Not Found"
		linerstrip
		echo " NOTE: Please check your Remote Account Username Password"
		linerstrip
	fi
}

# SSH Private Key
function ssh_private_key {
	SSHKEY=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "privatekey:"|awk '{print $2}')
	if [[ -f $SSHKEY ]];then
		echo " Private Key                    : $SSHKEY"
	else
		echo " Private Key                    : not found"
		linerstrip
		echo " NOTE: Please check your Private Key file"
		linerstrip
		exit
	fi
}

# SFTP Username
function cpwhm_username {
	USERNAME=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "username:"|awk '{print $2}')
	if [[ -n $USERNAME ]];then
		echo " Remote Account Username        : $USERNAME"
	elif [[ -z $USERNAME ]];then
		echo " Remote Account Username        : Not found"
		linerstrip
		echo " NOTE: There is no SSH/FTP/SFTP Account username to connect"
		linerstrip
		exit
	fi
}

# Validate Destination
function cpwhm_validate {
	VALIDATESTATUS=$(whmapi1 backup_destination_validate id="$DSTBACKUPID" disableonfail=0|grep -w reason:""|awk '{print $2}')
	if [[ $VALIDATESTATUS == "OK" ]];then
		echo " Validate Destination           : Succeeded"
	else
		echo " Validate Destination           : Failed"
		linerstrip
		echo " NOTE: Please recheck your Additional Backup Setting"
		linerstrip
	fi
}

# SSH Connection Test
function cpwhm_connection_test {
	if [[ $AUTHTYPE == "password" ]];then
		EXITVALUE=$($SSHPASS -p "$SSHPASSWORD" ssh -p "$RSSHPORT" "$USERNAME"@"$RBACKUP" 'exit 0';echo $?)
	elif [[ $AUTHTYPE == "key" ]];then
		EXITVALUE=$(ssh -i "$SSHKEY" -q -o BatchMode=yes  -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$RSSHPORT" "$USERNAME"@"$RBACKUP" 'exit 0'; echo $?);
	fi

	if [[ $EXITVALUE -eq 0 ]];then
		echo " SSH Connection Test            : Successful"
	else
		echo " SSH Connection Test            : Connection failed"
		linerstrip
		echo " NOTE: Please check your SSH Connection settings. SSH Private Key or SSH Password,"
		echo " SFTP Username, SSH Port, Remote Backup SFTP Server IP/Host."
		echo " Make sure your SSH Server IP and Port were accepted by firewall."
		linerstrip
		exit
	fi
}

# Local Backup Config
	function cpwhm_local_backup_config {
	LOCALBACKUP=$(awk '/^BACKUPENABLE:/ {print $2}' /var/cpanel/backups/config|sed "s/'//g")
	if [[ $LOCALBACKUP == "yes" ]];then
		echo " Local Backup Status            : Enabled. NOTE: It should be disabled to prevent local disk usage full"
	elif [[ $LOCALBACKUP == "no" ]];then
		echo " Local Backup Status            : Disabled"
	fi
}

# Additional Backup Status 
function cpwhm_disabled {
	DESTINATIONSTATUS=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "disabled:"|awk '{print $2}')
	if [[ $DESTINATIONSTATUS -eq 0 ]];then
		echo " Remote Backup Status           : Enabled"
	elif [[ $DESTINATIONSTATUS -eq 1 ]];then
		echo " Remote Backup Status           : Disabled"
		linerstrip
		echo " NOTE: Please enable it from WHM -> Backup -> Backup "
		echo " Configuration -> Additional Destinations -> Destination Type: "
		echo " SFTP -> Create New Destination"
		linerstrip
		exit
	fi
}

# Total cPanel Account
function cpwhm_total_cpaccount {
	TOTALCPANELACCOUNT=$(cut -d: -f1 /etc/trueuserowners|wc -l)
	if [[ $TOTALCPANELACCOUNT -eq 0 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Account"
		linerstrip
		echo " NOTE: There is no cPanel Account to be backuped"
		linerstrip
		exit
	elif [[ $TOTALCPANELACCOUNT -eq 1 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Account"
	elif [[ $TOTALCPANELACCOUNT -ge 2 ]];then
		echo " Total cPanel Account           : $TOTALCPANELACCOUNT Accounts"
	fi
}

# cPmove Backup Status
function cpwhm_backup_status {
	$SSHRCE "echo > $BACKUPDIR/logs/failed" 2>/dev/null
	# cPmove Backup Check
	cut -d: -f1 /etc/trueuserowners|sort|while read -r CPUSER;do
		if [[ $($SSHRCE "ls $BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/accounts/cpmove-$CPUSER.tar.gz" ]];then
			$SSHRCE "echo "failed: cpmove-"$CPUSER".tar.gz not found" >> $BACKUPDIR/logs/failed" 2>/dev/null
		fi
	done
	TOTALFAILEDCPMOVE=$($SSHRCE "grep cpmove-*.tar.gz $BACKUPDIR/logs/failed"|wc -l)
	TOTALCPANELCOMPLETEDCPMOVE=$(( TOTALCPANELACCOUNT - TOTALFAILEDCPMOVE ))
	echo " Total cPmove Backup            : $TOTALCPANELCOMPLETEDCPMOVE Complted, $TOTALFAILEDCPMOVE Failed"

	# cPhomedir Backup Check
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
		TOTALBACKUPSIZE=$($SSHRCE "du -sh $RBACKUPDIR/$BACKUPDIR" 2>/dev/null)
	else
		echo " NOTE: Backup Dir not found"
		linerstrip
	fi
	echo " Total Backup Size              : $TOTALBACKUPSIZE"
}

# Create Backup Directory
function cpwhm_create_backup_dir {
	if [[ $($SSHRCE "ls $RBACKUPDIR" 2>/dev/null) != "$BACKUPDIR" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/accounts";
		$SSHRCE "mkdir -p $BACKUPDIR/homedir";
		$SSHRCE "mkdir -p $BACKUPDIR/logs";
	fi
}

# cPmove Backup Skip Homedir
function sshrsync_cpmovebackup {
	if [[ $AUTHTYPE == "key" ]];then
		rsync -avHP --remove-source-files /home/cpmove-"$CPUSERBACKUP".tar.gz -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/accounts >/dev/null 2>&1
	elif [[ $AUTHTYPE == "password" ]];then
		rsync -avHP --remove-source-files /home/cpmove-"$CPUSERBACKUP".tar.gz --rsh="sshpass -p $SSHPASSWORD ssh -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/accounts >/dev/null 2>&1
	fi
}

function do_cpmovebackup {
	printf " cPmove Backup                  : Running "
	for CPUSERBACKUP in $(whmapi1 --output=jsonpretty list_users|jq ".data.users[]"|grep -Ev "(root)"|sort|sed 's/"//g');do
		printf "\r cPmove Backup                  : Running %s" "$CPUSERBACKUP"
		printf " %0.s" {0..50}
		printf "\r cPmove Backup                  : Running %s" "$CPUSERBACKUP"
		if [[ $($SSHRCE "ls $BACKUPDIR/accounts/cpmove-$CPUSERBACKUP.tar.gz" 2>/dev/null) != "$BACKUPDIR/accounts/cpmove-$CPUSERBACKUP.tar.gz" ]];then
			if [[ ! -f /home/cpmove-$CPUSERBACKUP.tar.gz ]];then
				/scripts/pkgacct --skiphomedir "$CPUSERBACKUP" >/dev/null 2>&1
				sshrsync_cpmovebackup
			elif [[ -f /home/cpmove-$CPUSERBACKUP.tar.gz ]];then
				sshrsync_cpmovebackup
			fi
		fi
	done
	echo -ne "\r cPmove Backup                  : ${CHECK_MARK} Done"
	printf " %0.s" {0..50}
	printf "\n"
}

# Backup Homedir
function sshrsync_cphomedirbackup {
	if [[ $AUTHTYPE == "password" ]];then
		rsync -avHP "$HOMEDIR" --rsh="sshpass -p $SSHPASSWORD ssh -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/homedir/ >/dev/null 2>&1
	elif [[ $AUTHTYPE == "key" ]];then
		rsync -avHP "$HOMEDIR" -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":"$RBACKUPDIR"/"$BACKUPDIR"/homedir/ >/dev/null 2>&1
	fi
}

function do_cphomedirbackup {
	printf " cPhomedir Backup               : Running "
	for CPUSER in $(whmapi1 --output=jsonpretty list_users|jq ".data.users[]"|grep -Ev "(root)"|sort|sed 's/"//g');do
		printf "\r cPhomedir Backup               : Running %s" "$CPUSER"
		printf " %0.s" {0..50}
		printf "\r cPhomedir Backup               : Running %s" "$CPUSER"
		HOMEDIR=$(grep "$CPUSER" /etc/passwd|cut -d: -f6)
		if [[ $($SSHRCE "ls $BACKUPDIR/homedir/$CPUSER.tar.gz" 2>/dev/null) != "$BACKUPDIR/homedir/$CPUSER.tar.gz" ]];then
			sshrsync_cphomedirbackup
			$SSHRCE "tar -czf $BACKUPDIR/homedir/$CPUSER.tar.gz -C $BACKUPDIR/homedir/ $CPUSER --remove-files" >/dev/null 2>&1
		fi
	done
	echo -ne "\r cPhomedir Backup               : ${CHECK_MARK} Done"
	printf " %0.s" {0..50}
	printf "\n"
}

# Backup System
function do_cpsystembackup {
	UPLOADBACKUPSYSTEM=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "upload_system_backup:"|awk '{print $2}')
	if [[ $UPLOADBACKUPSYSTEM -eq 1 ]];then
		printf " cPsystem Backup                : Running "
		backup_system_dirs
		backup_system_files
		echo -ne " \r cPsystem Backup                : ${CHECK_MARK} Done"
		printf " %0.s" {0..50}
		printf "\n"
	fi

}

# Backup System Dirs
function sshrsync_cpsystembackupdirs {
        if [[ $AUTHTYPE == "password" ]];then
		rsync -avHP "${SYSTEM_DIRS[$DIR]}" --rsh="sshpass -p $SSHPASSWORD ssh -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/dirs"$DIRNAME" >/dev/null 2>&1
        elif [[ $AUTHTYPE == "key" ]];then
		rsync -avHP "${SYSTEM_DIRS[$DIR]}" -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/dirs"$DIRNAME" >/dev/null 2>&1
        fi
}

function backup_system_dirs {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/dirs 2>/dev/null"|awk '{print $9}') != "$BACKUPDIR/system/dirs" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/dirs"
	fi

	SYSTEM_DIRS=(/etc/cpanel /etc/mail /etc/pki/tls/certs /etc/proftpd /etc/ssl /etc/valiases /etc/vdomainaliases /etc/vfilters /usr/local/cpanel/3rdparty/mailman /var/cpanel /var/lib/mysql /var/lib/rpm /var/named /var/spool/cron)

	for DIR in "${!SYSTEM_DIRS[@]}";do
		printf "\r cPsystem Backup                : Running %s" "${SYSTEM_DIRS[$DIR]}"
		printf " %0.s" {0..50}
		printf "\r cPsystem Backup                : Running %s" "${SYSTEM_DIRS[$DIR]}"
		if [[ -d "${SYSTEM_DIRS[$DIR]}" ]];then
			BACKUPSYSTEMDIR=$(echo "${SYSTEM_DIRS[$DIR]}"|sed "s/\//_/g")
			DIRNAME=$(dirname "${SYSTEM_DIRS[$DIR]}")
			BASEDIR=$(echo "${SYSTEM_DIRS[$DIR]}"|awk -F'/' '{print $2}')
			if [[ $($SSHRCE "ls $BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" 2>/dev/null) != "$BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz" ]];then
				$SSHRCE "mkdir -p $BACKUPDIR/system/dirs$DIRNAME"
				sshrsync_cpsystembackupdirs
				$SSHRCE "tar -czf $BACKUPDIR/system/dirs/$BACKUPSYSTEMDIR.tar.gz -C $BACKUPDIR/system/dirs $BASEDIR --remove-files" >/dev/null 2>&1
			fi
		fi
	done
}

# Backup System Files
function sshrsync_cpsystembackupfiles {
        if [[ $AUTHTYPE == "password" ]];then
		rsync -avHP "${SYSTEM_FILES[$FILE]}" --rsh="sshpass -p $SSHPASSWORD ssh -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/files >/dev/null 2>&1
        elif [[ $AUTHTYPE == "key" ]];then
		rsync -avHP "${SYSTEM_FILES[$FILE]}" -e "ssh -i $SSHKEY -p $RSSHPORT" "$USERNAME"@"$RBACKUP":$RBACKUPDIR/"$BACKUPDIR"/system/files >/dev/null 2>&1
        fi
}

function backup_system_files {
	if [[ $($SSHRCE "ls -ld $BACKUPDIR/system/files 2>/dev/null"|awk '{print $9}') != "$BACKUPDIR/system/files" ]];then
		$SSHRCE "mkdir -p $BACKUPDIR/system/files"
	fi

	SYSTEM_FILES=(/etc/apache2/conf/httpd.conf /etc/cpanel/exim/system/filter /etc/dovecot/sni.conf /etc/exim.conf /etc/exim.conf.localopts /etc/fstab /etc/group /etc/ips /etc/localdomains /etc/mailips /etc/manualmx /etc/my.cnf /etc/named.conf /etc/passwd /etc/pure-ftpd.conf /etc/remotedomains /etc/secondarymx /etc/senderverifybypasshosts /etc/shadow /etc/spammeripblocks /etc/spammers /etc/wwwacct.conf /root/.my.cnf /var/cpanel/greylist/greylist.sqlite /var/cpanel/mysql/remote/profiles/profiles.json)

	for FILE in "${!SYSTEM_FILES[@]}";do
		printf "\r cPsystem Backup                : Running %s" "${SYSTEM_FILES[$FILE]}"
                printf " %0.s" {0..50}
                printf "\r cPsystem Backup                : Running %s" "${SYSTEM_FILES[$FILE]}"
		if [[ -f "${SYSTEM_FILES[$FILE]}" ]];then
			BACKUPSYSTEMFILE=$(echo "${SYSTEM_FILES[$FILE]}"|sed "s/\//_/g")
			BASEFILE=$(echo "${SYSTEM_FILES[$FILE]}"|awk -F'/' '{print $NF}')
			if [[ $($SSHRCE "ls $BACKUPDIR/system/files/$BACKUPSYSTEMFILE.gz" 2>/dev/null) != "$BACKUPDIR/system/files/$BACKUPSYSTEMFILE.gz" ]];then
				sshrsync_cpsystembackupfiles
				$SSHRCE "mv $BACKUPDIR/system/files/$BASEFILE $BACKUPDIR/system/files/$BACKUPSYSTEMFILE"
				$SSHRCE "gzip -9 $BACKUPDIR/system/files/$BACKUPSYSTEMFILE" >/dev/null 2>&1
			fi
		fi
	done
}

# Print Intro
function print_intro {
	linerstrip
	echo "   Script   : RBackup - Split Homedir"
	echo "   By       : Adit Thaufan <adit@chrootid.com>"
	echo "   Docs     : https://github.com/chrootid/rbackupsh"
	echo "   Download : wget -qc rbackupsh.chrootid.com -O /usr/bin/rbackupsh"
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

# WHM Additional Destination Backup Setting 
function cpanelwhm_rbackupsh {
	whmapi1 backup_destination_list|grep -w "id:"|awk '{print $2}'|while read -r DSTBACKUPID;do
		TYPE=$(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "type:"|awk '{print $2}')
		if [[ $TYPE == SFTP ]];then
			linerstrip
			echo " Destination Name               : $(whmapi1 backup_destination_get id="$DSTBACKUPID"|grep -w "name:"|awk '{print $2}')"
			cpwhm_type
			cpwhm_host
			cpwhm_path
			cpwhm_port
			cpwhm_username
			cpwhm_authtype
			cpwhm_validate
			cpwhm_connection_test
			running_process
			linerstrip
			
			cpwhm_local_backup_config
			cpwhm_disabled
			cpwhm_total_cpaccount
			
			cpwhm_create_backup_dir
			do_cpmovebackup
			do_cphomedirbackup
			do_cpsystembackup
			
			cpwhm_backup_status
			linerstrip
			time_process
			linerstrip
			printf "\n"
		else
			linerstrip
			echo " NOTE: There is no active additional destinations backup setting "
			echo " in WHM Backup. Please enable it from WHM -> Backup -> Backup "
			echo " Configuration -> Additional Destinations -> Destination Type: "
			echo " SFTP -> Create New Destination"
			linerstrip
			exit
		fi
	done
}

clear;
BACKUPDIR=$(date +%F)
START_TIME=$(date +%s)
CHECK_MARK="\033[0;32m\xE2\x9C\x94\033[0m"

print_intro
cpanelwhm_rbackupsh
