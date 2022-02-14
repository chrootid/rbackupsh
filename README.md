# RBackup SH
RBackup SH is a very suitable bash script for servers that do not have enough free space to store backup data in their local disk space.

1. Create Additional Destination Backup
WHM -> Backup -> Backup Configuration -> Additional Destinations -> Destination Type: SFTP -> Create New Destination

Destination Name: your_backup_destination_name
Backup Directory: your_backup_default_dir
Remote Host: your_remote_backup_server_ip_host
Port: your_remote_port
Remote Account Username: your_account_username
Authentication Type: Key Authentication / Password Authentication
Password: your_password_if_password_auth
Private Key: your_ssh_private_key_full_path_file_if_keyauth
Save and Validate Destination
Enable

2. Download the script
```
# wget -qc rbackupsh.chrootid.com -O /usr/bin/rbackupsh
# chmod 700 /usr/bin/rbackupsh
# /usr/bin/rbackupsh 
```
