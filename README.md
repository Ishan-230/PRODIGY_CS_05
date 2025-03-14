#!/bin/bash


#variables
local_dir=~/Backup
remote_user=ubuntu
remote_host=13.233.251.205
remote_dir=~/backup
ssh_key=~/.ssh/backup-key.pem

#rsync command to sync files
rsync -avz -e "ssh -i $ssh_key" "$local_dir/" "$remote_user@$remote_host:$remote_dir/"

#Log the backup time
echo "Backup completed at $(date)" >> ~/backup.log
