# IP-Block
Fetches a list from spamhaus daily and blocks all offending IP's

### Install ipset for efficient IP blocking

`sudo apt-get install ipset`

### Create a cron job to update blocklists

`sudo nano /etc/cron.daily/update-blocklists`

Add: `ip-block.sh` contents

`sudo chmod +x /etc/cron.daily/update-blocklists`

### Create log file with proper permissions

`sudo touch /var/log/blocklist-update.log`

`sudo chmod 644 /var/log/blocklist-update.log`

### Test it manually first

`sudo /etc/cron.daily/update-blocklists`

### Check the log

`sudo tail -f /var/log/blocklist-update.log`
