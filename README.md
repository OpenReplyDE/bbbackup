# bbbackup
Bitbucket automatic backup solution providing Cloud-to-Local and Cloud-to-Cloud repository cloning written in Python

## Operation

Please install this script on a UNIX machine which is capable of executing scripts in an automated way. Have a closer look at the `bbbackup.sh` which is prepared to be called by a cronjob or a macOS LaunchDaemon.

Following files need to be deployed to a target machine for installation:

* `bbbackup.py`
* `requirements.txt`
* `bbbackup.sh` (optional for automation)
* `de.openreply.bbbackup.plist` (optional for automation on macOS)
* `bbbackup_sample.cfg` (optional to see how you could configure the app manually)

All other files are not really needed to run the software.

## Screenshot

![Screenshots of the app](/bbbackup_screenshot.png "Screenshot")

## Features

The script supports following features:

* Configure userid/teamname (password optional!) for accessing BitBucket repositories
* Configure slack so the solution can message/report via slack channel
* Execute full backup of all repositories belonging to a team or user
* Notify about success/warnings/failure via slack
* Execute post-backup analysis of existing backups (specific days & all backups available)
* Automatically rotate backups in a certain timespan, e.g. 14 days
* Monitor the free space remaning on the volume and configure limits for space usage
* Configure retry-limit for retrys of failed cloning of repos
* Configure error/fail-limit-threshold when to report the whole @channel in slack

## Requirements

The script needs a certain environment of python modules to execute its tasks. For details see `requirements.txt` to install needed python libraries using `pip install -r requirements.txt` on the commandline.

* Python 3 (use a *virtual environment* with `python3 -m venv <myfolder>`)
* **slackclient (v2.0.0)** — used to support messaging via Slack
* **GitPython (v2.1.11)** — used to support repo cloing via git
* **keyring (v19.0.1)** — used to store credentials and API keys/secrets on local OS's
* **rauth (v0.7.3)** — used to support OAuth2 requests against BitBucket API
* **configparser (v3.7.4)** — used to enable usage of config-file


## Installation

### Docker ###

See `README_DOCKER.md` for detailed instructions on how to prepare a docker image to run the backups from within a container and store backups to a folder on the host (outside of the container). You should install the the script at first on a local machine to see if everything works and export a `bbbackup.cfg` config file. Then follow instructions to dockerize!

### macOS ###

create a folder where to install the backup scripts like e.g. `/Users/$MyUsername/Backup/` (replace `$MyUserName` with your user which will be running the machine)  
`mkdir -p /Users/$MyUserName/Backup/`

change into the new directory   
`cd /Users/$MyUserName/Backup/`

#### Python 3 ####

check if you have Python 3 installed  
`python3 --version`

if no Python 3 is available on the machine, please install it using brew  
`brew update`  
`brew install python3`

create a virtual environment with Python 3  
`python3 -m venv BitBucketBackup`  

change into the created environment folder  
`cd BitBucketBackup`

copy following files into the current folder:  

* `requirements.txt`
* `bbbackup.py`
* `bbbackup.sh`
* `de.openreply.bbbackup.plist`

activate virtual environment  
`source bin/activate`

check if python 3 is now available  
`python --version` (this should give something like: "Python 3.7.1")

ensure you have the latest pip python module manager installed  
`pip install --upgrade pip` (use sudo if needed)

install python modules required  
`pip install -r requirements.txt`

#### Configuration ####

test if the main backup script is working by entering the following (this should give you the help page):  
`python bbbackup.py --help`

edit the file `bbbackup.sh` and adjust all paths and adjust the parameters to backup  

**IMPORTANT!!** upload the public ssh-key of the account on the machine to BitBucket, otherwise the backup script won't be able to authentify correctly to clone repositories. you can copy the public key to your clipboard on the mac using  
`pbcopy < ~/.ssh/id_rsa.pub `

test the `bbbackup.sh` script by executing it once manually (this will output log statements to check what is happening). if you have not yet provided any credentials the script will ask for BitBucket user credentials. Please provide these credentials incl. username, password and teamname. Execute the shellscript to test if the script works as expected:  
`sh ./bbbackup.sh`

if the script should be able to report via slack, please execute the python script manually as follows to configure slack. (See [Create a Slack app tutorial](https://github.com/slackapi/python-slackclient/blob/master/tutorial/01-creating-the-slack-app.md) on how to setup Slack) you will need to provide the slack API TOKEN of a slack-bot-user and provide a slack #CHANNEL where to post messages to.  
`python bbbackup.py -f /Users/$MyUserName/Backup/BitBucketBackup/clonedbackups/ --config-slack`

you can test if slack is working by sending a testmessage as follows:
`python bbbackup.py -f /Users/$MyUserName/Backup/BitBucketBackup/clonedbackups/ --message-slack "This is a test."`

#### Automation (on local machine) ####

you will automate the backups using macOS launchdaemon, which is configure with .plist-files

edit the file `de.openreply.bbbackup.plist` and adjust all paths  

edit the file `de.openreply.bbbackup.plist` and adjust the **StartCalendarInterval** for Hour & Minute at which time of the day the script should run  

activate the launchdaemon for automated backup (non-permanent!)  
`launchctl load de.openreply.bbbackup.plist`

**IMPORTANT!!** if you want the launchdaemon to reschedule backups even AFTER A REBOOT, you need to persist the configuration by placing it instead in the following folder and then execute the load command  
`cp /Users/$MyUserName/Backup/BitBucketBackup/de.openreply.bbbackup.plist /Library/LaunchDaemons/.`  
`launchctl load /Library/LaunchDaemons/de.openreply.bbbackup.plist`

_Congratulations! Your backups should now work automatically every day._

#### Deinstallation / Stopping ####

if you want to remove the service from scheduling and executing automatically every day you need to unload it  
`launchctl unload /Library/LaunchDaemons/de.openreply.bbbackup.plist`

**IMPORTANT!!** if you do NOT want the launchdaemon to restart/reschedule backups after a reboot you need to unload and remove it  
`launchctl unload /Library/LaunchDaemons/de.openreply.bbbackup.plist`  
`rm /Users/$MyUserName/Backup/Library/LaunchDaemons/de.openreply.bbbackup.plist`  

(for `launchctl load` and `launchctl unload` you need to provide the full absolute path always!!!)

## Help

Calling `python bbbackup.py --help` gives you all the options the app supports.

```
usage: bbbackup.py [-h] [-f FILEPATH | -c CONFIGFILE] [-a DATE]
                   [-m MESSAGESLACK] [-d DAYS] [-s STORAGELIMIT]
                   [-r RETRY_LIMIT] [-w WARNING_LIMIT]
                   [--backup | --no-backup] [--retry | --no-retry]
                   [--config-oauth2 | --no-config-oauth2]
                   [--config-bitbucket | --no-config-bitbucket]
                   [--config-slack | --no-config-slack]
                   [--notify | --no-notify] [--oauth2 | --no-oauth2]
                   [--config-import | --no-config-import]
                   [--config-export | --no-config-export] [--log | --no-log]
                   [--colors | --no-colors]

  _    _    _             _             
 | |__| |__| |__  __ _ __| |___  _ _ __ 
 | '_ \ '_ \ '_ \/ _` / _| / / || | '_ \
 |_.__/_.__/_.__/\__,_\__|_\_\\_,_| .__/
                             v1.3 |_|   
                                  
bbbackup - clone all repos from a given BitBucket team/user

Copyright (C) 2019  Helge Staedtler from Open Reply GmbH
This program comes with ABSOLUTELY NO WARRANTY
This is free software, and you are welcome to redistribute it
under certain conditions. DETAILS in the LICENSE file!

optional arguments:
  -h, --help            show this help message and exit
  -f FILEPATH, --filepath FILEPATH
                        Absolute path to a directory which will hold the managed backups
  -c CONFIGFILE, --configuration CONFIGFILE
                        Absolute path to configuration file where all necessary parameters are kept
                        *** WARNING: WILL OVERRIDE ALL COMMANDLINE ARGUMENTS LISTED HERE! ***
  -a DATE, --analyze DATE
                        Analyze backup for certain day/date/timestamp, e.g. YYYY-MM-DD
  -m MESSAGESLACK, --message-slack MESSAGESLACK
                        Send a testmessage as string via slack
  -d DAYS, --days DAYS  Maximum amount of days into the past we keep backups
                        [DEFAULT = 7]
  -s STORAGELIMIT, --storagelimit STORAGELIMIT
                        Minimum amount of free space in gigabytes on volume
                        [DEFAULT = 50]
  -r RETRY_LIMIT, --retry-limit RETRY_LIMIT
                        Number of attempts to clone repository that failed on first try
                        [DEFAULT = 3]
  -w WARNING_LIMIT, --warning-limit WARNING_LIMIT
                        Amount of failed repos allowed before we assume failure
                        [DEFAULT = 3]
  --backup              Will start/continue a full backup
  --no-backup           [DEFAULT] Will analyze existing backup
  --retry               [DEFAULT] Retry failed backup automatically
  --no-retry            Do NOT retry to accomplish failed backups
  --config-oauth2       Reset/configure oauth credentials (key/secret/app-name)
  --no-config-oauth2    [DEFAULT] Do not reset oauth credentials
  --config-bitbucket    Configure/reset the stored credentials for BitBucket uid, team, password
  --no-config-bitbucket
                        [DEFAULT] By default no configuration or reset of credentials
  --config-slack        Reset/configure slack credentials
  --no-config-slack     [DEFAULT] Do not reset slack credentials
  --notify              Notify on certain events via slack if configured
  --no-notify           [DEFAULT] Avoid notification via slack even if configured
  --oauth2              Authorize using OAuth 2.0
  --no-oauth2           [DEFAULT] Authorize with HTTPBasicAuth UserID/Password
  --config-import       Read/import current parameters from file 'bbbackup.cfg'
                        This will set the OAUTH, ACCOUNT & SLACK info for the current runtime context, to check the values
  --no-config-import    [DEFAULT] Do not import context from a config file
  --config-export       Write/export current context and parameters to file 'bbbackup.cfg'
                        This will create a config-file where OAUTH, ACCOUNT & SLACK info is stored/exported
  --no-config-export    [DEFAULT] Do not export context as a config file
  --log                 [DEFAULT] Send log output to tty
  --no-log              Avoid any log output to tty
  --colors              [DEFAULT] Colorize log output with ANSI code
  --no-colors           Do not colorize log output with ANSI code

HOW TO USE THIS APP
(1)
Run bbbackup.py locally with parameters --config-oauth2, --config-bitbucket and --config-slack
to configure BitBucket user/team, OAuth config and Slack config.

(2)
Then run bbbackup.py with --filepath to check if the connection to BitBucket works
e.g. bbbackup.py --filepath $PWD/mybackups

(3)
If everything worked, export the configuration by entering:
bbbackup.py --filepath $PWD/mybackups --config-export --oauth2
this creates the file 'bbbackup.cfg' to use in any non local OS env

(4)
You can now take this file and move it anywhere, e.g. a Docker environment
Just run bbbackup.py --configuration bbbackup.cfg --backup --notify
this will use the config file, start a backup and notify/report progress via slack
```
