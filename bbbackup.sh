#!/bin/bash

# activate virtual environment for bitbucket backup script
cd /Users/admin/Backup/
source bin/activate

# execute backup script to do a backup to the defined folder (see bbbackup.cfg which folder and which config the app will run with)
python bbbackup.py --configuration /Users/admin/Backup/bbbackup.cfg --notify --backup