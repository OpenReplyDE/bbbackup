# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""
    BBBACKUP
    Script to clone all repos from a specified BitBucket team/user to create a BitBucket Backup
    using the Atlassian BitBucket API 2.0 and GitPython

      Author: Helge Staedtler
      E-Mail: h.staedtler@reply.de
     Company: Open Reply GmbH, Bremen/Germany
     Version: 1.4
    Language: Python 3
     License: MIT License (see https://choosealicense.com/licenses/mit/)


    MIT License

    Copyright (c) 2019 Open Reply GmbH, Bremen, Germany
    Helge Staedtler <h.staedtler@reply.de>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.


    Useful sources:
    https://alvinalexander.com/mac-os-x/mac-osx-startup-crontab-launchd-jobs
    https://api.slack.com/rtm
    https://api.slack.com/methods/chat.postMessage#formatting
    https://confluence.atlassian.com/bitbucket/oauth-on-bitbucket-cloud-238027431.html
    https://stackoverflow.com/questions/36719540/how-can-i-get-an-oauth2-access-token-using-python
    https://rauth.readthedocs.io/en/latest/
    https://lanphier.co.uk/scripts/automated-bitbucket-repository-backups-without-a-dedicated-user-account/
    https://confluence.atlassian.com/jirakb/how-to-automate-backups-for-jira-cloud-applications-779160659.html
    https://bitbucket.org/atlassianlabs/automatic-cloud-backup/src/master/
    https://github.com/samkuehn/bitbucket-backup

"""

from argparse import RawTextHelpFormatter
from git import Repo
from requests.auth import HTTPBasicAuth
from datetime import datetime
from datetime import timedelta
from datetime import date
from getpass import getpass
from slack.errors import SlackApiError
from rauth import OAuth2Service
from configparser import ConfigParser
from keyring.errors import KeyringLocked, InitError

import argparse
import json
import os
import requests
import sys
import time
import keyring
import errno
import unicodedata
import shutil
import signal
import slack
import math
import traceback

# CONSTANT VALUES
APP_VERSION     = "v1.4"
APP_BUILD       = "42"
APP_PATH        = os.path.dirname( os.path.abspath( __file__ ) )
APP_CONFIG_FILE = 'bbbackup.cfg'
APP_LOGO = '''
  _    _    _             _
 | |__| |__| |__  __ _ __| |___  _ _ __
 | '_ \ '_ \ '_ \/ _` / _| / / || | '_ \\
 |_.__/_.__/_.__/\__,_\__|_\_\\\\_,_| .__/
                             {} |_|
                                  '''

APP_COPYRIGHT_NOTICE = '''
Copyright (C) 2019-2020  Helge Staedtler from Open Reply GmbH
This program comes with ABSOLUTELY NO WARRANTY
This is free software, and you are welcome to redistribute it
under certain conditions. DETAILS in the LICENSE file!
'''

# API 1
API_V1_ROOT  = 'https://api.bitbucket.org/1.0/'
API_V1_USERS = 'users/'

# API 2
API_V2_ROOT  = 'https://api.bitbucket.org/2.0/'
API_V2_USERS = 'users/'
API_V2_REPOSITORIES = 'repositories/'
API_V2_PARAM_ROLE = 'role=member'

AUTH_METHOD_OAUTH2 = 'oauth'
AUTH_METHOD_UIDPWD = 'uidpwd'

# DEFAULTS
DEFAULT_API_USED = '2.0' # '1.0' is deprecated
DEFAULT_AUTH = AUTH_METHOD_UIDPWD
DEFAULT_BACKUP_ALL_BRANCHES = False
DEFAULT_BACKUP_ROOT_DIRECTORY = ''
DEFAULT_BACKUP_MAX_RETRIES = 3
DEFAULT_BACKUP_MAX_FAILS = 3
DEFAULT_BACKUP_MIN_FREESPACE_GIGA = 50
DEFAULT_BACKUP_STORE_DAYS = 7
DEFAULT_SLACK_TO_CHANNEL = '@channel'
DEFAULT_LOG_OUTPUT = True
DEFAULT_LOG_COLORIZED = True

# API VERSION TO USE (LATEST 2.0 recommended)
API_USED = DEFAULT_API_USED

AUTH = DEFAULT_AUTH

# OAUTH 2.0 SUPPORT
OAUTH_CLIENT_KEY_OR_ID = None # call with parameter --config-oauth2
OAUTH_CLIENT_SECRET = None    # call with parameter --config-oauth2
OAUTH_CLIENT_NAME = None      # call with parameter --config-oauth2
OAUTH_URL_AUTORIZE = 'https://bitbucket.org/site/oauth2/authorize'
OAUTH_URL_ACCESS_TOKEN = 'https://bitbucket.org/site/oauth2/access_token'
# OAUTH KEY/SECRET/NAME KEYS
CRED_KEY_OAUTH_KEY = "OAUTH_KEY"
CRED_KEY_OAUTH_SECRET = "OAUTH_SECRET"
CRED_KEY_OAUTH_NAME = "OAUTH_NAME"

# BACKUP STORAGE NAME
BACKUP_ARCHIVE_PREFIX = "BACKUP"
BACKUP_ARCHIVE_SUFFIX = "UTC"
BACKUP_ARCHIVE_DIRECTORY = None
BACKUP_ROOT_DIRECTORY = DEFAULT_BACKUP_ROOT_DIRECTORY
BACKUP_MAX_RETRIES = DEFAULT_BACKUP_MAX_RETRIES
BACKUP_MAX_FAILS = DEFAULT_BACKUP_MAX_FAILS
BACKUP_MIN_FREESPACE_GIGA = DEFAULT_BACKUP_MIN_FREESPACE_GIGA
BACKUP_STORE_MIN_DAYS = 1
BACKUP_STORE_DAYS = DEFAULT_BACKUP_STORE_DAYS
BACKUP_STORE_DAYS_SCOPE = 30
BACKUP_LASTRUN_FILE = "BACKUP_LASTRUN.JSON"

# LOG MODES
LOG_OUTPUT = DEFAULT_LOG_OUTPUT
LOG_COLORIZED = DEFAULT_LOG_COLORIZED

# BACKUP STATUS TAGS
STATUS_SYNC = "SYNC"
STATUS_DONE = "DONE"
STATUS_FAIL = "FAIL"

# CREDENTIAL STORAGE KEYS
CRED_KEY_SERVICE = "BBBACKUP"
CRED_KEY_UID = "UID"
CRED_KEY_PWD = "PWD"
CRED_KEY_TEAM = "TEAM"

# CREDENTIAL VALUES USED FOR AUTH
CONFIG_UID = None
CONFIG_PWD = None
CONFIG_TEAM = None

# SLACK CREDENTIALS
SLACK_API_TOKEN = None
SLACK_CHANNEL = None
SLACK_TO_CHANNEL = DEFAULT_SLACK_TO_CHANNEL
CRED_KEY_SLACK_CHANNEL = "SLACK_CHANNEL"
CRED_KEY_SLACK_TOKEN = "SLACK_TOKEN"

'''
**********************************
*** SYSTEM RELATED METHODS
**********************************
'''
# FORCED EXIT HANDLING
def signal_handler(sig, frame):
    print( "" )
    exit_with_code( 1 )

# check if the script is run from commandline/terminal (TTY)
def is_running_interactively():
    return sys.stdin.isatty()

def exit_with_code( code, optional_message=None ):
    finishtime = datetime.now()
    printstyled('FINISHED: ' + str( finishtime ), 'yellow', 'bold' )
    exit_msg = ''
    if code == 0:
        exit_msg = 'BACKUP: BYE, BYE.'
    elif code == 1:
        exit_msg = 'BACKUP: ABORTED. (CODE = {})'.format( str(code).zfill(2) )
    elif code == 2:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no valid credentials provided)'.format( str(code).zfill(2) )
    elif code == 3:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, unable to fetch repos, check credentials)'.format( str(code).zfill(2) )
    elif code == 4:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no valid slack configuration)'.format( str(code).zfill(2) )
    elif code == 5:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, not enough free space on volume)'.format( str(code).zfill(2) )
    elif code == 6:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no valid oauth 2.0 configuration)'.format( str(code).zfill(2) )
    elif code == 7:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no valid filepath for directory of backups provided, use --filepath or --configuration parameters)'.format( str(code).zfill(2) )
    elif code == 8:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, just finished writing/exporting configuration)'.format( str(code).zfill(2) )
    elif code == 9:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, just finished reading/importing configuration)'.format( str(code).zfill(2) )
    elif code == 10:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no valid data from API)'.format( str(code).zfill(2) )
    elif code == 11:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, unexpected repo data from API)'.format( str(code).zfill(2) )
    elif code == 12:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, access to the secure credential store disallowed by user)'.format( str(code).zfill(2) )
    elif code == 13:
        exit_msg = 'BACKUP: ABORTED. (CODE = {}, no supported secure credential store infrastructure found in current OS environment)'.format( str(code).zfill(2) )
    else:
        exit_msg = 'BACKUP: UNEXPECTED EXIT. (CODE = {})'.format( str(code).zfill(2) )
    if optional_message:
        exit_msg = exit_msg + '\n' + optional_message
    printstyled( exit_msg, 'cyan' )
    if code != 0:
        slack_send_message_of_category( exit_msg, 'fail' )
    print( "" )
    sys.exit( code )

# CHECK IF DIR EXISTS, IF NOT CREATE IT
def ensure_directory_exists( absolute_dir_path ):
    if os.path.exists( absolute_dir_path ):
        printstyled( 'DIRECTORY: OK {}'.format( absolute_dir_path ), 'cyan' )
        return
    else:
        printstyled( 'DIRECTORY: MISSING {}'.format( absolute_dir_path ), 'cyan' )
        printstyled( 'DIRECTORY: CREATING... {}'.format( absolute_dir_path ), 'cyan' )
        try:
            os.makedirs( absolute_dir_path )
            printstyled( 'DIRECTORY: CREATED.', 'green' )
        except OSError as e:
            printstyled( 'DIRECTORY: CREATION FAILED.', 'red' )
            if e.errno != errno.EEXIST:
                raise
    return

def get_fs_freespace( pathname ):
    "Get the free space of the filesystem containing pathname"
    stat = os.statvfs( pathname )
    return stat.f_bavail * stat.f_frsize

def sizeof_fmt(num, suffix='B'):
    for unit in ['','k','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Y', suffix)

def get_size( dir_path ):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk( dir_path ):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size

# HELPER TO COLORIZE PRINT OUTPUT
class termcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def printstyled( text = '', color = 'white', style = 'plain' ):
    if not log_mode:
        return
    if colorized_mode:
        if color == 'red':
            text = termcolor.RED + text
        if color == 'green':
            text = termcolor.GREEN + text
        if color == 'yellow':
            text = termcolor.YELLOW + text
        if color == 'blue':
            text = termcolor.BLUE + text
        if color == 'magenta':
            text = termcolor.MAGENTA + text
        if color == 'cyan':
            text = termcolor.CYAN + text
        if style == 'bold':
            text = termcolor.BOLD + text
        if style == 'underlined':
            text = termcolor.UNDERLINE + text
        text += termcolor.ENDC
    print( text )

# FILE OPERATIONS
def write_file( filename, content ):
    try:
        with open( filename, 'w' ) as f:
            f.write( content )
    except IOError:
        printstyled( 'FAILED TO WRITE FILE: {}'.format( filename ), 'red' )
    return

def delete_file( filename ):
    try:
        os.remove( filename )
    except:
        printstyled( 'FAILED TO DELETE FILE: {}'.format( filename ), 'red' )
    return

def delete_dir( dirname ):
    if not os.path.exists( dirname ):
        printstyled( 'FILE I/O: DIRECTORY TO DESTROY DOES NOT EXIST.', 'red' )
        return
    try:
        shutil.rmtree( dirname )
    except Exception as e:
        printstyled( 'FILE I/O: FAILED TO DESTROY DIRECTORY RECURSIVELY: {}'.format( dirname ), 'red' )
        printstyled( 'FILE I/O EXCEPTION: {}'.format( e ), 'red' )

'''
**********************************
*** CONFIGURATION WITH .CFG-FILE
**********************************
'''
def configuration_print():
    printstyled( 'CONFIG I/O: CONFIGURED FOLLOWING VALUES...', 'cyan' )
    printstyled( '{}: {}'.format( "AUTH", AUTH ), 'blue' )
    printstyled( '{}: {}'.format( "OAUTH_CLIENT_KEY_OR_ID", OAUTH_CLIENT_KEY_OR_ID ), 'blue' )
    printstyled( '{}: {}'.format( "OAUTH_CLIENT_SECRET", OAUTH_CLIENT_SECRET ), 'blue' )
    printstyled( '{}: {}'.format( "OAUTH_CLIENT_NAME", OAUTH_CLIENT_NAME ), 'blue' )
    printstyled( '{}: {}'.format( "CONFIG_UID", CONFIG_UID ), 'blue' )
    printstyled( '{}: {}'.format( "CONFIG_PWD", CONFIG_PWD ), 'blue' )
    printstyled( '{}: {}'.format( "CONFIG_TEAM", CONFIG_TEAM ), 'blue' )
    printstyled( '{}: {}'.format( "SLACK_API_TOKEN", SLACK_API_TOKEN ), 'blue' )
    printstyled( '{}: {}'.format( "SLACK_CHANNEL", SLACK_CHANNEL ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_ALL_BRANCHES", BACKUP_ALL_BRANCHES ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_ROOT_DIRECTORY", BACKUP_ROOT_DIRECTORY ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_MAX_RETRIES", BACKUP_MAX_RETRIES ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_MAX_FAILS", BACKUP_MAX_FAILS ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_MIN_FREESPACE_GIGA", BACKUP_MIN_FREESPACE_GIGA ), 'blue' )
    printstyled( '{}: {}'.format( "BACKUP_STORE_DAYS", BACKUP_STORE_DAYS ), 'blue' )
    printstyled( '{}: {}'.format( "LOG_OUTPUT", LOG_OUTPUT ), 'blue' )
    printstyled( '{}: {}'.format( "LOG_COLORIZED", LOG_COLORIZED ), 'blue' )

def configuration_import():
    global AUTH, OAUTH_CLIENT_KEY_OR_ID, OAUTH_CLIENT_SECRET, OAUTH_CLIENT_NAME, CONFIG_UID, CONFIG_PWD, CONFIG_TEAM
    global SLACK_API_TOKEN, SLACK_CHANNEL, BACKUP_ROOT_DIRECTORY, BACKUP_MAX_RETRIES, BACKUP_MAX_FAILS, BACKUP_MIN_FREESPACE_GIGA, BACKUP_STORE_DAYS
    global BACKUP_ALL_BRANCHES

    CONFIG_FILE_PATH = APP_PATH+'/'+APP_CONFIG_FILE
    if not os.path.exists( CONFIG_FILE_PATH ):
        printstyled( 'CONFIG I/O: No config {} found. Configuring default values.'.format( CONFIG_FILE_PATH ), 'red' )
        # APPLY DEFAULT VALUES
        AUTH                        = DEFAULT_AUTH
        OAUTH_CLIENT_KEY_OR_ID      = None
        OAUTH_CLIENT_SECRET         = None
        OAUTH_CLIENT_NAME           = None
        CONFIG_UID                  = None
        CONFIG_PWD                  = None
        CONFIG_TEAM                 = None
        SLACK_API_TOKEN             = None
        SLACK_CHANNEL               = None
        BACKUP_ALL_BRANCHES         = DEFAULT_BACKUP_ALL_BRANCHES
        BACKUP_ROOT_DIRECTORY       = DEFAULT_BACKUP_ROOT_DIRECTORY
        BACKUP_MAX_RETRIES          = DEFAULT_BACKUP_MAX_RETRIES
        BACKUP_MAX_FAILS            = DEFAULT_BACKUP_MAX_FAILS
        BACKUP_MIN_FREESPACE_GIGA   = DEFAULT_BACKUP_MIN_FREESPACE_GIGA
        BACKUP_STORE_DAYS           = DEFAULT_BACKUP_STORE_DAYS
        LOG_OUTPUT                  = DEFAULT_LOG_OUTPUT
        LOG_COLORIZED               = DEFAULT_LOG_COLORIZED
        # CREATE FRESH CONFIG FROM SCRATCH
        configuration_export()
        return
    else:
        printstyled( 'CONFIG I/O: READING... {}'.format( CONFIG_FILE_PATH ), 'cyan' )

    config_file = ConfigParser( allow_no_value=True )
    try:
        config_file.read( CONFIG_FILE_PATH )
    except Exception as e:
        printstyled( 'CONFIG I/O: No config \'{}\' found or unreadable.\n Error: {}'.format( CONFIG_FILE_PATH, e ), 'red' )
        return

    # READ VALUES
    try:
        AUTH                        = config_file.get( 'authorization', 'auth_method' )
        OAUTH_CLIENT_KEY_OR_ID      = config_file.get( 'bitbucket_oauth', 'key_or_id' )
        OAUTH_CLIENT_SECRET         = config_file.get( 'bitbucket_oauth', 'secret' )
        OAUTH_CLIENT_NAME           = config_file.get( 'bitbucket_oauth', 'app_name' )
        CONFIG_UID                  = config_file.get( 'bitbucket_account', 'userid' )
        CONFIG_PWD                  = config_file.get( 'bitbucket_account', 'password' )
        CONFIG_TEAM                 = config_file.get( 'bitbucket_account', 'teamname' )
        SLACK_API_TOKEN             = config_file.get( 'slack', 'api_token' )
        SLACK_CHANNEL               = config_file.get( 'slack', 'channel_to_post' )
        BACKUP_ALL_BRANCHES         = config_file.get( 'backup', 'all_branches' )
        BACKUP_ROOT_DIRECTORY       = config_file.get( 'backup', 'filepath' )
        BACKUP_MAX_RETRIES          = config_file.getint( 'backup', 'max_retries' )
        BACKUP_MAX_FAILS            = config_file.getint( 'backup', 'max_fails' )
        BACKUP_MIN_FREESPACE_GIGA   = config_file.getint( 'backup', 'min_free_space' )
        BACKUP_STORE_DAYS           = config_file.getint( 'backup', 'amount_of_days_to_store' )
        LOG_OUTPUT                  = config_file.getboolean( 'log', 'logging_on' )
        LOG_COLORIZED               = config_file.getboolean( 'log', 'colorized_logging_on' )
    except Exception as e:
        printstyled( 'CONFIG I/O: Config \'{}\' was missing correct values.\n Error: {}'.format( CONFIG_FILE_PATH, e ), 'red' )
        return
    printstyled( 'CONFIG I/O: Config \'{}\' succesfully imported.'.format( CONFIG_FILE_PATH ), 'green' )

def configuration_stringify( value ):
    if value == None:
        return ""
    else:
        return "{}".format( value )

def configuration_export():
    CONFIG_FILE_PATH = APP_PATH+'/'+APP_CONFIG_FILE

    config_file = ConfigParser( allow_no_value=True )
    # STORE authorization method
    config_file.add_section( 'authorization' )
    config_file.set( 'authorization', '; ENTER WHICH AUTH METHOD TO USE \'oauth\' OR \'uidpwd\'' )
    config_file.set( 'authorization', '; YOU SHOULD CHOOSE \'oauth\' AND REMOVE THE PASSWORD FOR \'bitbucket_account\'' )
    config_file.set( 'authorization', 'auth_method', configuration_stringify( AUTH ) )
    # STORE oauth
    config_file.add_section( 'bitbucket_oauth' )
    config_file.set( 'bitbucket_oauth', '; ENTER OAUTH 2.0 CREDENTIALS HERE (RECOMMENDED!)' )
    config_file.set( 'bitbucket_oauth', 'key_or_id', configuration_stringify( OAUTH_CLIENT_KEY_OR_ID ) )
    config_file.set( 'bitbucket_oauth', 'secret', configuration_stringify( OAUTH_CLIENT_SECRET ) )
    config_file.set( 'bitbucket_oauth', 'app_name', configuration_stringify( OAUTH_CLIENT_NAME ) )
    # STORE account
    config_file.add_section( 'bitbucket_account' )
    config_file.set( 'bitbucket_account', '; ENTER YOUR CREDENTIALS FOR BITBUCKET HERE, USE SAME FOR USER AND TEAM IF YOU WANT USER' )
    config_file.set( 'bitbucket_account', '; PASSWORD IS ONLY NEEDED IF \'authorization\' USES \'uidpwd\' (NOT RECOMMENDED!)' )
    config_file.set( 'bitbucket_account', 'userid', configuration_stringify( CONFIG_UID ) )
    config_file.set( 'bitbucket_account', 'password', configuration_stringify( CONFIG_PWD ) )
    config_file.set( 'bitbucket_account', 'teamname', configuration_stringify( CONFIG_TEAM ) )
    # STORE slack
    config_file.add_section( 'slack' )
    config_file.set( 'slack', '; ENTER API-TOKEN AND THE CHANNEL NAME WHERE TO POST MESSAGES TO HERE' )
    config_file.set( 'slack', 'api_token', configuration_stringify( SLACK_API_TOKEN ) )
    config_file.set( 'slack', 'channel_to_post', configuration_stringify( SLACK_CHANNEL ) )
    # STORE backup
    config_file.add_section( 'backup' )
    config_file.set( 'backup', '; ENTER BACKUP RELATED PARAMETERS HERE, I.E. FILEPATH TO DIRECTORY WHERE TO STORE BACKUPS' )
    config_file.set( 'backup', 'backup_all_branches', configuration_stringify( BACKUP_ALL_BRANCHES ))
    config_file.set( 'backup', 'filepath', configuration_stringify( BACKUP_ROOT_DIRECTORY ) )
    config_file.set( 'backup', 'max_retries', configuration_stringify( BACKUP_MAX_RETRIES ) )
    config_file.set( 'backup', 'max_fails', configuration_stringify( BACKUP_MAX_FAILS ) )
    config_file.set( 'backup', 'min_free_space', configuration_stringify( BACKUP_MIN_FREESPACE_GIGA ) )
    config_file.set( 'backup', 'amount_of_days_to_store', configuration_stringify( BACKUP_STORE_DAYS ) )
    # STORE log
    config_file.add_section( 'log' )
    config_file.set( 'log', '; ENTER LOG RELATED OPTIONS AS True AND FALSE' )
    config_file.set( 'log', 'logging_on', configuration_stringify( LOG_OUTPUT ) )
    config_file.set( 'log', 'colorized_logging_on', configuration_stringify( LOG_COLORIZED ) )

    printstyled( 'CONFIG I/O: WRITING... {}'.format( CONFIG_FILE_PATH ), 'cyan' )

    try:
        with open( CONFIG_FILE_PATH, 'w' ) as file_to_write:
            config_file.write( file_to_write )
    except Exception as e:
        printstyled( 'CONFIG I/O: Failed to save config \'{}\'.\n Error: {}'.format( CONFIG_FILE_PATH, e ), 'red' )
    return

'''
**********************************
*** SLACK
**********************************
'''
# SLACK COMMUNICATION
def slack_send_message_to_channel( message, channel ):
    global SLACK_API_TOKEN
    if not notify_mode:
        if log_mode:
            if SLACK_API_TOKEN:
                printstyled( 'SLACK: SUPRESSING NOTIFICATION\n>>>\n' + message + '\n<<<', 'white' )
        return
    if SLACK_API_TOKEN == None:
        printstyled( 'SLACK: MISSING API TOKEN', 'red' )
    else:
        if message:
            printstyled( 'SLACK: SENDING MESSAGE \'{}\''.format( message ), 'cyan' )
            client = None
            try:
                client = slack.WebClient( token = SLACK_API_TOKEN, timeout=60 )
            except Exception as e:
                printstyled( 'SLACK: API EXCEPTION {}'.format( e ), 'red' )
            if not channel:
                channel = '#random'
            if client:
                try:
                    response = client.chat_postMessage( channel=channel,text=message, link_names=True, mrkdwn=True )
                    printstyled( 'SLACK: MESSAGE WAS SENT.', 'green' )
                except SlackApiError as e:
                    printstyled( 'SLACK: API CONNECTION ERROR. EXCEPTION: {}'.format( e ), 'red' )
            else:
                printstyled( 'SLACK: MESSAGE NOT SENT.', 'red' )
        else:
            printstyled( 'SLACK: NO MESSAGE TO SEND.', 'red' )

# CONVENIENCE MESSAGE
def slack_send_message_of_category( message, category=None ):
    if not message:
        return
    message_prefix = None
    if category == 'fail':
        message_prefix = '⛔️ FAIL' + ' ' + SLACK_TO_CHANNEL + ' '
    elif category == 'warn':
        message_prefix = '⚠️ WARNING'
    elif category == 'ok':
        message_prefix = '✅ OK'
    elif category == 'info':
        message_prefix = '🌐 INFO'
    else:
        message_prefix = None
    if message_prefix:
        message = message_prefix + '\n' + message
    slack_send_message_to_channel( message, SLACK_CHANNEL )

def slack_selftest():
    slack_send_message_of_category( 'Nachrichtentest' )
    slack_send_message_of_category( 'Nachrichtentest Failed', 'fail' )
    slack_send_message_of_category( 'Nachrichtentest Warning', 'warn' )
    slack_send_message_of_category( 'Nachrichtentest Okay', 'ok' )
    slack_send_message_of_category( 'Nachrichtentest Information', 'info' )

# CHECK SLACK CONFIG
def slack_config_load( should_ask = True ):
    global SLACK_API_TOKEN, SLACK_CHANNEL
    ring = None
    try:
        ring = keyring.get_keyring()
        SLACK_API_TOKEN = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_TOKEN )
        SLACK_CHANNEL = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_CHANNEL )
    except KeyringLocked:
        printstyled( 'SLACK: CONFIG NOT AVAILABLE. KEYRING IS LOCKED!', 'red' )
        exit_with_code( 12, "Slack API tokens could not be read from secure credential store." )
    except InitError:
        exit_with_code( 13 )

    if not should_ask:
        return

    if SLACK_API_TOKEN == None or SLACK_CHANNEL == None:
        printstyled( 'SLACK: CONFIG NOT FOUND.', 'red' )
        if is_running_interactively() and slackconfig:
            print( "---    PLEASE ENTER SLACK CHANNEL AND API TOKEN NOW    ---" )
            print( "--- (WILL BE STORED IN SECURE KEYRING INFRASTRUCTURE.) ---" )
            input_token = input( termcolor.BLUE +  "API TOKEN: " + termcolor.ENDC )
            input_channel = input( termcolor.BLUE + "  CHANNEL: " + termcolor.ENDC )
            if input_token and input_channel:
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_TOKEN, input_token )
                SLACK_API_TOKEN = input_token
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_CHANNEL, input_channel )
                SLACK_CHANNEL = input_channel
                printstyled( 'SLACK: SUCCESS, CONFIG STORED.', 'green' )
            else:
                printstyled( 'SLACK: FAIL, COULD NOT STORE CONFIG.', 'red' )
                exit_with_code( 4, 'Slack credential could not be saved.' )
        else:
            if slackconfig:
                exit_with_code( 4, 'Missing credentials could not be requested interactively, because script not running in tty/shell context.' )
    else:
        printstyled( 'SLACK: CONFIGURED.', 'green' )

def slack_config_reset():
    global SLACK_API_TOKEN, SLACK_CHANNEL
    printstyled( 'SLACK: RESETTING...', 'cyan' )
    ring = None
    try:
        ring = keyring.get_keyring()
    except KeyringLocked:
        exit_with_code( 12 )
    except InitError:
        exit_with_code( 13 )
    try:
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_CHANNEL )
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_SLACK_TOKEN )
        SLACK_API_TOKEN = None
        SLACK_CHANNEL = None
        printstyled( 'SLACK: REMOVED.', 'cyan' )
    except:
        printstyled( 'SLACK: NO CREDENTIALS TO REMOVE.', 'red' )

    slack_config_load()

'''
**********************************
*** OAUTH CREDENTIALS
**********************************
'''
# CHECK OAUTH 2 CONFIG
def oauth_config_load( should_ask = True ):
    global OAUTH_CLIENT_NAME, OAUTH_CLIENT_KEY_OR_ID, OAUTH_CLIENT_SECRET
    ring = None
    try:
        ring = keyring.get_keyring()
        OAUTH_CLIENT_NAME = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_NAME )
        OAUTH_CLIENT_KEY_OR_ID = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_KEY )
        OAUTH_CLIENT_SECRET = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_SECRET )
    except KeyringLocked:
        printstyled( 'OAUTH: NOT AVAILABLE. KEYRING IS LOCKED!', 'red' )
        exit_with_code( 12, "Bitbucket OAuth 2.0 config could not be read from secure credential store." )
    except InitError:
        exit_with_code( 13 )

    if not should_ask:
        return

    if OAUTH_CLIENT_NAME == None or OAUTH_CLIENT_KEY_OR_ID == None or OAUTH_CLIENT_SECRET == None:
        printstyled( 'OAUTH: CONFIG NOT FOUND.', 'red' )
        if is_running_interactively():
            print( "---  PLEASE ENTER OAUTH NAME/KEY/SECRET FOR BITBUCKET  ---" )
            print( "--- (WILL BE STORED IN SECURE KEYRING INFRASTRUCTURE.) ---" )
            input_key = input( termcolor.BLUE +    "     OAUTH KEY: " + termcolor.ENDC )
            input_secret = input( termcolor.BLUE + "  OAUTH SECRET: " + termcolor.ENDC )
            input_name = input( termcolor.BLUE +   "OAUTH APP NAME: " + termcolor.ENDC )
            if input_name and input_key and input_secret:
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_NAME, input_name )
                OAUTH_CLIENT_NAME = input_name
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_KEY, input_key )
                OAUTH_CLIENT_KEY_OR_ID = input_key
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_SECRET, input_secret )
                OAUTH_CLIENT_SECRET = input_secret
                printstyled( 'OAUTH: SUCCESS, CONFIG STORED.', 'green' )
            else:
                printstyled( 'OAUTH: FAIL, COULD NOT STORE CONFIG.', 'red' )
                exit_with_code( 6, 'OAuth 2.0 credentials could not be saved.' )
        else:
            if oauthconfig:
                exit_with_code( 6, 'Missing OAuth 2.0 credentials could not be requested interactively, because script not running in tty/shell context.' )
    else:
        printstyled( 'OAUTH: CONFIGURED.', 'green' )

def oauth_config_reset():
    global OAUTH_CLIENT_NAME, OAUTH_CLIENT_KEY_OR_ID, OAUTH_CLIENT_SECRET
    printstyled( 'OAUTH: RESETTING...', 'cyan' )
    ring = None
    try:
        ring = keyring.get_keyring()
    except KeyringLocked:
        exit_with_code( 12 )
    except InitError:
        exit_with_code( 13 )
    try:
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_NAME )
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_KEY )
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_OAUTH_SECRET )
        OAUTH_CLIENT_NAME = None
        OAUTH_CLIENT_KEY_OR_ID = None
        OAUTH_CLIENT_SECRET = None
        printstyled( 'OAUTH: REMOVED.', 'cyan' )
    except:
        printstyled( 'OAUTH: NO CREDENTIALS TO REMOVE.', 'red' )

    oauth_config_load()



'''
**********************************
*** BITBUCKET
**********************************
'''
# CHECKS IF VALID CREDENTIALS ARE STORED IN SECURE STORAGE
def bitbucket_config_load( should_ask = True ):
    global CONFIG_UID, CONFIG_PWD, CONFIG_TEAM
    ring = None
    try:
        ring = keyring.get_keyring()
        CONFIG_UID = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_UID )
        CONFIG_PWD = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_PWD )
        CONFIG_TEAM = ring.get_password( CRED_KEY_SERVICE, CRED_KEY_TEAM )
    except KeyringLocked:
        printstyled( 'BITBUCKET: CONFIG NOT AVAILABLE. KEYRING IS LOCKED!', 'red' )
        exit_with_code( 12, "Bitbucket credentials could not be read from secure credential store." )
    except InitError:
        exit_with_code( 13 )

    if not should_ask:
        return

    if CONFIG_UID == None or CONFIG_PWD == None:
        printstyled( 'BITBUCKET: NOT CONFIGURED.', 'red' )
        if is_running_interactively():
            print( "--- PLEASE ENTER CREDENTIALS FOR BITBUCKET ACCOUNT NOW ---" )
            print( "--- (WILL BE STORED IN SECURE KEYRING INFRASTRUCTURE.) ---" )
            input_uid = input( termcolor.BLUE + "  BitBucket USER ID: " + termcolor.ENDC )
            input_password = getpass( prompt=termcolor.BLUE + " BitBucket PASSWORD: " + termcolor.ENDC )
            input_team = input( termcolor.BLUE + "  BitBucket TEAM ID: " + termcolor.ENDC )
            if input_uid and input_password:
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_UID, input_uid )
                CONFIG_UID = input_uid
                ring.set_password( CRED_KEY_SERVICE, CRED_KEY_PWD, input_password )
                CONFIG_PWD = input_password
                if input_team:
                    ring.set_password( CRED_KEY_SERVICE, CRED_KEY_TEAM, input_team )
                    CONFIG_TEAM = input_team
                printstyled( 'BITBUCKET: SUCCESS, CONFIG STORED.', 'green' )
            else:
                printstyled( 'BITBUCKET: FAIL, CONFIG COULD NOT BE STORED.', 'red' )
                exit_with_code( 2, 'Credentials could not be saved.' )
        else:
            exit_with_code( 2, 'Missing credentials could not be requested interactively, because script not running in tty/shell context.' )
    else:
        printstyled( 'BITBUCKET: CONFIGURED.', 'green' )

# REMOVES ALL STORED CREDENTIALS FROM SECURE STORAGE
def bitbucket_config_reset():
    printstyled( 'BITBUCKET: RESETTING CONFIG...', 'cyan' )
    ring = None
    try:
        ring = keyring.get_keyring()
    except InitError:
        printstyled( 'BITBUCKET: UNABLE TO RESET CONFIG.', 'red' )
        exit_with_code( 13 )
    try:
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_UID )
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_PWD )
        ring.delete_password( CRED_KEY_SERVICE, CRED_KEY_TEAM )
        CONFIG_UID = None
        CONFIG_PWD = None
        CONFIG_TEAM = None
        printstyled( 'BITBUCKET: CONFIG REMOVED.', 'cyan' )
    except:
        printstyled( 'BITBUCKET: NO CREDENTIALS TO REMOVE.', 'red' )

    bitbucket_config_load()

'''
**********************************
*** REPO STATUS HANDLING
**********************************
'''
def repo_status_is( repo_path, status ):
    filename_status = "{}.{}".format( repo_path, status )
    return os.path.exists( filename_status )

def repo_status_set( repo_path, status, content ):
    filename_status = "{}.{}".format( repo_path, status )
    if os.path.exists( filename_status ):
        os.remove( filename_status )
    if content == None:
        content = status
    write_file( filename_status, content )

def mark_repo_sync( repo_path, content=None ):
    mark_repo_clear( repo_path )
    repo_status_set( repo_path, STATUS_SYNC, content )
    printstyled( "REPO SYNC: {}".format( repo_path ), 'yellow' )
    # step 1: check if a syncing-tag exists
    # step 2: if yes, remove it and remove the incomplete git repo (we will retry a full backup any way)
    # step 3: if no, create a syncing-tag
    return

def mark_repo_done( repo_path, content=None ):
    mark_repo_clear( repo_path )
    repo_status_set( repo_path, STATUS_DONE, content )
    printstyled( "REPO DONE: {}".format( repo_path ), 'green' )
    # step 1: remove existing syncing-tag
    # step 2: add complete-tag
    return

def mark_repo_fail( repo_path, content=None ):
    mark_repo_clear( repo_path )
    repo_status_set( repo_path, STATUS_FAIL, content )
    printstyled( "REPO FAIL: {}".format( repo_path ), 'red' )
    # step 1: remove syncing-tag
    # step 2: add failed-tag
    return

def mark_repo_clear( repo_path ):
    filename_sync = "{}.{}".format( repo_path, STATUS_SYNC )
    filename_done = "{}.{}".format( repo_path, STATUS_DONE )
    filename_fail = "{}.{}".format( repo_path, STATUS_FAIL )
    files = {filename_sync, filename_done, filename_fail}
    for current_file in files:
        if os.path.exists( current_file ):
            os.remove( current_file )

'''
**********************************
*** BACKUP
**********************************
'''
def backup_archive_system_stats():
    BACKUP_LOCAL_PATH =  os.path.abspath( os.path.join( BACKUP_ROOT_DIRECTORY, BACKUP_ARCHIVE_DIRECTORY ) )
    size_of_directory = get_size( BACKUP_LOCAL_PATH )
    string_dirsize = 'Storage size used by backup: {}'.format( sizeof_fmt( size_of_directory ) )

    size_remaining = get_fs_freespace( BACKUP_ROOT_DIRECTORY )
    string_freespace = 'Storage size available on volume: {}'.format( sizeof_fmt( size_remaining ) )

    size_of_root_directory = get_size( BACKUP_ROOT_DIRECTORY )
    string_rootsize = 'Storage size used over ALL backups: {}'.format( sizeof_fmt( size_of_root_directory ) )

    return string_dirsize + '\n' + string_freespace + '\n' + string_rootsize

# returns datetime of last run based on stored JSON datetime object
def backup_archive_datetime_lastrun():
    t = None
    try:
        with open( BACKUP_LASTRUN_FILE, 'r' ) as json_file:
            lastrun = json.load( json_file )
            json_file.close()
            t = datetime( year=lastrun['year'], month=lastrun['month'],day=lastrun['day'],hour=lastrun['hour'],minute=lastrun['minute'],second=lastrun['second'] )
            printstyled( 'LASTRUN: WAS AT {}'.format( str( t ) ), 'green' )
    except Exception as e:
        printstyled( 'LASTRUN: NOT AVAILABLE. {}'.format( e ), 'red' )
    return t

def backup_archive_num_of_repos_lastrun():
    num_of_repos = None
    try:
        with open( BACKUP_LASTRUN_FILE, 'r' ) as json_file:
            lastrun = json.load( json_file )
            json_file.close()
            num_of_repos = int( lastrun['num_of_repos'] )
            printstyled( 'LASTRUN: NUM OF REPOS WAS {}'.format( str( num_of_repos ) ), 'green' )
    except Exception as e:
        printstyled( 'LASTRUN: NUM OF REPOS NOT AVAILABLE. {}'.format( e ), 'red' )
    return num_of_repos

# save the date and time the last successful backup was completed
# this is needed to detect issues of system clock/date/timezone
# to not accidentially delete valid backups
def backup_archive_save_lastrun( num_of_repos, size_of_repos):
    t = datetime.now().utcnow()
    lastrun = {
        'year' : t.year,
        'month' : t.month,
        'day' : t.day,
        'hour' : t.hour,
        'minute' : t.minute,
        'second' : t.second,
        'num_of_repos' : num_of_repos,
        'size_of_repos' : size_of_repos,
    }
    with open( BACKUP_LASTRUN_FILE, 'w' ) as json_file:
        json.dump( lastrun, json_file )
        json_file.close()

# check if we can safely operate with the provided datetime by the operating system
def backup_archive_has_valid_time_context():
    past = backup_archive_datetime_lastrun()
    if not past: # no last run available, thus no valid context
        return False
    present = datetime.now().utcnow()
    if present < past: # present MUST always be greater than past to have valid context
        return False
    return True

# GENERATE NEW TIMESTAMPED BACKUP DIRECTORY NAME, e.g. BACKUP_20190513_UTC
def backup_archive_name_for_datetime_utc( timestamp_utc ):
    global BACKUP_ARCHIVE_PREFIX, BACKUP_ARCHIVE_SUFFIX, BACKUP_ARCHIVE_NAME
    if not timestamp_utc:
        timestamp_utc = datetime.now().utcnow()
    return BACKUP_ARCHIVE_PREFIX+"_"+str(timestamp_utc.year)+str(timestamp_utc.month).zfill(2)+str(timestamp_utc.day).zfill(2)+"_"+BACKUP_ARCHIVE_SUFFIX
    # +"_"+str(now.hour).zfill(2)+str(now.minute).zfill(2)

# check existence
def backup_archive_exists_with_name( directory_name ):
    if not directory_name:
        return False
    BACKUP_LOCAL_PATH =  os.path.abspath( os.path.join( BACKUP_ROOT_DIRECTORY, directory_name ) )
    return os.path.exists( BACKUP_LOCAL_PATH )

def backup_archive_rotate_with_days( days_into_past_keep, days_into_past_scope ):
    printstyled( 'ROTATION: VACUUMING OLD BACKUPS ...', 'magenta' )
    current_day = datetime.now().utcnow()
    oneday = timedelta( days=1 )
    i = 0
    while i < days_into_past_scope:
        current_day = current_day - oneday
        current_archive_name = backup_archive_name_for_datetime_utc( current_day )
        should_remove = ( i + 1 > days_into_past_keep )

        if backup_archive_exists_with_name( current_archive_name ):
            printstyled( 'ROTATION: BACKUP EXISTS: {}; SHOULD DELETE == {}'.format( current_archive_name, str(should_remove) ), 'green', 'bold' )
            if should_remove: # REMOVE(!!!) complete backupfolder
                printstyled( 'ROTATION: DESTROYING {}'.format( current_archive_name ), 'magenta', 'bold' )
                BACKUP_LOCAL_PATH =  os.path.abspath( os.path.join( BACKUP_ROOT_DIRECTORY, current_archive_name ) )
                delete_dir( BACKUP_LOCAL_PATH )
        else:
            printstyled( 'ROTATION: BACKUP NOT EXISTING: {}; SHOULD DELETE == {}'.format( current_archive_name, str(should_remove) ), 'red', 'bold' )
        i += 1
    printstyled( 'ROTATION: VACUUMING COMPLETED.', 'magenta' )
    return

def backup_archive_days_archived( days_into_past_keep ):
    current_day = datetime.now().utcnow()
    oneday = timedelta( days=1 )
    num_stored_archives = 0
    i = 0
    current_day = current_day + oneday
    while i < ( days_into_past_keep + 1 ):
        current_day = current_day - oneday
        current_archive_name = backup_archive_name_for_datetime_utc( current_day )

        if backup_archive_exists_with_name( current_archive_name ):
            num_stored_archives += 1
        i += 1
    return num_stored_archives

'''
**********************************
*** BITBUCKET & API & OAUTH HELPERS
**********************************
'''
# OAUTH 2.0 SUPPORT/HELPERS
def bitbucket_api_oauth2_token():
    global OAUTH_CLIENT_NAME, OAUTH_CLIENT_KEY_OR_ID, OAUTH_CLIENT_SECRET
    printstyled( "BITBUCKET: Fetching OAuth 2.0 Token... ", 'magenta' )
    bitbucket_service = OAuth2Service(
        client_id = OAUTH_CLIENT_KEY_OR_ID,
        client_secret = OAUTH_CLIENT_SECRET,
        name = OAUTH_CLIENT_NAME,
        authorize_url = OAUTH_URL_AUTORIZE,
        access_token_url = OAUTH_URL_ACCESS_TOKEN,
        base_url = API_V2_ROOT)

    data = { 'code':'bar', 'grant_type':'client_credentials', 'redirect_uri':'http://127.0.0.1/' }
    session = bitbucket_service.get_auth_session( data=data, decoder=json.loads )
    if session.access_token:
        printstyled( 'BITBUCKET: Received OAuth 2.0 Token: {}'.format( session.access_token ), 'magenta' )
    else:
        printstyled( 'BITBUCKET: ERROR, no OAuth 2.0 Token received.', 'red' )
    return session.access_token

def bitbucket_api_oauth2_header_with_token( oauth_token ):
    bearer_token = 'Bearer {}'.format( oauth_token )
    header = { 'Authorization': bearer_token }
    return header

# FETCH LIST OF REPOSITORIES (API 1.0)
def bitbucket_api_get_repos_10( username, password, team ):
    bitbucket_endpoint_repos = API_V1_ROOT + API_V1_USERS
    raw_request = None
    if AUTH == AUTH_METHOD_UIDPWD:
        raw_request = requests.get( bitbucket_endpoint_repos + team, auth = HTTPBasicAuth( username, password ) )
    elif AUTH == AUTH_METHOD_OAUTH2:
        oauth_token = bitbucket_api_oauth2_token()
        raw_request = requests.get( bitbucket_endpoint_repos + team, headers = bitbucket_api_oauth2_header_with_token( oauth_token ) )
    dict_request = None
    repos = None
    statuscode = None
    try:
        statuscode = raw_request.status_code
        dict_request = json.loads( raw_request.content.decode('utf-8') )

        repos = dict_request['repositories']
    except Exception as e:
        error_msg = 'BITBUCKET: CONNECTION FAILED. — HTTP STATUS CODE: {}'.format( str(statuscode) )
        printstyled( error_msg, 'red' )
        if backup:
            slack_send_message_of_category( error_msg, 'fail' )
        raw_request.raise_for_status()
    return repos

def bitbucket_api_get_repos_20_oauth( username, password, team ):
    if not username or not team:
        exit_with_code( 2 )
    bitbucket_endpoint_repos = 'https://api.bitbucket.org/2.0/' + API_V2_REPOSITORIES + team + '/?'+ API_V2_PARAM_ROLE

    # GET OVERVIEW OF HOW MANY REPOS AND PAGES TO FETCH...
    dict_request = None
    repos = []
    statuscode = None

    oauth_token = bitbucket_api_oauth2_token()

    printstyled( "BITBUCKET: Fetching list of repos (OAUTH)... "+bitbucket_endpoint_repos, 'green' )
    try:
        raw_request = requests.get( bitbucket_endpoint_repos, headers = bitbucket_api_oauth2_header_with_token( oauth_token ) )
        statuscode = raw_request.status_code
    except Exception as e:
        error_msg = 'BITBUCKET: CONNECTION FAILED. — HTTP STATUS CODE: {}'.format( str(statuscode) )
        printstyled( error_msg, 'red' )
        if backup:
            slack_send_message_of_category( error_msg, 'fail' )
        raw_request.raise_for_status()

    dict_request = json.loads( raw_request.content.decode('utf-8') )
    num_of_repos = dict_request['size']
    num_of_page = dict_request['page']
    pagelen = dict_request['pagelen']
    num_of_pages = math.ceil( num_of_repos / pagelen )
    printstyled( "Number of Repos = {}; Num of pages {}".format( num_of_repos, num_of_pages ), 'green' )
    return repos

# FETCH LIST OF REPOSITORIES (API 2.0)
def bitbucket_api_get_repos_20( username, password, team ):
    role = 'role=member'
    bitbucket_endpoint_repos = 'https://api.bitbucket.org/2.0/' + API_V2_REPOSITORIES + team + '/?'+ API_V2_PARAM_ROLE

    auth_mode_str = None
    if AUTH == AUTH_METHOD_UIDPWD:
        auth_mode_str = 'UID/PWD'
    elif AUTH == AUTH_METHOD_OAUTH2:
        auth_mode_str = 'OAUTH'
    printstyled( "BITBUCKET: Fetching list of repos ({})... ".format( auth_mode_str )+bitbucket_endpoint_repos, 'green' )

    # GET OVERVIEW OF HOW MANY REPOS AND PAGES TO FETCH...
    dict_request = None
    repos = []
    statuscode = None
    oauth_token = None
    raw_request = None
    try:
        if AUTH == AUTH_METHOD_UIDPWD:
            raw_request = requests.get( bitbucket_endpoint_repos, auth = HTTPBasicAuth( username, password ) )
        elif AUTH == AUTH_METHOD_OAUTH2:
            oauth_token = bitbucket_api_oauth2_token()
            raw_request = requests.get( bitbucket_endpoint_repos, headers = bitbucket_api_oauth2_header_with_token( oauth_token ) )
        statuscode = raw_request.status_code
    except Exception as e:
        error_msg = 'BITBUCKET: CONNECTION FAILED. — HTTP STATUS CODE: {}\n{}'.format( str(statuscode), e )
        printstyled( error_msg, 'red' )
        if backup:
            slack_send_message_of_category( error_msg, 'fail' )
        raw_request.raise_for_status()
    if statuscode != 200:
        if statuscode == 401:
            printstyled( "BITBUCKET: {}, AUTHORIZATION FAILED.".format( statuscode ), 'red' )
            exit_with_code( 3 )
        else:
            printstyled( "BITBUCKET: {}, HTTP STATUS CODE OF CONNECTION.".format( statuscode ), 'red' )
    try:
        dict_request = json.loads( raw_request.content.decode('utf-8') )
        num_of_repos = dict_request['size']
        num_of_page = dict_request['page']
        pagelen = dict_request['pagelen']
        num_of_pages = math.ceil( num_of_repos / pagelen )
        printstyled( "Number of Repos = {}; Num of pages {}".format( num_of_repos, num_of_pages ), 'green' )
    except Exception as e:
        error_msg = 'BITBUCKET: API FAILED TO DELIVER EXPECTED DATA: {}\n{}'.format( raw_request.content.decode('utf-8'), e )
        printstyled( error_msg, 'red' )
        exit_with_code( 10, raw_request.content.decode('utf-8') )

    # FETCH ALL PAGES OF REPOS
    current_page_index = 1

    while current_page_index <= num_of_pages:
        bitbucket_api_call = 'https://api.bitbucket.org/2.0/' + API_V2_REPOSITORIES + team + '/?' + API_V2_PARAM_ROLE + '&page={}'.format( current_page_index )
        raw_request = None
        try:
            printstyled( "BITBUCKET: Fetching repo page #{} ... ".format( current_page_index ) + bitbucket_api_call, 'yellow' )
            if AUTH == AUTH_METHOD_UIDPWD:
                raw_request = requests.get( bitbucket_api_call, auth = HTTPBasicAuth( username, password ) )
            elif AUTH == AUTH_METHOD_OAUTH2:
                raw_request = requests.get( bitbucket_api_call, headers = bitbucket_api_oauth2_header_with_token( oauth_token ) )
            statuscode = raw_request.status_code
        except Exception as e:
            error_msg = 'BITBUCKET: CONNECTION FAILED. — HTTP STATUS CODE: {}'.format( str(statuscode) )
            printstyled( error_msg, 'red' )
            if backup:
                slack_send_message_of_category( error_msg, 'fail' )
            raw_request.raise_for_status()

        values = None
        try:
            dict_request = json.loads( raw_request.content.decode('utf-8') )
            # NOW COLLECT REPO INFO
            values = dict_request['values']
        except Exception as e:
            error_msg = 'BITBUCKET: API FAILED TO DELIVER EXPECTED REPO-DATA: {}'.format( raw_request.content.decode('utf-8') )
            printstyled( error_msg, 'red' )
            exit_with_code( 11, raw_request.content.decode('utf-8') )

        index = 0
        index_offset = (current_page_index - 1) * pagelen
        while index < len( values ) :
            current_value = values[ index ]
            index += 1
            current_repo_slug = current_value['slug']
            # printstyled( "{}. {}".format( (index_offset+index), current_repo_slug), 'green' )
            repos.append( current_value )
        current_page_index += 1
    return repos


def bitbucket_estimated_size_repos( repos ):
    aggregated_size_in_bytes = 0
    for repo in repos:
        # print( 'REPO: {} — {} — {}'.format( repo['name'], repo['utc_last_updated'], repo['size'] ) )
        aggregated_size_in_bytes += int( repo['size'] )
    #print( 'OVERALL ESTIMATED SIZE: {} bytes ( {} )'.format( aggregated_size_in_bytes, sizeof_fmt( aggregated_size_in_bytes ) ) )
    return aggregated_size_in_bytes

# Repo object properties delivered by api call
'''
FROM API 1.0 WE GET
{
'scm': 'git', 'has_wiki': False, 'last_updated': '2018-12-06T09:59:18.743', 'no_forks': False, 'created_on': '2018-01-31T10:39:25.346',
'owner': 'openreply-de', 'logo': 'https://bytebucket.org/ravatar/%7B4e6450b8-fc69-40ad-b523-bc089a0a4066%7D?ts=default',
'email_mailinglist': '', 'is_mq': False, 'size': 62957, 'read_only': False, 'fork_of': None, 'mq_of': None, 'state': 'available',
'utc_created_on': '2018-01-31 09:39:25+00:00', 'website': '', 'description': '', 'has_issues': False, 'is_fork': False, 'slug': 'obi-companion-be-systemtest',
'is_private': True, 'name': 'obi-companion-be-systemtest', 'language': '', 'utc_last_updated': '2018-12-06 08:59:18+00:00',
'no_public_forks': True, 'creator': None, 'resource_uri': '/api/1.0/repositories/openreply-de/obi-companion-be-systemtest'
}
'''

# ANALYZE EXISTING LOCAL REPOSITORIES COMPARED TO REMOTE REPOSITORIES (SAME DAY)
def bitbucket_analyze( repos ):
    counted = 0
    counted_done = 0
    counted_fail = 0
    counted_sync = 0
    if not os.path.exists( BACKUP_ROOT_DIRECTORY ):
        printstyled( 'BACKUP: ROOT DIRECTORY NOT FOUND {}'.format( BACKUP_ROOT_DIRECTORY ), 'red', 'bold' )
        return

    # check if enough free space on volume available
    estimated_size_bytes = bitbucket_estimated_size_repos( repos )
    estimated_five_times = estimated_size_bytes * 5
    available_size_bytes = get_fs_freespace( BACKUP_ROOT_DIRECTORY )
    minimum_size_bytes = BACKUP_MIN_FREESPACE_GIGA * 1024 * 1024 * 1024

    # check if minimum of free space available on volume will be sufficient
    if available_size_bytes - estimated_size_bytes < minimum_size_bytes:
        printstyled( 'BACKUP: NOT ENOUGH FREE SPACE ON VOLUME {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ), sizeof_fmt( minimum_size_bytes ) ), 'red', 'bold')
    else:
        if available_size_bytes - estimated_five_times < minimum_size_bytes:
            printstyled( 'BACKUP: FREE SPACE ON VOLUME RUNNING LOW {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ) , sizeof_fmt( minimum_size_bytes ) ), 'magenta', 'bold')
        else:
            printstyled( 'BACKUP: FREE SPACE ON VOLUME {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ), sizeof_fmt( minimum_size_bytes ) ), 'green', 'bold')


    BACKUP_LOCAL_PATH =  os.path.abspath( os.path.join( BACKUP_ROOT_DIRECTORY, BACKUP_ARCHIVE_DIRECTORY ) )
    printstyled( 'BACKUP: CHECKING... {} FOR BACKUP... {}'.format( BACKUP_ROOT_DIRECTORY, BACKUP_ARCHIVE_DIRECTORY ), 'cyan' )
    if os.path.exists( BACKUP_LOCAL_PATH ):
        printstyled( 'BACKUP: DIRECTORY OK {}'.format( BACKUP_LOCAL_PATH ), 'cyan', 'bold' )
    else:
        printstyled( 'BACKUP: DIRECTORY MISSING {}'.format( BACKUP_LOCAL_PATH ), 'cyan', 'bold' )

    printstyled( 'BACKUP: ESTIMATED STORAGE SIZE NEEDED {} ({} bytes)'.format( sizeof_fmt( estimated_size_bytes ), estimated_size_bytes ), 'white' )

    for repo in repos:
        repo_slug = repo['slug']
        BACKUP_LOCAL_REPO_PATH = os.path.abspath( os.path.join( BACKUP_LOCAL_PATH, repo_slug ) )

        if os.path.exists( BACKUP_LOCAL_REPO_PATH ) and repo_status_is( BACKUP_LOCAL_REPO_PATH, STATUS_DONE ):
            printstyled( 'SECURED: {}'.format( repo_slug ), 'green' )
            counted_done += 1
        else:
            if os.path.exists( BACKUP_LOCAL_REPO_PATH ) or repo_status_is( BACKUP_LOCAL_REPO_PATH, STATUS_SYNC ):
                printstyled( 'ABORTED: {}'.format( repo_slug ), 'yellow' )
                counted_sync += 1
            else:
                printstyled( 'MISSING: {}'.format( repo_slug ), 'red' )
                counted_fail += 1
        counted += 1
    printstyled( "BACKUP: ANALYZED \'{}\'.".format( BACKUP_ARCHIVE_DIRECTORY ), 'cyan' )
    printstyled( 'DONE: {} repos already existing'.format( counted_done ), 'green')
    printstyled( 'SYNC: {} repos incomplete'.format( counted_sync ), 'yellow')
    printstyled( 'FAIL: {} repos new/missing'.format( counted_fail ), 'red' )
    stats_string = backup_archive_system_stats()
    printstyled( '{}'.format( stats_string ), 'white' )

# CLONE REPOSITORIES FROM BITBUCKET TO LOCAL STORAGE FOLDER
def bitbucket_clone( repos ):
    i = 1
    repos_failed = []
    repos_done = []
    success_clone = 0
    BACKUP_LOCAL_PATH =  os.path.abspath( os.path.join( BACKUP_ROOT_DIRECTORY, BACKUP_ARCHIVE_DIRECTORY ) )
    printstyled( 'BACKUP: CHECKING... {} FOR BACKUP... {}'.format( BACKUP_ROOT_DIRECTORY, BACKUP_ARCHIVE_DIRECTORY ), 'cyan' )

    ensure_directory_exists( BACKUP_LOCAL_PATH )

    # check if enough free space on volume available
    estimated_size_bytes = bitbucket_estimated_size_repos( repos )
    estimated_five_times = estimated_size_bytes * 5
    available_size_bytes = get_fs_freespace( BACKUP_ROOT_DIRECTORY )
    minimum_size_bytes = BACKUP_MIN_FREESPACE_GIGA * 1024 * 1024 * 1024

    # check if minimum of free space available on volume will be sufficient
    # cloning will NOT take place if the amount of space left after the backup would be lower than defined
    if available_size_bytes - estimated_size_bytes < minimum_size_bytes:
        printstyled( 'BACKUP: NOT ENOUGH FREE SPACE ON VOLUME {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ), sizeof_fmt( minimum_size_bytes + estimated_size_bytes ) ), 'red', 'bold')
        exit_msg = 'Space left on volume is {}, but we need at least {}.'.format( sizeof_fmt( available_size_bytes ), sizeof_fmt( minimum_size_bytes + estimated_size_bytes ) )
        exit_with_code( 5, exit_msg )
    else:
        if available_size_bytes - estimated_five_times < minimum_size_bytes:
            printstyled( 'BACKUP: FREE SPACE ON VOLUME RUNNING LOW {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ) , sizeof_fmt( minimum_size_bytes + estimated_size_bytes ) ), 'magenta', 'bold')
            slack_msg = 'Free space on volume is running low. We have only left {} and backups will fail if we fall below {}'.format( sizeof_fmt( available_size_bytes ) , sizeof_fmt( minimum_size_bytes + estimated_size_bytes ) )
            slack_send_message_of_category( slack_msg, 'warn' )
        else:
            printstyled( 'BACKUP: FREE SPACE ON VOLUME {} / NEEDED {}'.format( sizeof_fmt( available_size_bytes ), sizeof_fmt( minimum_size_bytes + estimated_size_bytes ) ), 'green', 'bold')

    # fetch before we overwrite old information
    num_of_repos_lastrun = backup_archive_num_of_repos_lastrun()

    # mark last run date and time for future date time context validations
    backup_archive_save_lastrun( len( repos ), estimated_size_bytes )

    printstyled( 'BACKUP: ESTIMATED STORAGE SIZE NEEDED {} ({} bytes)'.format( sizeof_fmt( estimated_size_bytes ), estimated_size_bytes ), 'white' )

    for repo in repos:
        repo_slug = repo['slug']
        BACKUP_LOCAL_REPO_PATH = os.path.abspath( os.path.join( BACKUP_LOCAL_PATH, repo_slug ) )

        # STEP 1: check if repo marked as SYNC/FAIL
        # STEP 2: remove repo folder and tags
        # STEP 3: add SYNC and go
        print( 'Cloning repo {} of {}. — {}'.format(i, len(repos), repo_slug) )
        if repo_status_is( BACKUP_LOCAL_REPO_PATH, STATUS_SYNC ) or repo_status_is( BACKUP_LOCAL_REPO_PATH, STATUS_FAIL ):
            try:
                shutil.rmtree( BACKUP_LOCAL_REPO_PATH )
            except:
                printstyled( 'ERROR REMOVING DIRECTORY: {}'.format( BACKUP_LOCAL_REPO_PATH ), 'red' )
            mark_repo_clear( BACKUP_LOCAL_REPO_PATH )

        if os.path.exists( BACKUP_LOCAL_REPO_PATH ):
            printstyled( 'Skipping repo {} of {} because path {} exists'.format(i, len(repos), BACKUP_LOCAL_REPO_PATH ), 'white' )
            success_clone = success_clone + 1
            repos_done.append( repo )
        else:
            num_of_tries = 0
            was_cloning_fail = True
            while was_cloning_fail and num_of_tries <= retry_limit:
                if num_of_tries > 0:
                    printstyled( 'RETRYING: Try #{} of {} to clone repo.'.format( (num_of_tries+1), retry_limit ), 'magenta' )
                num_of_tries +=1
                mark_repo_sync( BACKUP_LOCAL_REPO_PATH )
                try:
                    REMOTE_REPO_PATH = 'git@bitbucket.org:{}/{}.git'.format( CONFIG_TEAM, repo_slug)
                    # --no-single-branch Option added will backup all branches
                    if BACKUP_ALL_BRANCHES:
                        current_repo = Repo.clone_from( REMOTE_REPO_PATH, BACKUP_LOCAL_REPO_PATH, no_single_branch=True )
                    else:
                        current_repo = Repo.clone_from( REMOTE_REPO_PATH, BACKUP_LOCAL_REPO_PATH )

                    was_cloning_fail = False
                    success_clone = success_clone + 1
                    repos_done.append( repo )
                    mark_repo_done( BACKUP_LOCAL_REPO_PATH )
                except Exception as e:
                    mark_repo_fail( BACKUP_LOCAL_REPO_PATH, str( e ) )
                    was_cloning_fail = True
                    printstyled( 'Unable to clone repo {}. Exception: {}'.format( repo_slug, e ), 'red' )
            if was_cloning_fail:
                repos_failed.append( repo )
        i = i + 1
    printstyled( 'Successfully cloned {} out of {} repos'.format(success_clone, len(repos)), 'blue')
    printstyled( "BACKUP: COMPLETE FOR \'{}\'.".format( BACKUP_ARCHIVE_DIRECTORY ), 'cyan' )
    stats_string = backup_archive_system_stats()
    printstyled( '{}'.format( stats_string ), 'white' )

    # list of failed repos
    slack_repos_failed_list = 'Following repos failed to backup:\n'
    for current_repo in repos_failed:
        current_repo_size = sizeof_fmt( int( current_repo['size'] ) )
        slack_repos_failed_list += ' - ' + current_repo['name'] + ' (Size: ' + current_repo_size + ')' + '\n'

    days_archived = backup_archive_days_archived( BACKUP_STORE_DAYS )

    slack_msg = 'bbbackup {} build {}\n'.format( APP_VERSION, APP_BUILD )
    slack_msg += 'Backup of {} repos completed.\n'.format( len( repos ) )
    slack_msg += 'We keep backups for up to {} days into the past.\n'.format( BACKUP_STORE_DAYS )
    slack_msg += 'We have build up an archive which now stores {} full days.\n'.format( days_archived )
    slack_msg += '```' + stats_string + '```'
    slack_send_message_of_category( slack_msg, 'ok' )

    failed_repos = len( repos ) - success_clone
    if failed_repos > 0 and failed_repos <= warning_limit:
        slack_send_message_of_category( 'There were {} of {} repos which failed to backup.\n```{}```'.format( str( failed_repos ), str( len( repos ) ), slack_repos_failed_list ), 'warn' )
    if failed_repos > warning_limit and failed_repos <= len( repos ):
        slack_send_message_of_category( '{} of {} repos failed to backup.\n```{}```'.format( str( failed_repos ), str( len( repos ) ), slack_repos_failed_list ), 'fail' )

    if num_of_repos_lastrun:
        diff = len( repos ) - num_of_repos_lastrun
        if diff < 0: # repos were deleted
            slack_send_message_of_category( 'There were only {} repos instead of {} repos the last time we backed up.'.format( len( repos ), num_of_repos_lastrun ), 'warn' )

'''
**********************************
*** MAIN
**********************************
'''
# ENABLE SIG INTERRUPT HANDLING
signal.signal( signal.SIGINT, signal_handler )

# PARSE INPUT ARGUMENTS
examples = 'HOW TO USE THIS APP\n'
examples += '(1)\n'
examples += 'Run bbbackup.py locally with parameters --config-oauth2, --config-bitbucket and --config-slack\n'
examples += 'to configure BitBucket user/team, OAuth config and Slack config.\n\n'
examples += '(2)\n'
examples += 'Then run bbbackup.py with --filepath to check if the connection to BitBucket works\n'
examples += 'e.g. bbbackup.py --filepath $PWD/mybackups\n\n'
examples += '(3)\n'
examples += 'If everything worked, export the configuration by entering:\n'
examples += 'bbbackup.py --filepath $PWD/mybackups --config-export --oauth2\n'
examples += 'this creates the file \'{}\' to use in any non local OS env\n\n'.format( APP_CONFIG_FILE )
examples += '(4)\n'
examples += 'You can now take this file and move it anywhere, e.g. a Docker environment\n'
examples += 'Just run bbbackup.py --configuration {} --backup --notify\n'.format(APP_CONFIG_FILE )
examples += 'this will use the config file, start a backup and notify/report progress via slack\n\n'
parser = argparse.ArgumentParser( description='{}\nbbbackup - clone all repos from a given BitBucket team/user\n\n{}'.format( APP_LOGO.format( APP_VERSION ), APP_COPYRIGHT_NOTICE ),
    epilog = examples, formatter_class=RawTextHelpFormatter)

main_parser = parser.add_mutually_exclusive_group( required=False )
main_parser.add_argument('-f', '--filepath', dest='filepath', required=False, help='Absolute path to a directory which will hold the managed backups')
main_parser.add_argument('-c', '--configuration', dest='configfile', required=False, help='Absolute path to configuration file where all necessary parameters are kept\n*** WARNING: WILL OVERRIDE ALL COMMANDLINE ARGUMENTS LISTED HERE! ***')
parser.set_defaults( filepath=None )
parser.set_defaults( configfile=None )

#parser.add_argument('-f', '--filepath', dest='filepath', required=True, help='Absolute path to a directory which will hold the managed backups')
#parser.add_argument('-c', '--configuration', dest='configfile', required=False, help='Name of configuration file where all kind of parameters are kept\nWARNING: this will override/ignore all other commandline parameters')
parser.add_argument('-a', '--analyze', dest='date', required=False, help='Analyze backup for certain day/date/timestamp, e.g. YYYY-MM-DD', type=lambda s: datetime.strptime(s, '%Y-%m-%d') )
parser.add_argument('-m', '--message-slack', dest='messageslack', required=False, help='Send a testmessage as string via slack', type=str)

parser.add_argument('-d', '--days', dest='days', required=False, help='Maximum amount of days into the past we keep backups\n[DEFAULT = {}]'.format( DEFAULT_BACKUP_STORE_DAYS ), default=DEFAULT_BACKUP_STORE_DAYS, type=int)
parser.set_defaults( days = DEFAULT_BACKUP_STORE_DAYS )

parser.add_argument('-s', '--storagelimit', dest='storagelimit', required=False, help='Minimum amount of free space in gigabytes on volume\n[DEFAULT = {}]'.format( BACKUP_MIN_FREESPACE_GIGA ), default=BACKUP_MIN_FREESPACE_GIGA, type=int)
parser.set_defaults( storagelimit = BACKUP_MIN_FREESPACE_GIGA )

parser.add_argument('-r', '--retry-limit', dest='retry_limit', required=False, help='Number of attempts to clone repository that failed on first try\n[DEFAULT = {}]'.format( BACKUP_MAX_RETRIES ), type=int)
parser.set_defaults( retry_limit = BACKUP_MAX_RETRIES )

parser.add_argument('-w', '--warning-limit', dest='warning_limit', required=False, help='Amount of failed repos allowed before we assume failure\n[DEFAULT = {}]'.format( BACKUP_MAX_FAILS ), type=int)
parser.set_defaults( warning_limit = BACKUP_MAX_FAILS )


backup_parser = parser.add_mutually_exclusive_group( required=False )
backup_parser.add_argument( '--backup', dest='backup', action='store_true', help='Will start/continue a full backup' )
backup_parser.add_argument( '--no-backup', dest='backup', action='store_false', help='[DEFAULT] Will analyze existing backup' )
parser.set_defaults( backup=False )

retry_parser = parser.add_mutually_exclusive_group( required=False )
retry_parser.add_argument( '--retry', dest='retry', action='store_true', help='[DEFAULT] Retry failed backup automatically' )
retry_parser.add_argument( '--no-retry', dest='retry', action='store_false', help='Do NOT retry to accomplish failed backups' )
parser.set_defaults( retry=True )

oauthconf_parser = parser.add_mutually_exclusive_group( required=False )
oauthconf_parser.add_argument( '--config-oauth2', dest='oauthconfig', action='store_true', help='Reset/configure oauth credentials (key/secret/app-name)' )
oauthconf_parser.add_argument( '--no-config-oauth2', dest='oauthconfig', action='store_false', help='[DEFAULT] Do not reset oauth credentials' )
parser.set_defaults( oauthconfig=False )

feature_parser = parser.add_mutually_exclusive_group( required=False )
feature_parser.add_argument( '--config-bitbucket', dest='credconfig', action='store_true', help='Configure/reset the stored credentials for BitBucket uid, team, password' )
feature_parser.add_argument( '--no-config-bitbucket', dest='credconfig', action='store_false', help='[DEFAULT] By default no configuration or reset of credentials' )
parser.set_defaults( credconfig=False )

slack_parser = parser.add_mutually_exclusive_group( required=False )
slack_parser.add_argument( '--config-slack', dest='slackconfig', action='store_true', help='Reset/configure slack credentials' )
slack_parser.add_argument( '--no-config-slack', dest='slackconfig', action='store_false', help='[DEFAULT] Do not reset slack credentials' )
parser.set_defaults( slackconfig=False )

notify_parser = parser.add_mutually_exclusive_group( required=False )
notify_parser.add_argument('--notify', dest='notify_mode', action='store_true', required=False, help='Notify on certain events via slack if configured')
notify_parser.add_argument('--no-notify', dest='notify_mode', action='store_false', required=False, help='[DEFAULT] Avoid notification via slack even if configured')
parser.set_defaults( notify_mode = False )

oauth_parser = parser.add_mutually_exclusive_group( required=False )
oauth_parser.add_argument('--oauth2', dest='oauth_mode', action='store_true', required=False, help='Authorize using OAuth 2.0')
oauth_parser.add_argument('--no-oauth2', dest='oauth_mode', action='store_false', required=False, help='[DEFAULT] Authorize with HTTPBasicAuth UserID/Password')
parser.set_defaults( oauth_mode = False )

configimport_parser = parser.add_mutually_exclusive_group( required=False )
configimport_parser.add_argument('--config-import', dest='config_import_mode', action='store_true', required=False, help='Read/import current parameters from file \'{}\'\nThis will set the OAUTH, ACCOUNT & SLACK info for the current runtime context, to check the values'.format( APP_CONFIG_FILE ) )
configimport_parser.add_argument('--no-config-import', dest='config_import_mode', action='store_false', required=False, help='[DEFAULT] Do not import context from a config file')
parser.set_defaults( config_import_mode = False )

configexport_parser = parser.add_mutually_exclusive_group( required=False )
configexport_parser.add_argument('--config-export', dest='config_export_mode', action='store_true', required=False, help='Write/export current context and parameters to file \'{}\'\nThis will create a config-file where OAUTH, ACCOUNT & SLACK info is stored/exported'.format( APP_CONFIG_FILE ) )
configexport_parser.add_argument('--no-config-export', dest='config_export_mode', action='store_false', required=False, help='[DEFAULT] Do not export context as a config file')
parser.set_defaults( config_export_mode = False )

log_parser = parser.add_mutually_exclusive_group( required=False )
log_parser.add_argument('--log', dest='log_mode', action='store_true', required=False, help='[DEFAULT] Send log output to tty')
log_parser.add_argument('--no-log', dest='log_mode', action='store_false', required=False, help='Avoid any log output to tty')
parser.set_defaults( log_mode = True )

colors_parser = parser.add_mutually_exclusive_group( required=False )
colors_parser.add_argument('--colors', dest='colorized_mode', action='store_true', required=False, help='[DEFAULT] Colorize log output with ANSI code')
colors_parser.add_argument('--no-colors', dest='colorized_mode', action='store_false', required=False, help='Do not colorize log output with ANSI code')
parser.set_defaults( colorized_mode = True )


args = parser.parse_args()

backup = args.backup
credconfig = args.credconfig
slackconfig = args.slackconfig
oauthconfig = args.oauthconfig
message_slack = args.messageslack
date_analyze = args.date
notify_mode = args.notify_mode
retry_mode = args.retry
oauth_mode = args.oauth_mode
retry_limit = args.retry_limit
warning_limit = args.warning_limit
log_mode = args.log_mode
colorized_mode = args.colorized_mode
config_export_mode = args.config_export_mode
config_import_mode = args.config_import_mode
config_from_file = args.configfile
filepath_backup_dir = args.filepath

# START
printstyled( 'BACKUP: WELCOME.', 'cyan' )

is_interactive = is_running_interactively()

launchtime = datetime.now()
printstyled( 'STARTED: ' + str( launchtime ), 'yellow', 'bold' )

print( APP_LOGO.format( APP_VERSION ) )

if config_import_mode:
    configuration_import()
    configuration_print()
    exit_with_code( 9 )

# EVALUATE CMD-LINE-PARAMS INTO VARIABLES (USE DEFAULT VALUES WHERE NECESSARY)
if args.days < BACKUP_STORE_MIN_DAYS:
    BACKUP_STORE_DAYS = BACKUP_STORE_MIN_DAYS
else:
    BACKUP_STORE_DAYS = args.days

if args.storagelimit <= 0:
    BACKUP_MIN_FREESPACE_GIGA = 1 # never use less than minimum of 1 Gigabyte free space
else:
    BACKUP_MIN_FREESPACE_GIGA = args.storagelimit

if retry_limit:
    BACKUP_MAX_RETRIES = retry_limit

if warning_limit:
    BACKUP_MAX_FAILS = warning_limit

LOG_OUTPUT = log_mode
LOG_COLORIZED = colorized_mode

# EVALUATE CMD-LINE-PARAMS INTO ACTIONS
if oauthconfig:
    oauth_config_reset()

if slackconfig:
    slack_config_reset()

if credconfig:
    bitbucket_config_reset()

if not config_from_file:
    if oauth_mode:
        AUTH = AUTH_METHOD_OAUTH2
        oauth_config_load( True )
    else:
        AUTH = AUTH_METHOD_UIDPWD
        bitbucket_config_load( True )
    # load always
    oauth_config_load( False )
    bitbucket_config_load( False )
    if notify_mode:
        slack_config_load( True )
    else:
        slack_config_load( False )

if not CONFIG_TEAM:
    CONFIG_TEAM = CONFIG_UID

if filepath_backup_dir:
    BACKUP_ROOT_DIRECTORY = filepath_backup_dir

if config_export_mode:
    configuration_print()
    configuration_export()
    exit_with_code( 8 )

if not config_from_file: # THEN CHECK CONFIG FROM FILEPATH PARAMETER
    if not filepath_backup_dir or len( filepath_backup_dir ) == 0:
        printstyled( "WARNING: The given FILEPATH for archiving backups was missing or invalid.", 'red' )
        exit_with_code( 7 )
    else:
        BACKUP_ROOT_DIRECTORY = filepath_backup_dir

# WARNING: THIS WILL OVERRIDE ALL PREVIOUS CONFIG FROM COMMANDLINE
if config_from_file:
    CONFIG_FILE_PATH = APP_PATH+'/'+APP_CONFIG_FILE
    printstyled( 'CONFIG: USING \'{}\' AS CONFIG...'.format( CONFIG_FILE_PATH ), 'cyan' )
    if not os.path.exists( CONFIG_FILE_PATH ):
        printstyled( 'CONFIG: ERROR, CONFIGURATION DOES NOT EXIST.', 'red' )
        exit_with_code( 10, "Exited because we have no valid configuration" )
    else:
        configuration_import()

# BEGIN OF MAIN
if __name__ == '__main__':

    if SLACK_CHANNEL and SLACK_API_TOKEN:
        printstyled( 'SLACK: CONFIGURATION ...', 'cyan' )
        printstyled( 'CHANNEL: {}'.format( SLACK_CHANNEL ), 'blue' )
        printstyled( '  TOKEN: {}'.format( SLACK_API_TOKEN ), 'blue' )

    if message_slack and len( str( message_slack ) ) > 0:
        slack_send_message_to_channel( message_slack, SLACK_CHANNEL )

    try:
        operation_mode_str = "BACKUP" if (backup == True) else "ANALYZE"
        printstyled( 'BITBUCKET: CONNECTING TO {}...'.format( operation_mode_str ), 'cyan' )
        if AUTH == AUTH_METHOD_UIDPWD:
            printstyled( '   USER: {}'.format( CONFIG_UID ), 'blue' )
            printstyled( '   TEAM: {}'.format( CONFIG_TEAM ), 'blue' )
        elif AUTH == AUTH_METHOD_OAUTH2:
            printstyled( '   NAME: {}'.format( OAUTH_CLIENT_NAME ), 'blue' )
            printstyled( '    KEY: {}'.format( OAUTH_CLIENT_KEY_OR_ID ), 'blue' )
            printstyled( ' SECRET: {}'.format( OAUTH_CLIENT_SECRET ), 'blue' )

        repos = None
        if API_USED == '1.0':
            repos = bitbucket_api_get_repos_10( CONFIG_UID, CONFIG_PWD, CONFIG_TEAM )
        elif API_USED == '2.0':
            repos = bitbucket_api_get_repos_20( CONFIG_UID, CONFIG_PWD, CONFIG_TEAM )
        printstyled( 'BITBUCKET: {} REPOS FETCHED.'.format( str( len( repos ) ) ), 'green' )

    except Exception as e:
        printstyled( 'BITBUCKET: COULD NOT FETCH REPOS. {}\n{}'.format( e, sys.exc_info() ), 'red' )
        traceback.print_exc()
        exit_msg = 'Exception while we tried to connect: {}'.format( e )
        exit_with_code( 3, exit_msg )

    now = datetime.now().utcnow()
    BACKUP_ARCHIVE_DIRECTORY = backup_archive_name_for_datetime_utc( now )

    printstyled( "BACKUP: LIMITED AMOUNT OF DAYS STORED ARE {}.".format( str( BACKUP_STORE_DAYS ) ), 'cyan')
    printstyled( "BACKUP: MINIMUM OF GIGABYTES KEPT FREE ON VOLUME {} GB.".format( str( BACKUP_MIN_FREESPACE_GIGA ) ), 'cyan')

    if backup:
        # cleanup before we download new stuff
        # only if we have a valid date and time context we will DELETE old backups
        if backup_archive_has_valid_time_context():
            printstyled( "BACKUP: ROTATION-CONTEXT VALID.", 'green')
            backup_archive_rotate_with_days( BACKUP_STORE_DAYS, BACKUP_STORE_DAYS + BACKUP_STORE_DAYS_SCOPE )
        else:
            printstyled( "BACKUP: ROTATION-CONTEXT: INVALID.", 'red')

        printstyled( "BACKUP: CLONING...", 'cyan')
        bitbucket_clone( repos )
    else:
        printstyled( "BACKUP: ANALYZING...", 'cyan')
        if date_analyze:
            print( 'BACKUP: FROM {}'.format( date_analyze.strftime( '%Y-%m-%d' ) ) )
            BACKUP_ARCHIVE_DIRECTORY = backup_archive_name_for_datetime_utc( date_analyze )
        bitbucket_analyze( repos )
    exit_with_code( 0 )
