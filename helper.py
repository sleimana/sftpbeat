#!/usr/bin/env python

"""helpr.py: standard Output/Alert/Error messages for the SFTPbeat service"""

__author__      = "Sleiman A."
__version__     = "v0.95"

def get_info(x):
	return {
		101:'[i] Source list loaded [%s]',
		701:'[<] Cycle started',
		702:'%d  files to fetch',
		703:'[*] File collected to: %s',
		704:'[*] File validation check OK',
		705:'[*] File signed OK',
		706:'[>] Cycle finished',
		707:'[!] File %s was not signed as configured',
		708:'[X] File %s was removed from the remote host',
		709:'[!] Got and signed %d files in total',
		801:'[i] Lock file is missing',
		802:'[i] Diary file is missing',
		1001:'[i] Lock file created %s',
		1401:'[i] Diary file created %s',
		1601:'[i] Diary updated',
		1602:'[i] Alert %s',
		2001:'[i] Move to warm storage OK.',
		2002:'[i] Copy to elasticsearch OK.',
		2003:'[i] Backup to remote storage OK.',
		2005:'[i] Deleted file [%s] from elasticsearch pool'
	}.get(x, '')
def get_error(x):
	return {
		501:'Error formatting dir',
		701:'[!] #201 File is empty %s - %s - %s',
		1001:'[!] Error: _build_lock %s',
		1501:'[!] Error: can not check file size %s',
		1701:'[!] Error: empty zip file %s',
		1702:'[!] Error: can not extract zip file %s',
		2001:'[!] Error: can not write to NFS partition: %s',
		2002:'[!] Error: can not move to NFS partition: %s',
		2003:'[!] Error: can not copy to elasticsearch dir %s',
		2004:'[!] Error: can not backup to remote storage %s',
		7001:'[!] Error: can not load ssh key %s',
		7002:'[!] Error: can not get the remote file [%s]: %s',
		7003:'[!] Error: can not get remove original file from host',
		8003:'[!] Error: can not get memory usage',
		8004:'[!] Error: can not get disk usage'
	}.get(x, '')

def get_warning(x):
	return {
		801:'[!] Diary file is corrupted',
		802:'[!] Repository file changed, update diary file',
		701:'[!] Could not open SFTP connection with [%s]',
		703:'[!] Log file [%s] from [%s] was not moved to ES',
		704:'[!] Log file [%s] from [%s] was not sent to Catania LC',
		705:'[!] Log file [%s] from [%s] was not moved to warm storage',
		706:'[!] Could not deleted file [%s] from elasticsearch pool: %s'
		
	}.get(x, '')
	
def get_debug(x):
	return {
		701:'[+] SFT connecting to: %s',
		702:'[-] Already connected to: %s',
		703:'[i] New file found in %s: %s',
		704:'[L] Num Files/Dirs: %d',
		705:'[C] Num Files To Fetch: %d',
		706:'[x] Closing connection with %s',
		707:'[x] Closing connection with the last socket %s',
		801:'[i] Repository file changed',
		1501:'[i] Diary file loaded %s',
		1601:'[i] Diary - changes in id %d',
		1602:'[i] Alert %s',
		1701:'[X] Removed %s from %s',
		1702:'[E] Extracting file %s',
		1703:'[E] %d file extracted, output %s',
		2001:'[=] Move (Copy) .log & .sig to warm storage [%s]',
		2002:'[=] Copy .log to elasticsearch pipeline %s',
		2003:'[=] backup .log & .sig to remote storage [%s]',
		2004:'[@] created dir [%s] under path [%s] on the remote server',
		2005:'[i] Cleaning elasticsearch pool'
		
	}.get(x, '')
	
def get_critical(x):
	return {
		101:'[!] #101 - Fatal Error - empty sources-list [%s]',
		102:'[!] #102 - Fatal Error - non valid source-list [%s]'
	}.get(x, '')

def get_alert(x):
	return {
		1601:'1601 - No logs from [%s] in the past %d hours for file [%s]',
		2001:'2001 - [%s] service is down on [%s]',
		701: '0701 - Zip file [%s] is empty or corrupted on %s (%s)',
		702: '0702 - Log file [%s] is empty on %s (%s)',
		703: '0703 - Log file [%s] from [%s] was not moved to ES',
		704: '0704 - Log file [%s] from [%s] was not sent to Catania LC',
		705: '0705 - Log file [%s] from [%s] was not moved to warm storage',
		4001:'4001 - %s service stopped on %s',
		4002:'4002 - Low memory on %s',
		4003:'4003 - Low disk space on partition %s on host %s'
		
	}.get(x, '')
