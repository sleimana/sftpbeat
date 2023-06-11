#!/usr/bin/env python2.7

__author__  = "Sleiman A."
__license__ = "GPL"
__email__   = "sleiman.ahmad@nttdata.com"
__version__ = '1.63'
__name__    = 'collector'

import paramiko, json, socket, datetime, locale, os, subprocess, glob, sys
import disigner
import helper, re, shutil, gzip
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from time import sleep, time
import logging, socket
from ConfigParser import SafeConfigParser
import crypt

CONF_FILE = '/etc/collector/collector.conf'
parser = None
logger = None
alerts = None

CONNECT_INTERVAL = None
DEBUG_LOGS = False

___SFTP_CALLBACK_FILE_INPROGRESS = ''
___SFTP_CALLBACK_FILE_LAST_HNDLD = ''

#QA - OK
def create_sftp_client (host, port, username, password, keyfilepath, keyfiletype):
	sftp = None
	key = None
	transport = None
	try:
		if keyfilepath is not None:
			# Get private key used to authenticate user.
			if keyfiletype == 'DSA':
                # The private key is a DSA type key.
				key = paramiko.DSSKey.from_private_key_file(keyfilepath)
			else:
                # The private key is a RSA type key.
				with open(keyfilepath, "r+") as f:
					key = paramiko.RSAKey.from_private_key(f)
        # Create Transport object using supplied method of authentication.
		transport = paramiko.Transport((host, port))
		transport.connect(None, username, password, pkey=key)
		sftp = paramiko.SFTPClient.from_transport(transport)
		return sftp
	except paramiko.ssh_exception.AuthenticationException as e:
		print 'Auth Err'
		##log
		return False
	except paramiko.ssh_exception as e:
		print 'SSH Err'
		##log
		return False
	except Exception as e:
		print('An error occurred creating SFTP client: %s: %s' % (e.__class__, e))
		if sftp is not None:
			sftp.close()
		if transport is not None:
			transport.close()
		##log
		return False

#QA - OK
def get_secure_connection (host, port, username, key, passwd = None):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		if passwd is None:
			ssh.connect(host, port, username, pkey = key, timeout=10)
			logger.info('[+] Connected to %s (key)' %host)
		else:
			ssh.connect(host, port, username, password = passwd, timeout=10)
			logger.info('[+] Connected to %s (pwd)' %host)

		return ssh
	except paramiko.ssh_exception.AuthenticationException as e:
		##log
		
		return -1, "Authentication Error %s@%s:%d" %(username, host, port)
	except paramiko.ssh_exception as e:
		##log
		
		return -2, "SSH Exception Error %s@%s:%d" %(username, host, port)
	except socket.timeout:
		##log
		
		return -3, "Connection Timeout %s@%s:%d" %(username, host, port)
	except paramiko.ssh_exception.BadHostKeyException as e:
		##log
		
		return -4, "Bad Key %s@%s:%d" %(username, host, port)
	except paramiko.ssh_exception.NoValidConnectionsError as e:
		##log
		
		return -5, "No Valid Connections Error %s@%s:%d" %(username, host, port)
	except Exception as e:
		logger.exception('could not connect')
		
		return -100, "General Exception %s@%s:%d" %(username, host, port)

#QA - 
def log (msg, type = 'ERROR'):
	if not DEBUG_LOGS:
		return
	with open('/tmp/_tst_collector_cstm_logs.txt', 'a+') as f:
		m = '%s | %s | %s\n' %(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), type, msg)
		f.write(m)

#QA - OK
def isEnabled(val):
	if val.lower().strip() == 'yes':
		return True
	return False
	
#QA - OK
def load_registry():
	REG_FILE = parser.get('Collector','source_list')
	hosts = []
	try:
		with open(REG_FILE, 'r') as f:
			hosts = f.readlines()
		hosts = [x.replace(' ', '') for x in hosts[1:-1]]
		logger.info(helper.get_info(101) %REG_FILE)
		if len(hosts) == 0:
			logger.critical(helper.get_critical(101) %REG_FILE)
			sys.exit(-1)
	except Exception as e:
		print str(e)
		logger.critical(helper.get_critical(102) %REG_FILE)
		sys.exit(-1)
	return hosts

#QA - OK
def build_repo(REPO_FILE):
	
	dic = {}
	with open(REPO_FILE, 'r') as f:
		hosts = f.readlines()
	hosts = [x.strip() for x in hosts[1:-1]]
	i = -1
	for host in hosts:
		i += 1
		_ip = host.split(',')[1]
		dic[i]["ip"] = _ip
	return dic

#QA - 
def load_json_reg():
	return

#QA - OK
def get_time_format(ndays = 2):
	try:
		ndays = int (parser.get('Collector','date_range'))
		if not ndays:
			ndays = 2
	except:
		ndays = 2
	locale.setlocale(locale.LC_TIME, "it_IT")
	possible_formats = ['%Y-%m_%d', '%Y-%m-%d', '%d%b%Y', '%Y_%m_%d', '%Y%m%d']
	possible_dates = []
	for format in possible_formats:	
		_date = [(datetime.datetime.now()-datetime.timedelta(days=x)).strftime(format) for x in range(0, ndays)]
		for x in _date:
			possible_dates.append(x)
		if format == '%d%b%Y':
			for y in range (0, ndays):
				_d = '%s%s' %(((datetime.datetime.now()-datetime.timedelta(days=y)).strftime(format))[:3].upper(), ((datetime.datetime.now()-datetime.timedelta(days=y)).strftime(format))[3:])
				possible_dates.append(_d)
	return possible_dates

#QA - OK
def get_expected_rfiles_perhost(file_prefix, ext):
	#SYS_SUDOuxstsa01_2020-04_16_1746.tar.Z
	if file_prefix is not None and ext is not None:
		return ['%s.*%s%s' %(file_prefix, x, ext) for x in get_time_format()]

#QA - OK
def get_files_of_interest(r_actuals, substrings):
	rfiles_of_interset = []
	for act in r_actuals:
		for sub in substrings:
			if re.search(sub, act):
				rfiles_of_interset.append(act)
	return rfiles_of_interset

#QA - OK
def get_local_dir(rootdir, hostname, system = 'sys'):
	try:
		now = datetime.datetime.now()
		year = now.strftime('%Y')
		month = now.strftime('%m')
		day = now.strftime('%d')
		dir =  '%s/%s/%s/%s/%s/%s/' %(rootdir, year, system.strip(), hostname, month, day)
		return dir
	except Exception as e:
		logger.exception(helper.get_error(501))


def process_file(tarfile, path = None, warm_path = None):


	if tarfile.endswith(".log"):
		return True 
	try:
		## init
		path += 'extract/'
		if not os.path.exists(path):
			os.makedirs(path)	
		## clean 
		files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
		if len(files) > 0:
			for file in files:
				os.remove(os.path.join(path, file))
				logger.debug(helper.get_debug('1701') %(file, path))
		## check
		retcode = subprocess.call(['tar', '-xvf', tarfile, '-C', path])
		logger.debug(helper.get_debug('1702') %tarfile)
		sleep(2)
		if retcode == 0:
			files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
			logger.debug(helper.get_debug('1703') %(len(files), files))
			if len(files) > 0:
				

				
				#Move to Warm
				return True
		return False
	except Exception as e:
		logger.exception('ERROR File Process: %s' %tarfile)

def unzipit(l_file):
	filepath = os.path.dirname(l_file)
	ret_filename = os.path.join(filepath, os.path.basename(l_file).replace('.gz','')) 
	## init
	filepath += '/extract/'
	if not os.path.exists(filepath):
		os.makedirs(filepath)
		
	try:
		with gzip.open(l_file, 'rb') as f_in:
			with open(ret_filename, 'wb') as f_out:
				shutil.copyfileobj(f_in, f_out)
				return ret_filename
	except Exception as e:
		logger.exception('ERROR unzipping %s' %file)
		return -1
		
#QA - OK
def extract_file(l_file):
		filepath = os.path.dirname(l_file)
		filename = os.path.basename(l_file)
		
		## dir to move the file after the extract 
		_parent_dir = filepath
		## init
		filepath += '/extract/'
		if not os.path.exists(filepath):
			os.makedirs(filepath)
			
		## clean 
		files = [f for f in os.listdir(filepath) if os.path.isfile(os.path.join(filepath, f))]
		if len(files) > 0:
			for file in files:
				os.remove(os.path.join(filepath, file))
				logger.debug(helper.get_debug(1701) %(file, filepath))
		## extract		
		retcode = subprocess.call(['tar', '-xvf', l_file, '-C', filepath])
		logger.debug(helper.get_debug(1702) %l_file)
		sleep(2)
		if retcode == 0:
			files = [f for f in os.listdir(filepath) if os.path.isfile(os.path.join(filepath, f))]
			logger.debug(helper.get_debug(1703) %(len(files), files))
			if len(files) > 0:
				log_file = files[0]
				logger.debug('log_file is: %s' %log_file)
				
				## move logfile from the extract dir to the parent dir
				_parent_path = os.path.join(_parent_dir, log_file)
				_extrac_path = os.path.join(filepath, log_file)
				shutil.copy(_extrac_path, _parent_path)
				
				logger.debug('log_file extraced to: %s' %_parent_path)
				return _parent_path

			else:
				logger.error(helper.get_error(1701) %l_file)
				return -2
		else:
			logger.error(helper.get_error(1702) %l_file)
			return -1

#QA - OK			
def is_log_file_empty(log_file):
	try:
		logger.debug('%s file size: %d' %(log_file, os.stat(log_file).st_size))
		return True if os.stat(log_file).st_size == 0 else False
	except:
		logger.exception(helper.get_error(1501) %log_file)

#QA - OK		
def move_to_warm(log_file, w_path, is_sig_included):

	try:
		if not os.path.exists(w_path):
			os.makedirs(w_path)
	except:
		logger.exception(helper.get_error(2001) %log_file)
		return False
	try:
		
	
		### move only .enc files, when exist
		encrypted_files = log_file + '.enc'
		if os.path.isfile(encrypted_files):
			shutil.copy(encrypted_files, os.path.join(w_path, os.path.basename(encrypted_files)))
			logger.debug('[w] Encrypted file moved to warm')
		else:
			### SAG, don't move to warm 
			logger.debug(helper.get_debug(2001) %(w_path))
			shutil.copy(log_file, os.path.join(w_path, os.path.basename(log_file)))
		### 
		
		if is_sig_included:
			sig_file = log_file + '.sig'
			shutil.copy(sig_file, os.path.join(w_path, os.path.basename(sig_file)))
		logger.info(helper.get_info(2001))
		return True
	except:
		logger.exception(helper.get_error(2002) %log_file)
		#logger.error('Error while move to warm storage')
#QA - OK		
def copy_to_es(log_file, es_path, str_logfile_pfx = ''):
	try:
		logger.debug(helper.get_debug(2002) %(es_path))
		shutil.copy(log_file, os.path.join(es_path, str_logfile_pfx + os.path.basename(log_file)))
		logger.info(helper.get_info(2002))
		
		return True

	except:
		logger.exception(helper.get_error(2003) %log_file)
		#logger.error('Error copy to elasticsearch')
#QA - OK		
def backup_to_remote_storage(log_file, backup_client, r_path, is_sig_included):
	global ___SFTP_CALLBACK_FILE_INPROGRESS
	if type(backup_client) is tuple and backup_client[0] < 0:
		## handle exception
		logger.warning(backup_client[1])
		return False

	def mkdir_p(sftp, remote_directory):
		'''Change to this directory, recursively making new folders if needed.
		Returns True if any folders were created.'''
		
		if remote_directory == '/':
			# absolute path so change directory to root
			sftp.chdir('/')
			return
		if remote_directory == '':
			# top-level relative directory must exist
			return
		try:
			sftp.chdir(remote_directory) # sub-directory exists
		except IOError:
			dirname, basename = os.path.split(remote_directory.rstrip('/'))
			mkdir_p(sftp, dirname) # make parent directories
			sftp.mkdir(basename) # sub-directory missing, so created it
			logger.debug(helper.get_debug(2004) %(basename, dirname))
			sftp.chdir(basename)
			return True
	
	try:
		logger.debug(helper.get_debug(2003) %(r_path))
		sftp_client = backup_client.open_sftp()
		mkdir_p(sftp_client, r_path)
		
		___SFTP_CALLBACK_FILE_INPROGRESS = log_file
		sftp_client.put(log_file, r_path + os.path.basename(log_file), callback=watch_progress)
		if is_sig_included:
			sig_file = log_file + '.sig'
			sftp_client.put(sig_file, r_path + os.path.basename(sig_file))
		backup_client.close()
		
		logger.info(helper.get_info(2003))
		return True
	except:
		logger.exception(helper.get_error(2004) %log_file)
#QA - OK	

def watch_progress(transferred, toBeTransferred):
	global ___SFTP_CALLBACK_FILE_LAST_HNDLD
	global ___SFTP_CALLBACK_FILE_INPROGRESS
	if ___SFTP_CALLBACK_FILE_INPROGRESS != ___SFTP_CALLBACK_FILE_LAST_HNDLD:
		logger.debug("[%] Started Transfer {0} KB".format(toBeTransferred/1024))
		___SFTP_CALLBACK_FILE_LAST_HNDLD = ___SFTP_CALLBACK_FILE_INPROGRESS
	return
    ##logger.debug("Transferred: {0}\tOut of: {1}".format(transferred, toBeTransferred))
	
def run():
	global ___SFTP_CALLBACK_FILE_INPROGRESS
	USER = parser.get('Collector','ssh_user')
	KEYP = parser.get('Collector','ssh_key')
	KEY_SIGN = parser.get('Signer','private_key')
	
	PORT = int(parser.get('Collector','ssh_port'))
	DIRL = parser.get('Collector','hot_dir')
	REGF = parser.get('Collector','source_list')
	
	DIRW = parser.get('NFS','warm_dir')
	isNFS = parser.get('NFS','enabled')
	
	## Legacy Windows Logs IDM 
	LEGACY_IP_LIST = get_conf_values('Collector', 'ip_list', 'Legacy windows list')
	LEGACY_AUTH_PW = parser.get('Collector','auth_pw')
	
	DEBUG_HOSTS = get_conf_values('Collector', 'debug_host', 'Debugging hosts')
	
	## ES CONFGI
	DIRES = parser.get('Elasticsearch','log_dir')
	isES = parser.get('Elasticsearch','enabled')
	##
	DR_IP = parser.get('DR','backup_collector')
	DR_PORT = int(parser.get('DR','ssh_port'))
	DR_USER = parser.get('DR','ssh_user')
	DR_KEY = parser.get('DR','ssh_key')
	DR_DIR = parser.get('DR','backup_dir')
	isDR = parser.get('DR','enabled')
	
	
	
	
	SSH_KEY = None
	DR_SSH_KEY = None
	try:
		with open(KEYP, "r+") as f:
			SSH_KEY = paramiko.RSAKey.from_private_key(f)
	except:
		logger.exception(helper.get_error(7001) %KEYP)
		
	try:
		with open(DR_KEY, "r+") as k:
			DR_SSH_KEY = paramiko.RSAKey.from_private_key(k)
	except:
		logger.exception(helper.get_error(7001) %DR_KEY)

	try:
		delete_original = True if (parser.get('Collector','delete_original').lower().strip() == 'yes') else False
	except:
		logger.exception('Error getting delete_original')
	
	
	logger.info(helper.get_info(701))	
	hosts = load_registry()
	num_hosts = len(hosts)
	now = datetime.datetime.now()

	logger.info(helper.get_info(702) %num_hosts)
	
	last_ip = None
	sshclient = None
	records_diary = []
	num_get = 0
	
	
	for host in hosts:
		hostname, ip, path, file_prefix, ext, system = host.split(',')
		## exceptions
		is_legacy = False ## Flag to delete file immediately from  legacy windows servers

		if ip != last_ip:
			## connect to the new host
			logger.debug(helper.get_debug(701) %ip)
			if ip in LEGACY_IP_LIST:
				sshclient = get_secure_connection(ip, PORT, USER, None, LEGACY_AUTH_PW)
				is_legacy = True
			else:
				sshclient = get_secure_connection(ip, PORT, USER, SSH_KEY, None)
				
			if type(sshclient) is tuple and sshclient[0] < 0:
				## handle exception
				logger.warning(sshclient[1])
				records_diary.append('%s, %s, %s' %(ip, file_prefix, sshclient[0]))
				continue
			records_line = ('%s, %s, %s' %(ip, '', _get_ts()))
		else:
			logger.debug(helper.get_debug(702) %ip)
		try:
			sftpclient = sshclient.open_sftp()
		except:
				logger.warning(helper.get_warning(701) %hostname)
				records_diary.append('%s, %s, %s' %(ip, file_prefix, '-200'))
				continue
		if (ip in LEGACY_IP_LIST or ip == '127.0.0.1' or ip in ['172.16.x.x', '20.x.x.x','10.x.x.x']): #quick fix for two single source 
			# added 10.10.10.10 @11022022
			sftpclient.chdir(path)
		

		r_files_found = sftpclient.listdir(path='.')
		logger.debug(helper.get_debug(704) %len(r_files_found))
		r_files_expected = get_expected_rfiles_perhost(file_prefix, ext='')
		r_files_of_interset = get_files_of_interest(r_files_found, r_files_expected)
		logger.debug(helper.get_debug(705) %len(r_files_of_interset))
		
		yesterday = 'dummy file.ext'
		if ip == '127.0.0.1':
			## get only files of yesterday
			yesterday = ((datetime.datetime.now()-datetime.timedelta(days=1)).strftime('%Y-%m-%d'))
			r_files_expected = [file for file in r_files_found if file.endswith(yesterday)]
			
		if ip in DEBUG_HOSTS:
			logger.debug ('CWD: %s' %sftpclient.getcwd())
			logger.debug('remote files found: %s' %(r_files_found))
			logger.debug('Expected files: %s' %(r_files_expected))
			logger.debug('Files of interset: %s' %(r_files_of_interset))
		if not len(r_files_of_interset) == 0:
			logger.debug(helper.get_debug(703) %(hostname, str(r_files_of_interset)))
			for r_file in r_files_of_interset:
				l_path = get_local_dir(DIRL, hostname, system = system if (system and system != '') else 'sys')
				if not os.path.exists(l_path):
					os.makedirs(l_path)
				l_file = os.path.join(l_path, r_file)
				try:
					___SFTP_CALLBACK_FILE_INPROGRESS = l_file
					sftpclient.get(r_file, l_file, callback = watch_progress)
					sleep(10)
					logger.info(helper.get_info(703) %l_file)	
					log("%s, %s, %s, %s, %s" %(system, hostname, ip, r_file, l_file), type = 'GET')
				except Exception as e:
					logger.error(helper.get_error(7002) %(r_file, str(e)))
					logger.warning('file was skipped %s' %r_file)
					continue
					
				### validate file [compression, size] before signing
				signer_exclude = get_conf_values('Signer', 'exclude', 'Signer Exclude')
				if ip in signer_exclude:
					## snodo file don't extract and don't sign
					log_file = l_file
				else:
					## .log .txt file
					NO_EXTRACT = ('.log', '.txt', yesterday)
					
					if l_file.endswith(NO_EXTRACT):
						log_file = l_file
					## zip file
					elif l_file.endswith('.gz'):
						## unzip file
						log_file = unzipit(l_file)
						if log_file < 0:
							alerts.critical(helper.get_alert(701) %(r_file, hostname, ip))
					else:
						## tar.GZ
						log_file = extract_file(l_file)
						if log_file < 0:
							alerts.critical(helper.get_alert(701) %(r_file, hostname, ip))
				## empty content 		
				if is_log_file_empty(log_file):
					alerts.critical(helper.get_alert(702) %(r_file, hostname, ip))
					logger.warning(helper.get_alert(702) %(r_file, hostname, ip))
					#log_file = l_file #QA: useless here
				## normal logfile .log or zipped
				try:
					## proceed
					logger.info(helper.get_info(704))
					backup_signature = False ## exception when no .sig is generated
					if signer_exclude and ip not in signer_exclude:
						if disigner.sign_file(log_file, key = KEY_SIGN):
							logger.info(helper.get_info(705))
							backup_signature = True
						else:
							logger.info(helper.get_info(707) %log_file)
					
					## Encrypt Files (SAG)
					if ip in ['192.x.x.x','192.x.x.x', '20.x.x.x']:
						
						crypt.encrypt_file(log_file)
						logger.info('file %s has been encrypted' %log_file)

					## copy to the elasticsearch dir. don't send non raw 
					if isEnabled(isES) and log_file.endswith('.log') or log_file.endswith(yesterday):
						if not copy_to_es(log_file, DIRES, str_logfile_pfx = '%s_%s_' %(system.strip() if (system and system != '') else 'sys', hostname)):
							logger.warning(helper.get_warning(703) %(log_file, hostname))
							alerts.critical(helper.get_alert(703) %(log_file, hostname))
					
					## copy to catania
					if isEnabled(isDR):
						backup_client = get_secure_connection(DR_IP, DR_PORT, DR_USER, DR_SSH_KEY, None)
						r_path = get_local_dir(DR_DIR, hostname, system = system if (system and system != '') else 'sys')		
						if not backup_to_remote_storage(log_file, backup_client, r_path, backup_signature):
							logger.warning(helper.get_warning(704) %(log_file, hostname))
							alerts.critical(helper.get_alert(704) %(log_file, hostname))
						
					## copy to warm
					if isEnabled(isNFS):
						w_path = get_local_dir(DIRW, hostname, system = system if (system and system != '') else 'sys')						
						if not move_to_warm(log_file, w_path, backup_signature):
							logger.warning(helper.get_warning(705) %(log_file, hostname))
							alerts.critical(helper.get_alert(705) %(log_file, hostname))
					
					records_diary.append('%s, %s, %s' %(ip, file_prefix, _get_ts()))

					logger.debug("[x] Enable removing from the remote host")	
					if (delete_original):
						try:
							sftpclient.remove(r_file)
							logger.info(helper.get_info(708) %r_file)
						except:
							logger.exception(helper.get_info(7003))
				except:
					logger.exception('General Error')
				records_diary.append('%s, %s, %s' %(ip, file_prefix, _get_ts()))
				num_get += 1
				# else:
					# logger.error(helper.get_error(701) %(r_file, hostname, ip))					
		else:
			records_diary.append('%s, %s, %s' %(ip, file_prefix, ''))
		
		
		## close the previous socket file
		_IDX_CUR_HOST = hosts.index(host)
		if _IDX_CUR_HOST < len(hosts) - 1:
			a, next_ip, b, c, d, e = hosts[_IDX_CUR_HOST+1].split(',')
			if ip != next_ip:
				logger.debug(helper.get_debug(706)%ip)
			#logger.debug(helper.get_debug(701) %ip)
				if sshclient:
					sshclient.close()
		else:
			logger.debug(helper.get_debug(707)%ip)
			if sshclient:
				sshclient.close()
		last_ip = ip

	#diary opeations
	
	# update diary with time values changes
	current_diary = read_diary()
	updated_diary = update_diary(current_diary, list(set(records_diary)))
	write_diary(updated_diary)
	
	# update diary with ip values changes
	# upgraded = upgrade_diary(updated_diary, records_diary)
	# if upgraded:
		# write_diary(upgraded)
				
	logger.info(helper.get_info(706))
	logger.info(helper.get_info(709) %num_get)
	
#QA - OK
def _init_program():
	
	STANDBY = 1 # mins before trying to enter the critical section
	logger.info('_init_program: %s' %socket.gethostname())
	
	while not _mutex():
		logger.debug('%s: standby..' %socket.gethostname())
		sleep(60*STANDBY)
	
	logger.info('** Collector started on %s **' %socket.gethostname())
	
	FOLB_LOCK = '.collector.lck'
	DIARY_FILE = '.collector.dry' 
	
	lock_path = os.path.join(parser.get('Alerting','shared_resource'), FOLB_LOCK)
	repo_hash = disigner.get_hmac_sha256(parser.get('Collector','source_list'))
	diary_path = os.path.join(parser.get('Alerting','shared_resource'), DIARY_FILE)
	
	#creat lock
	if not os.path.isfile(lock_path):
		#create new lock file for the first run
		logger.info(helper.get_info(801))
		_build_lock()
		hash, ts, host = _load_lock()
	else:
		try:		
			#lock exists, avoid any human misuse or corruption 
			hash, ts, host = _load_lock()
		except:
			_build_lock()
			hash, ts, host = _load_lock()
		_build_lock()
	
	#build diary
	if not os.path.isfile(diary_path):
		logger.info(helper.get_info(802))
		diary = set(build_diary())
		write_diary(diary)
	#check diary
	try:		
		#lock exists, avoid any human misuse or corruption 
		diary = read_diary()
		for di in diary:
			a, b, c = di.split(',')
	except:
		logger.warning(helper.get_warning(801))
		diary = set(build_diary())
		write_diary(diary)	

	if hash.strip() != repo_hash:
		logger.debug(helper.get_debug(801))
		logger.warning(helper.get_warning(802))


	run()
	clean_elastic_pool()
	check_service_status()
	check_free_memory()
	check_disk_space()
	logger.info('</round finished>')
	
#QA - OK
def _get_ts():
	return int(round(time() * 1000))

#QA - OK
def _build_lock():
	'''
	creats shared lock object for FO/LB mutex
	'''
	FOLB_LOCK = '.collector.lck'
	
	lock_path = os.path.join(parser.get('Alerting','shared_resource'), FOLB_LOCK)
	repo_hash = disigner.get_hmac_sha256(parser.get('Collector','source_list'))

	try:
		with open(lock_path, 'w+') as lock:
			lock.write('%s,%s,%s' %(repo_hash, _get_ts(), socket.gethostname()))
		sleep(2)
		logger.debug(helper.get_info(1001) %lock_path)
	except Exception as e:
		logger.exception(helper.get_error(1001) %str(e))

#QA - OK
def _load_lock():
	FOLB_LOCK = '.collector.lck'
	
	lock_path = os.path.join(parser.get('Alerting','shared_resource'), FOLB_LOCK)

	try:
		with open(lock_path, 'r') as lock:
			hash, ts, host = lock.readline().replace(' ', '').split(',')
			logger.debug("lock file loaded %s" %lock_path)
		return hash, ts, host
	except Exception as e:
		logger.exception('Error: _load_lock %s' %str(e))

#QA - OK
def _init_logger(log_file, module, level = 10, max_size = 50, bk_count = 10):
	if level not in [0, 10, 20, 30, 40, 50]:
		level = 20
	# Gets or creates a logger
	logger = logging.getLogger(module)  
	if not len(logger.handlers):
		# set log level
		logger.setLevel(level)
		size = max_size * 1024 * 1024
		# define file handler and set formatter
		#file_handler = RotatingFileHandler(log_file, maxBytes = size, backupCount = bk_count)
		file_handler = TimedRotatingFileHandler(log_file, when = 'midnight', backupCount = bk_count)
		formatter    = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')
		file_handler.setFormatter(formatter)

		# add file handler to logger
		logger.addHandler(file_handler)
	return logger

#QA -
def _init_parser(conf_file):
	try:
		parser = SafeConfigParser()
		parser.read(conf_file)
		return parser
		
	#except ConfigParser.NoSectionError as e:
		#logger.exception("NoSection Error" + str(e))
		
	#except ConfigParser.NoOptionError as e:
		#logger.exception("NoOption Error" + str(e))
		
	except Exception as e:
		logger.exception("Error param %s" %str(e))
 
#QA -
def _init_dir():
		x = '/${ANNO}/${SYS}/${HOSTNAME}/${MESE}/${GIORNO}/${FILE}'
		y = '/data/_logs/2020/'
		return

#QA - OK
def _mutex():
	# race condition protection, deadlocks & starvation
	'''
	return True if host has right to access
	'''
	shared_dir = parser.get('Alerting','shared_resource')
	FOLB_iVAL = int (parser.get('Collector','failover_interval'))
	lock_path = os.path.join(shared_dir, '.collector.lck')
	
	if os.path.isfile(lock_path):
		logger.info('%s: -> halt <-' %socket.gethostname())
		diff_min = ((_get_ts()/1000) - os.path.getctime(lock_path))/60
		logger.debug('%s: diff: %d - threshold: %d' %(socket.gethostname(), diff_min, FOLB_iVAL))
		if (diff_min > FOLB_iVAL):
			logger.debug('%s: taking control' %socket.gethostname())
			return True
		else:
			# prevent self-lockout deadlock
			hash, ts, host = _load_lock()
			if host.strip() == socket.gethostname():
				logger.debug('%s: active..' %socket.gethostname())
				return True
			logger.debug('%s: standby..' %socket.gethostname())
			return False
	else:
		logger.debug('%s: Not Locked' %socket.gethostname())
		return True

#QA - OK
def write_diary(diary):
	'''
	writes diary object to the file system
	'''
	logger.debug('__write_diary__: %s' %diary)
	if diary is None:
		return
	try:
		records = os.path.join(parser.get('Alerting', 'shared_resource'), '.collector.dry')
		with open(records, 'w+') as f:
			for line in diary:
				f.write('%s\n' % line)
				
		logger.debug(helper.get_info(1401) %records)
		return
	except Exception as e:
		logger.exception('Error write_diary')

#QA - OK
def read_diary():
	'''
	loads diary object from the file system
	'''
	diary = []
	try:
		records = os.path.join(parser.get('Alerting', 'shared_resource'), '.collector.dry')
		with open(records, 'r') as f:
			for line in f:
				diary.append(line[:-1])
	except Exception as e:
		logger.exception(str(e))
	logger.debug('__read_diary__: %s' %diary)	
	logger.debug(helper.get_debug(1501) %records)
	return (diary)

#QA - 
def update_diary(old_diary, new_diary):
	try:
		alert_threshold = int(parser.get('Alerting', 'alert_threshold'))
	except:
		alert_threshold = 24
	logger.debug('__update_diary__: old %s <> new: %s' %(old_diary, new_diary))
	if len(old_diary) == 0:
		return new_diary
	try:
		for x in old_diary:
			x = x.replace(' ', '') # avoid human edittig errors 
			##old_ip, old_ts = x.split(',')
			old_ip, old_file, old_ts = x.split(',')
			for y in new_diary:
				y = y.replace(' ', '') # avoid human edittig errors
				##new_ip, new_ts = y.split(',')
				new_ip, new_file, new_ts = y.split(',')
				if new_ip == old_ip and new_file == old_file:
				# checks if host stops to send files
				# to check the file add the file to the list, uncomment, then make the IFTTT
					if new_ts != '' and int(new_ts) > int(old_ts):
						## compare ts changes
						## if diff > 1 day alert
						try:
							idx = (old_diary.index('%s, %s, %s' %(old_ip, old_file, old_ts)))
						except ValueError:
							logger.warning('[!] Could not get index of [%s, %s, %s]' %(old_ip, old_file, old_ts))
							break
						###idx = (old_diary.index('%s, %s, %s' %(old_ip, old_file, old_ts)))
						###old_diary[idx] = '%s, %s, %s' %(old_ip, old_file, new_ts)
						old_diary[idx] = '%s, %s, %s' %(old_ip, old_file, new_ts)
						logger.debug(helper.get_debug(1601) %idx + ' [%s, %s] [%s, %s]' %(old_ip, old_ts, old_ip, new_ts))
						logger.debug('old %s' %(old_diary))

					if old_ts != '':
						if new_ts == '':
							new_ts = _get_ts()
						diff_ts = int(new_ts) - int(old_ts)
						logger.debug('alert? new_ts: %s, old_ts: %s, diff: %d, threshold: 86400000' %(new_ts, old_ts, diff_ts))
						if  diff_ts > alert_threshold * 60 * 60 * 1000 or int(new_ts) < 0:
							alerts.critical(helper.get_alert(1601) %(new_ip, alert_threshold, new_file))
							logger.info(helper.get_debug(1602) %new_ip)
		
		# add new IPs to the diary with 0 time
		logger.info(helper.get_info(1601))
		return old_diary
	except Exception as e:
		logger.exception("Error update_diary")

#QA - OK
def build_diary():
	'''
	creats an empty diary object
	'''
	##update when the source_list changes:
	repo = load_registry()
	diary = []
	for host in repo:
		if ',' not in host:
			continue
		ip = host.split(',')[1].strip()
		file = host.split(',')[3].strip()
		diary.append('%s, %s, %s' %(ip, file, '0'))
	return diary

#QA - OK
def upgrade_diary(old_diary, new_diary, from_repo = False):
	'''
	adds new ips to the old diary with 0 time
	'''
	## from diary to diary the same idx
	ip_idx = 1 if from_repo else 0
		
	try:
		old_ips = [x.split(',')[0].strip() for x in old_diary]
		new_ips = [x.split(',')[ip_idx].strip() for x in new_diary]
		dif_ips = [x for x in new_ips if x not in old_ips]
		if len(dif_ips) > 0:
			for ip in dif_ips:
				old_diary.append('%s, %s' %(ip, '0'))
			return old_diary
		return False
	except:
		logger.exception('error upgrade_diary')

def alert():
	parser.get('Alerting', 'shared_resource')
	
def check_service_status():
		services = parser.get('Alerting', 'services')
		if ',' in services:
			services = services.split(',')
		else:
			services = [services] 
		for service in services:
			if service.strip() in ['elasticsearch', 'kibana'] and socket.gethostname() == 'siem-lgst-aci-02':
				logger.debug('[!] Skipped checking %s service on this host %s' %(service, socket.gethostname()))
				continue
			logger.info('[i] Checking service %s' %service.replace(' ',''))
			status = os.system('systemctl status %s > /dev/null' %service.replace(' ',''))
			if status != 0:
				alerts.critical(helper.get_alert(4001) %(service, socket.gethostname()))
				logger.warning('%s service stopped on %s' %(service, socket.gethostname()))
				sendToSIEM(helper.get_alert(4001) %(service, socket.gethostname()))
		return status

def check_free_memory():
	try:
		mem_threshold = int(parser.get('Alerting', 'mem_threshold').replace('%',''))
	except:
		mem_threshold = 20
	try:
		tot_m, used_m, free_m = map(int, os.popen('free -t -m').readlines()[-1].split()[1:])
		free_m_precent = int (free_m) * 100 / int(tot_m)
		logger.info('[i] Free memory: %d percent' %free_m_precent)
		if free_m_precent < mem_threshold:
			alerts.critical(helper.get_alert(4002) %socket.gethostname())
			logger.warning('[!] Low memory on %s' %socket.gethostname())
			sendToSIEM(helper.get_alert(4002) %socket.gethostname())
	except:
		#logger.error('Error getting memory usage ')
		logger.exception(helper.get_error(8003))

def check_disk_space():
	try:
		disk_threshold = int(parser.get('Alerting', 'disk_threshold').replace('%',''))
	except:
		disk_threshold = 20
		
	partitions = ['/data', '/home/nfs']
	
	for partition in partitions:
		try:
			st = os.statvfs(partition)
			free_d = st.f_bavail * st.f_frsize
			tot_d = st.f_blocks * st.f_frsize
			used_d = (st.f_blocks - st.f_bfree) * st.f_frsize
			free_d_precent = int (free_d) * 100 / int(tot_d)
			logger.info('[i] Free space on %s: %d percent' %(partition, free_d_precent))
			if free_d_precent < disk_threshold:
				alerts.critical(helper.get_alert(4003) %(partition, socket.gethostname()))
				logger.warning('[!] Low disk space on partition %s on host %s' %(partition, socket.gethostname()))
				sendToSIEM(helper.get_alert(4003) %socket.gethostname())
		except:
			#logger.error('Error getting disk usage')
			logger.exception(helper.get_error(8004))	

def get_connect_ival(CONF_FILE):
	parser = _init_parser(CONF_FILE)		
	try:
		return int(parser.get('Collector', 'connect_interval'))
	except:
		return 10

def get_conf_values(section, category, log_comment):
	'''
	get line of values from conf ile
	return list of values
	'''
	try:
		exc = parser.get(section, category).replace(' ','')
		logger.debug('%s %s' %(log_comment, exc))
		if ',' in exc:
			return exc.split(',')
		return [exc]
	except:
		return []
		
def notify(code):
	if code == 0:
		logger.info('[i] service stop request')
	logger.info('[i] collector service stopped')

def getVersion():
	print (__version__)
	return __version__

def getLogFileName(ALERT = True):
	if ALERT:
		return 'alerts_collector_%s.log' %(socket.gethostname())
	return 'logs_collector_%s.log' %(socket.gethostname())

def collect(CONF_FILE):
	global parser 
	global logger 
	global alerts
	
	parser = _init_parser(CONF_FILE)
	
	log_level = int(parser.get('Logging', 'log_level'))
	alert_file = os.path.join(parser.get('Alerting', 'log_dir'), getLogFileName(ALERT = True))
	log_file = os.path.join(parser.get('Logging', 'log_dir'), getLogFileName(ALERT = False))
	log_max_size = int (parser.get('Logging', 'max_size'))
	log_count = int(parser.get('Logging', 'max_chunks'))
	
	logger = _init_logger(log_file, module = __name__, level = log_level, max_size = log_max_size, bk_count = log_count)
	alerts = _init_logger(alert_file, module = 'alerts', level = log_level, max_size = log_max_size, bk_count = log_count)
	
	params = _init_program()

def clean_elastic_pool():
	filepath = parser.get('Elasticsearch','log_dir')
	log_max_age = int (parser.get('Elasticsearch','log_max_age'))
	logger.debug(helper.get_debug(2005))
	files = [f for f in os.listdir(filepath) if os.path.isfile(os.path.join(filepath, f))]
	
	for file in files:
		try:
			stat = os.stat(os.path.join(filepath, file))
			if (((_get_ts()/1000) - int(stat.st_mtime))/(60*60*24)) > log_max_age:
				os.remove(os.path.join(filepath, file))
				logger.info(helper.get_info(2005) %file)
		except Exception as e:
			logger.warning(helper.get_warning(706) %(file, str(e)))
		 
def sendToSIEM(msg):
		'''
		send syslog message
		'''
		isSIEM = parser.get('Alerting', 'enabled')
		
		if not isEnabled(isSIEM):
			logger.debug('[i] SIEM alerts are disabled.')
			return
		syslog = _formatMessage(msg)
		_ip = parser.get('Alerting', 'siem_ips')
		_port = int(parser.get('Alerting', 'syslog_port'))
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		logger.info('[i] Sending syslog to SIEM at %s:514' %_ip)
		try:
			sock.connect((_ip, _port))
			sock.send(syslog)
			sock.close()
		except:
			logger.error("Error sending info to SIEM", exc_info=True)
			
def _formatMessage(msg):
		'''
		Format Message
		HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP MSG
		'''
		dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
		return "<41>1 %s %s %s %s" %(dt[:-3], socket.gethostname(), 'Collector', msg)


