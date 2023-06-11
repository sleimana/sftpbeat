#!/usr/bin/env python2.7
# disigner 2019
# Author: Sleiman Ahmad
	
##
## Digital sign/verfiy log files/signatures
##

## This script wasn't designed to validate inputs and handle exceptions, the caller application should do so.
	
__version__ = '0.512'

import subprocess, hashlib, sys, base64, re, datetime

#---- Config
PUB_KEY = ''	# Path to public key
PRV_KEY = ''	# Path to private key
PFX_FIL = ''	# Path to pfx file
PFX_PWD = ''	# PFX File Password
EXT = '.sig'    # Singature file extention
#----


#------- Important: don't change after this line unless you know what you're doing
RSASSA_PSS = False # Set to ture to use the Probabilistic Signature Scheme. For more info see https://tools.ietf.org/html/rfc3447.html
HASH = 5 # Hashing alogrithm, to change choose a number from below
	
	### 0 -> sha    	### 6 -> sha384
	### 1 -> sha1   	### 7 -> sha512
	### 2 -> mdc2   	### 8 -> md2
	### 3 -> ripemd160	### 9 -> md4
	### 4 -> sha224		### 10 -> md5
	### 5 -> sha256	  	### 11 -> dss1
	
SIGN = NTV = 0 # NATIVE, no RSASSA-PSS Support
VRFY = LIB = 1 # LIBRARY, with RSASSA-PSS Support

	#   Op	Mode
	# # 0	0	sign native
	# # 0	1	sign lib
	# # 1	0	verify native
	# # 1	1	verify lib
	
DGST = ['-sha', '-sha1', '-mdc2', '-ripemd160', '-sha224', '-sha256', '-sha384', '-sha512', '-md2', '-md4', '-md5', '-dss1']
CMDs = ['-sign','-verify', 'openssl', 'dgst', '-signature', '-out', '-in', '-nocerts', 'pkcs12', '-password', '-nodes']

K_HEADER = 'PRIVATE KEY-----'
K_FOOTER = '-----END '
#-------


	

def get_serialized_key(PRV_KEY, password = None):
	# '''
	# input: pem private key
	# output: serialized key
	# '''
	with open(PRV_KEY, "rb") as key_file:
		private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	return private_key

def rsa_sign(message, key, signature = None):
	# '''
	# input: message, key, signature file-path
	# output: signature
	# '''

	try:
		signature = key.sign(
			message,
			cryptography.hazmat.primitives.asymmetric.padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		return signature
	except Exception as e:
		print (e)
		return False

def rsa_verify(message, key, signature):
	# '''
	# input: message, key, signature
	# output: results
	# '''
	try:
		public_key = key.public_key()
		public_key.verify(
			signature,
			message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		return True
	except cryptography.exceptions.InvalidSignature:
		return False
	except Exception as e:
		print (e)
		return False

def _exval(msg, str_start, str_end=None):
	if str_end is not None:
		return None if not (re.search('%s(.*)%s' %(str_start, str_end), msg)) else re.search('%s(.*)%s' %(str_start, str_end), msg).group(1)
	return None if not (re.search('%s(.*) ' %str_start, msg)) else re.search('%s(.*) ' %str_start, msg).group(1).split(" ")[0]

def log(msg):
	print  '%s | disigner | %s' %(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)
	return
	
def get_hmac_sha256(filepath):
	'''
	input: file-path
	output: HMAC-SHA256
	'''
	signature = hashlib.sha256()
	with open(filepath, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			signature.update(chunk)
	return signature.hexdigest()
	
def get_cmd(file, sig, opertation):
	'''
	input: file to sign, signature file-path, opertation
	output: opertation commands
	'''
	return [CMDs[2], CMDs[3], DGST[HASH], CMDs[opertation], PUB_KEY if opertation else PRV_KEY, CMDs[4] if opertation else CMDs[5], sig, file]

def encode(sig):
	'''
	encode signature 
	'''
	return base64.b64encode(sig)

def decode(sig):
	'''
	decode signature
	'''
	return base64.b64decode(sig)
	
def load_pkcs12(data, password = None):
	# epiremental #more tests needed on this.
	try:
		return cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data, password, backend=default_backend())
	except Exception as e:
		print e
		return False
		
def get_key_from_pkcs12(file, password):
	'''
	input: pkcs12 file, password
	output: deserialized key
	'''
	get_pkcs_bag_with_plain_key = [CMDs[2], CMDs[8], CMDs[6], file, CMDs[7], CMDs[9], 'pass:%s' %password, CMDs[10]]
	out, err = subprocess.Popen(get_pkcs_bag_with_plain_key, stdout=subprocess.PIPE).communicate()
	return _exval(out.replace("\n", ""), K_HEADER, K_FOOTER)
	
def store_sig(fname, sig):
	'''
	store signature
	'''
	file = open(fname, 'w')
	file.write(sig)
	return

def read_sig(fname):
	'''
	read signature
	'''
	file = open(fname, 'rb')
	return file.read()
	
def main(m, k, s, op, mode = LIB):
	'''
		inputs: m: message, k: key, s: signature, op: opertation, [mode]
		output: sign | verify results
	'''
	if mode: # PSS
		if op:
			#1 1
			log ('Verifying [%s] for [%s] | mode: %d' %(s, m, mode))
			r = None #'Verified OK' if rsa_verify(get_hmac_sha256(m), get_serialized_key(k), read_sig(s)) else 'NOT Verified'
			log(r)
			return
		#0 1
		r = None #rsa_sign(get_hmac_sha256(m), get_serialized_key(k))
		sig = base64.b64encode(r) if r else None
		if sig:
			store_sig(s, r)
			log('[%s] Signed in [%s] | mode: %d' %(m, s, mode))
	else: # 1 0
		if op:
			log('Verifying [%s] for [%s] | mode: %d' %(s, m, mode))
			log( subprocess.Popen(get_cmd(m, s, VRFY),stdout=subprocess.PIPE).stdout.readline())
			sys.exit()
			
		else: # 0 0
			r = subprocess.Popen(get_cmd(m, s, SIGN),stdout=subprocess.PIPE)
			#print ('***\ncmd %s\n' %get_cmd(m, s, SIGN))
			if r.stdout.readline() == b'':
				log('[%s] Signed in [%s] | mode: %d' %(m, s, mode))
				return True
			return False

def _init():
	# standalone mode only
	mode = LIB if RSASSA_PSS else NTV
	try:
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives import serialization
		from cryptography.hazmat.primitives import hashes
		from cryptography.hazmat.primitives.asymmetric import padding
		from cryptography import exceptions
		from cryptography.hazmat.primitives.serialization import pkcs12
	except ImportError as e:
		mode = NTV
	if (len(sys.argv) == 4 and sys.argv[1].lower() == '-v'):
		main(sys.argv[2], PUB_KEY, sys.argv[3], VRFY, mode)
	elif (len(sys.argv) == 3 and sys.argv[1].lower() == '-s'):
		main(sys.argv[2], PRV_KEY, sys.argv[2] + EXT, SIGN, mode)
	elif (len(sys.argv) > 1):
		return usage()

def usage():
	print 'Disigner v'+ __version__ +'\nUSAGE:\n\
	To Sign:   disigner -s FILE-NAME\n\
	To Verify: disigner -v FILE-NAME FILE-SIGNATURE'

def verify_file(file, sig = None, key = None, keystore = None, password = None):
	'''
	verify a given log file
	'''
	global PUB_KEY
	PUB_KEY = key
	if PUB_KEY is None:
		PUB_KEY = get_key_from_pkcs12(PFX_FIL, PFX_PWD)
	m = file
	s = m + EXT
	main(m, PUB_KEY, s, VRFY, mode = NTV)

def sign_file(file, sig = None, key = None, keystore = None, password = None):
	'''
	sign a given log file
	'''
	global PRV_KEY
	m = file
	PRV_KEY = key
	if PRV_KEY is None:
		PRV_KEY = get_key_from_pkcs12(PFX_FIL, PFX_PWD)
	s = m + EXT	
	return main(m, PRV_KEY, s, SIGN, mode = NTV)

_init()
