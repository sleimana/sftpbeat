#!/usr/bin/env python2.7
# Project: SFTPBeat
# Collector: [LS01 - LS02]
# Author: sleiman.ahmad@nttdata.com

__version__ = '1.20'

import signal
import time
import sftpbeat 

CONF = '/data/collector/collector.conf'

class GracefulTerminator:
	terminate = False
	def __init__(self):
		signal.signal(signal.SIGINT, self.exit_gracefully)
		signal.signal(signal.SIGTERM, self.exit_gracefully)

	def exit_gracefully(self,signum, frame):
		self.terminate = True

if __name__ == '__main__':
	_systemd = GracefulTerminator()
	
	while not _systemd.terminate:
		#Sync server time
	#	if time.localtime().tm_min % 5 == 0:
			sftpbeat.collect(CONF)
			time.sleep(60 * sftpbeat.get_connect_ival(CONF))
					
	print "Collector Stopped"
