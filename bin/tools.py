# ===========================================================================================================		
# Module tools
#
# Author: Sebastian Lopienski <Sebastian.Lopienski@cern.ch>
# ===========================================================================================================		
	
# python 2.5+ -> hashlib; before -> md5 
try: from hashlib import md5
except ImportError: from md5 import md5

import logging

# ===========================================================================================================		
def count(d, e):
	if type(e) == list:
		for i in e:
			count(d, i)
	else:
		if d.has_key(e): d[e] += 1
		else: d[e] = 1

# ===========================================================================================================		

def hashId(x):
	return md5(x).hexdigest()[:8]

# ===========================================================================================================		

def addLogOptions(parser):
	
	parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False,
					help="be quiet")

	parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
					help="be verbose")

	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False,
					help="be more verbose")

	parser.add_option("--log", action="store", dest="log_file", metavar="FILE", default=None,
					help="log to a file instead to standard output")


def useLogOptions(options, name = None):
		
	if name: f = '%(asctime)s (' + hashId(name) + '):%(module)s:%(levelname)s %(message)s'
	else: f = '%(asctime)s %(module)s:%(levelname)s %(message)s'
	
	df = '%Y/%m/%d-%H:%M:%S'
	l = logging.WARNING
		
	if options.verbose: l = logging.INFO
	if options.debug: l = logging.DEBUG
	if options.quiet: l = logging.ERROR
		
	if options.log_file: logging.basicConfig(filename=options.log_file, level=l, format=f, datefmt=df)
	else: logging.basicConfig(level=l, format=f, datefmt=df)
