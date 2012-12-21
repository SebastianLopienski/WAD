#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author: Sebastian.Lopienski@cern.ch
#

# ===========================================================================================================		

# To test, run:
#		py.test -v wad_*.py

# ===========================================================================================================		

# TODO: (consider) use "confidence" field?? if yes, then follow in inheritance ("implies")

import re
import yaml
import urllib2
import copy
import logging

from optparse import OptionParser

# prefering simplejson but fallback to json - this should work both on python 2.4 and 2.6
# for more see http://stackoverflow.com/a/712799
try: import simplejson as json
except ImportError: import json

import tools

# ===========================================================================================================		


CLUES_FILE = '../etc/apps.json'
global categories, apps 
TIMEOUT = 3

reMeta = re.compile('<meta[^>]+name\s*=\s*["\']([^"\']*)["\'][^>]+content\s*=\s*["\']([^"\']*)', re.IGNORECASE);
reScript = re.compile('<script[^>]+src\s*=\s*["\']([^"\']*)', re.IGNORECASE);

	
# ===========================================================================================================		

# Clues taken from Wappalyzer
# 
# clues:		https://github.com/ElbertF/Wappalyzer/blob/master/share/apps.json
# more info:	https://github.com/ElbertF/Wappalyzer/blob/master/README.md
# detection:	https://github.com/ElbertF/Wappalyzer/blob/master/share/js/wappalyzer.js

# ===========================================================================================================		

def loadClues(filename = CLUES_FILE):
	global apps, categories

	try:	
		json_data = open(filename)
		cc = json.load(json_data, encoding='utf-8')
		json_data.close()

		categories = cc['categories']			
		apps = cc['apps']

	except Exception, e:
		# this is either file I/O exception, or YAML parse exception
		logging.error("Clues file error, terminating: %s", str(e))
		raise e
				
	# correcting a difference between regular expressions in JavaScript (where [^] works fine) and Python
	apps["osCommerce"]['html'] = apps["osCommerce"]['html'].replace("[^]", "[\^]")	

	#test_loadClues()
										
def test_loadClues():
	loadClues(CLUES_FILE)
	
def test_cluesLoaded():
	assert type(apps) == dict
	assert type(categories) == dict
	
def test_cluesCorrect():
	
	types = {}	
	for app in apps:
		for t in apps[app]:
			tools.count(types, t)
	
	# check if all apps have a category
	assert types['cats'] == len(apps)

	# check if all categories listed in app are defined 
	assert (set(reduce(list.__add__, [apps[a]['cats'] for a in apps])) <= 
		set([int(x) for x in categories.keys()]))
			
	# check if only expected fields are defined for apps
	assert (set(types.keys()) == 
		set(['implies', 'script', 'scripts', 'url', 'cats', 'headers', 'html', 'meta', 'env', 'confidence']))

	types = {}	
	for t in [k for a in apps for k in apps[a]]:
		tools.count(types, t)
	logging.debug(types)
	# {u'confidence': 4, u'implies': 124, u'script': 100, u'url': 22, u'html': 148, u'headers': 88, u'cats': 380, u'meta': 97, u'env': 121}	

	# check if numbers of entries are as expected
	assert types['implies'] > 120
	assert types['script'] > 95
	assert types['scripts'] > 0
	assert types['url'] > 20
	assert types['headers'] > 80
	assert types['html'] > 140
	assert types['meta'] > 90
	assert types['env'] > 115
	
	# check if all implies are lists of unicodes, headers and meta are dictionaries of str/unicode,
	# and others (including app names) are str/unicode
	assert set([type(a) for a in apps]) <= set([str, unicode])
	assert set([type(apps[a]['script'])  for a in apps if apps[a].has_key('script') ]) <= set([str, unicode])
	assert set([type(apps[a]['url'])     for a in apps if apps[a].has_key('url')    ]) <= set([str, unicode])
	assert set([type(apps[a]['html'])    for a in apps if apps[a].has_key('html')   ]) <= set([str, unicode])
	assert set([type(apps[a]['env'])     for a in apps if apps[a].has_key('env')    ]) <= set([str, unicode])
	assert set([type(apps[a]['implies']) for a in apps if apps[a].has_key('implies')]) == set([list])
	assert set([type(apps[a]['meta'])    for a in apps if apps[a].has_key('meta')   ]) == set([dict])
	assert set([type(apps[a]['headers']) for a in apps if apps[a].has_key('headers')]) == set([dict])
	assert set([
			type(v) 
			for a in apps if apps[a].has_key('implies') 
			for v in apps[a]['implies']]) <= set([str, unicode])	
	assert set([
			type(x) 
			for a in apps if apps[a].has_key('headers') 
			for k in apps[a]['headers'] 
			for x in [k, apps[a]['headers'][k]]]) <= set([str, unicode])
	assert set([
			type(x) 
			for a in apps if apps[a].has_key('meta') 
			for k in apps[a]['meta'] 
			for x in [k, apps[a]['meta'][k]]]) <= set([str, unicode])

	for h in [apps[a]["headers"] for a in apps if apps[a].has_key("headers")]:
		for k in h:
			logging.debug(type(k), k)
				
	# check if all 'implies' references exist
	assert set(reduce(list.__add__, [apps[a]['implies'] 
			for a in apps if apps[a].has_key('implies')])) - set(apps.keys()) == set()   


# ===========================================================================================================		

def compileClue(regexpExtended):
	values = regexpExtended.split("\;")
	d = {"re": re.compile(values[0], flags=re.IGNORECASE)}
	for e in values[1:]:
		try: 
			(k, v) = e.split(':', 1)
			d[k] = v
		except ValueError:
			d[e] = None
		
	return d	

def test_compileClue():
	assert compileClue("abc") == {"re": re.compile("abc", flags=re.I)}
	assert compileClue("abc\;version:$1") == {"re": re.compile("abc", flags=re.I), "version": "$1"}
	assert compileClue("ab;c\;k:v1:v2\;aaa") == {"re": re.compile("ab;c", flags=re.I), "k": "v1:v2", "aaa": None}
	
def compileClues():
	global apps										
	# compiling regular expressions
	for app in apps:
		regexps = {}
		for key in apps[app]:			
			if key in ['html', 'script', 'url']:
				regexps[key + "_re"] = compileClue(apps[app][key])
			if key in ['meta', 'headers']:
				regexps[key + "_re"] = {}				
				for entry in apps[app][key]:
					regexps[key + "_re"][entry] = compileClue(apps[app][key][entry])
			if key in ['scripts']:
				regexps[key + "_re"] = map(compileClue, apps[app][key])
		apps[app].update(regexps)

def test_compileClues():
	compileClues()

# ===========================================================================================================		

# if re matches text, then add to found the det(ector) and the app(lication)
def checkRe(reCompiled, reRaw, text, found, det, app, showMatchOnly = False):
	match = reCompiled["re"].search(text)
	if match:
		ver = None
		
		if showMatchOnly: showText = match.group(0)
		else:             showText = text
		
		showText = ''.join(showText.splitlines())

		if reCompiled.has_key("version"):
			try:	
				ver = match.expand(reCompiled["version"])
			except Exception, e:
				logging.debug("Version not detected: expanding '%s' with '%s' failed: %s", showText, reRaw, str(e))
				ver = None
				
			if ver:
				ver = ver.strip() 

		logging.info("  + %-7s -> %s (%s): %s =~ %s" % (det, app, ver, showText, reRaw))
		
		#found += [{'app': app, 'ver': ver, 'det': det}]
		found += [{'app': str(app), 'ver': ver}]

		

# ===========================================================================================================		

def checkURL(url): 
	global apps
	
	found = []
	for app in apps: 	
		if 'url' in apps[app]:
			checkRe(apps[app]['url_re'], apps[app]['url'], url, found, 'url', app)					
	return found		


def test_checkURL():
	#assert checkURL("http://whatever.blogspot.com") == [{'app': 'Blogger', 'ver': None, 'det': 'url'}]
	#assert checkURL("https://whatever-else3414.de/script.php") == [{'app': 'PHP', 'ver': None, 'det': 'url'}]
	assert checkURL("http://whatever.blogspot.com") == [{'app': 'Blogger', 'ver': None}]
	assert checkURL("https://whatever-else3414.de/script.php") == [{'app': 'PHP', 'ver': None}]


# ===========================================================================================================		

def checkHTML(content):
	found = []
	for app in apps:
		if 'html' in apps[app]:
			checkRe(apps[app]["html_re"], apps[app]['html'], content, found, "html", app, True)
	return found		

def test_checkHTML():
	content = """
	<html>
	<div id="gsNavBar" class="gcBorder1">
	whatever
	"""
	#assert checkHTML(content) == [{'app': 'Gallery', 'ver': None, 'det': 'html'}]
	assert checkHTML(content) == [{'app': 'Gallery', 'ver': None}]

# ===========================================================================================================		

def checkMeta(content):
	found = []	
	for tag in reMeta.finditer(content):
		for app in apps:
			if 'meta' in apps[app]:
				for meta in apps[app]['meta']:
					if tag.group(1).lower() == meta.lower():
						checkRe(apps[app]["meta_re"][meta], apps[app]['meta'][meta], 
							tag.group(2), found, 'meta(%s)' % meta, app)										
						
	return found		

def test_checkMeta():
	assert (checkMeta('<html>	s<meta name="generator" content="Percussion">sssss	whatever') == 
		#[{'app': 'Percussion', 'ver': None, 'det': 'meta(generator)'}])
		[{'app': 'Percussion', 'ver': None}])
	assert (checkMeta(" dcsaasd f<meta 	name	= 'cargo_title' dd  content    =		'Pdafadfda'  >") == 
		#[{'app': 'Cargo', 'ver': None, 'det': 'meta(cargo_title)'}]) 
		[{'app': 'Cargo', 'ver': None}]) 
	assert (checkMeta(" dcsaasd f<mfffffffeta 	name='cargo_title' dd  content='Pdafadfda'  >") == 
		[]) 
	assert (checkMeta(" dcsaasd f<meta 	name='cargo_title' >") == 
		[]) 
	
# ===========================================================================================================		

def checkScript(content):
	found = []	
	for tag in reScript.finditer(content):
		for app in apps:
			if 'script' in apps[app]:
				checkRe(apps[app]["script_re"], apps[app]["script"], tag.group(1), found, 'script', app)				
			if 'scripts' in apps[app]:
				for i in range(len(apps[app]['scripts_re'])):
					checkRe(apps[app]["scripts_re"][i], apps[app]['scripts'][i], 
						tag.group(1), found, 'script', app)										
														
	return found		

def test_checkScript():
	assert (checkScript('<html>	s<script  sda f 	src	=  "jquery1.7.js">') == 
		#[{'app': 'jQuery', 'ver': None, 'det': 'script'}]) 
		[{'app': 'jQuery', 'ver': None}]) 
	assert (checkScript(" dcsaasd f<script 	src='' >") == 
		[]) 

# ===========================================================================================================		

def checkHeaders(headers):
	global apps
	
	headerKeys = [x.lower() for x in headers.keys()]
	
	found = []
	for app in apps: 	
		if 'headers' in apps[app]:  
			for entry in apps[app]['headers']:  
				if entry.lower() in headerKeys:
					checkRe(apps[app]['headers_re'][entry], apps[app]['headers'][entry], 
						headers[entry], found, 'headers(%s)' % entry, app)											
	return found		
									
								
def test_checkHeaders():
	headers = {
			'Host': 'abc.com',
			'Server': 'Linux Ubuntu 12.10',
			}
	assert (checkHeaders(headers) == 
		#[{'app': 'Ubuntu', 'ver': None, 'det': 'headers(Server)'}])
		[{'app': 'Ubuntu', 'ver': None}])

# ===========================================================================================================		

def impliedBy(appList):
	global apps
	return list(set(reduce(list.__add__, 
						[apps[app]['implies'] for app in appList if apps[app].has_key('implies')],
						[])) 
			- set(appList))
	
def test_impliedBy():	
	# ASP implies WS and IIS and IIS implies WS; 
	# but we already know about IIS, so the only new implied app is WS
	assert impliedBy(['Microsoft ASP.NET', 'IIS']) == ['Windows Server']


# ===========================================================================================================		
	
def	followImplies(findings):	
	new = impliedBy([f['app'] for f in findings])
	while new != []:
		for app in new:
			#findings += [{'app': app, 'ver': None, 'det': 'implies'}]
			findings += [{'app': app, 'ver': None}]
			logging.info("  + %-7s -> %s" % ("implies", app))
			
		new = impliedBy([f['app'] for f in findings])

def test_followImplies():	

	# empty findings
	findings = []
	followImplies(findings)
	assert findings == [] 	

	# no implies
	findings = [{'app': 'reCAPTCHA', 'ver': None}]
	followImplies(findings)
	assert findings == [{'app': 'reCAPTCHA', 'ver': None}] 	
			
	# Django CMS implies Django, and Django implies Python - let's see if this chain is followed
	findings = [{'app': 'Django CMS', 'ver': None}]
	followImplies(findings)	
	assert (findings == 	
		[{'app': 'Django CMS', 'ver': None},
		#{'app': 'Django', 'ver': None, 'det': 'implies'},
		#{'app': 'Python', 'ver': None, 'det': 'implies'}])
		{'app': 'Django', 'ver': None},
		{'app': 'Python', 'ver': None}])

# ===========================================================================================================		

def removeDuplicates(findings):
	
	temp = copy.deepcopy(findings)
		
	# empty list findings 
	# (keeping the existing list reference, rather than creating new list with 'findings = []' )	
	findings[:] = []
		
	# loop over temp and insert back info findings unless it already exists
	for t in temp:
		already = False
		for f in findings:
			if t == f: 
				already = True
			elif t['app'] == f['app']:
				# same app but different versions - now decide which one to take
				
				# if f is empty or prefix of t then overwrite f with t
				if f['ver'] == None or (t['ver'] != None and t['ver'].find(f['ver']) == 0): 
					f['ver'] = t['ver']
					already = True
				# if t is empty or prefix of f, then ignore t
				elif t['ver'] == None or f['ver'].find(t['ver']) == 0:
					already = True	
							
		# if t is new, then add it to final findings
		if not already:
			findings += [t]
			

def test_removeDuplicates():
	withDuplicates = [
			{'app': 'A', 'ver': None}, {'app': 'B', 'ver': "1.5"},
			{'app': 'C', 'ver': None}, {'app': 'D', 'ver': "7.0"},
			{'app': 'E', 'ver': "1"},  {'app': 'F', 'ver': "2.2"},

			{'app': 'A', 'ver': None}, {'app': 'B', 'ver': "1.5"},
			{'app': 'C', 'ver': "be"}, {'app': 'D', 'ver': "222"},
			{'app': 'A', 'ver': None}, {'app': 'B', 'ver': "1.5"},
			{'app': 'E', 'ver': None}, {'app': 'E', 'ver': "1.3"},
			{'app': 'F', 'ver': "2" }, {'app': 'F', 'ver': None },
			]
	
	withoutDuplicates = [
			{'app': 'A', 'ver': None}, {'app': 'B', 'ver': "1.5"},
			{'app': 'C', 'ver': "be"}, {'app': 'D', 'ver': "7.0"}, 
			{'app': 'E', 'ver': "1.3"}, 
			{'app': 'F', 'ver': "2.2"}, {'app': 'D', 'ver': "222"},
			]
						
	removeDuplicates(withDuplicates)	
	assert withDuplicates == withoutDuplicates 

# ===========================================================================================================		

def addCategories(findings):
	global apps, categories
	# some apps are in several categories => merged to a comma-separated string 
	for f in findings:
		f['type'] = reduce(lambda a, b: "%s, %s" % (a, b), 
						[str(categories[str(x)]) for x in apps[f['app']]['cats']])

def test_addCategories():	
	findings = [
			{'app': 'Django CMS', 'ver': None},
			{'app': 'Django', 'ver': None},
			{'app': 'Python', 'ver': '2.7'},
			{'app': 'Dynamicweb', 'ver': 'beta'}]
	original = copy.deepcopy(findings)
	original[0]["type"] = "cms"
	original[1]["type"] = "web-frameworks"
	original[2]["type"] = "programming-languages"
	original[3]["type"] = "cms, web-shops, analytics"
	
	addCategories(findings)
	assert original == findings
	

# ===========================================================================================================		

def urlMatch(url, regexp, default):
	if regexp:	return re.match(regexp, url, re.IGNORECASE)
	else:		return default

def expectedURL(url, limit, exclude):
	if not urlMatch(url, limit, True):
		logging.info("x %s !~ %s" % (url, limit))
		return False		
	if urlMatch(url, exclude, False):
		logging.info("x %s =~ %s" % (url, exclude))
		return False
	return True

def test_expectedURL():
	url = "http://site.abc.com/dir/sub/script.php"		
	assert     expectedURL(url, None, None)
	assert     expectedURL(url, 'http://.*abc.com/', None)
	assert not expectedURL(url, 'http://abc.com/', None)
	assert     expectedURL(url, 'http://.*abc.com/', "php")
	assert not expectedURL(url, 'http://.*abc.com/', ".*php")
	assert     expectedURL(url, None, ".*\.asp")
	assert not expectedURL(url, None, ".*\.php")
	

# ===========================================================================================================		

def wadDetect(url, limit=None, exclude=None):
	global TIMEOUT

	logging.info("- %s" % url)
	
	findings = []
	page = None
	content = None
	originalUrl = url
	
	if not expectedURL(url, limit, exclude): 
		return (url, findings)
	
	try:
		# python 2.6+ -> timeout argument added 
		try:				page = urllib2.urlopen(url, timeout = TIMEOUT)
		except TypeError:	page = urllib2.urlopen(url)
		
		url = page.geturl()
		if url != originalUrl:			
			logging.info("` %s" % url)
			
			if not expectedURL(url, limit, exclude): 
				return (url, findings)

		content = page.read()
						
	except urllib2.URLError, e: 
		# a network problem? page unavailable? wrong URL?
		logging.error("Error opening %s, terminating: %s", url, str(e))
		return {}

	findings += checkURL(url)							# 'url'
	#findings += checkURL(originalUrl)					# do we want to check the original url??? probably not				
	if page: findings += checkHeaders(page.info())		# 'headers'
	if content:
		findings += checkMeta(content)				# 'meta'
		findings += checkScript(content)			# 'script'
		findings += checkHTML(content)				# 'html'
	
	followImplies(findings)						# 'implies'
	removeDuplicates(findings)
	addCategories(findings)

	return {url: findings}


# ===========================================================================================================		

def wadDetectMultiple(urls, limit=None, exclude=None):
	# remove duplicate URLs	
	urls = list(set(urls))
	
	results = {}
	for url in urls: 
		res = wadDetect(url, limit, exclude)
		results.update(res)

	return results


# ===========================================================================================================		

def main():
	
	global TIMEOUT, CLUES_FILE

	desc = """WAS detect -
This component analyzes given URL(s) and detects technologies, libraries, 
frameworks etc. used by this application, from the OS and web server level,
to the programming platform and frameworks, and server- and client-side 
applications, tools and libraries. For example: OS=Linux, webserver=Apache,
platform=PHP, cms=Drupal, analytics=Google Analytics, javascript-lib=jQuery
etc."""

	parser = OptionParser(
						description=desc,
						usage="Usage: %prog -u <URLs|@URLfile>\nHelp:  %prog -h",
						version="%prog 1.0") 			
	
	parser.add_option("-u", "--url", dest="urls", metavar="URLS|@FILE",
	              	help="list of URLs (comma-separated), or a file with a list of URLs (one per line)") 

	parser.add_option("-l", "--limit", dest="limit", metavar="URLMASK",
	              	help="in case of redirections, only include pages with URLs matching this mask - e.g. 'https?://[^/]*\.abc\.com/'") 
	
	parser.add_option("-x", "--exclude", dest="exclude", metavar="URLMASK",
	              	help="in case of redirections, exclude pages with URL matching this mask - e.g. 'https?://[^/]*/(login|logout)'")
	
	parser.add_option("-o", "--output", dest="output_file", metavar="FILE",
					help="output file for detection results (default: STDOUT)") 

	parser.add_option("-c", "--clues", dest="clues_file", metavar="FILE", default=CLUES_FILE,
					help="clues for detecting web applications and technologies")
	
	parser.add_option("-t", "--timeout", action="store", dest="TIMEOUT", default=TIMEOUT,
					help="set timeout (in seconds) for accessing a single URL")

	tools.addLogOptions(parser)
		
	options = parser.parse_args()[0] 
		
	tools.useLogOptions(options)

	if not options.urls:
		parser.error("Argument -u missing")
		return
		
	TIMEOUT = int(options.TIMEOUT)
				
	if  options.urls[0] == "@":
		try:
			f = open(options.urls[1:]) 	
			urls = f.read_lines()
			f.close()
		except Exception, e:
			# an I/O exception?
			logging.error("Error reading URL file %s, terminating: %s", options.urls[1:], str(e))
			return	
	else:
		urls = [x.strip() for x in options.urls.split(",") if x.strip() != ""]		
		
	loadClues(options.clues_file)
	
	compileClues()	
		
	results = wadDetectMultiple(urls, limit=options.limit, exclude=options.exclude)  
	
	if options.output_file:	
		try:
			f = open(options.output_file, "w")
			f.write(yaml.dump(results))
			f.close()
			logging.debug("Results written to file %s", options.output_file)
		except Exception, e:
			# an I/O exception?
			logging.error("Error writing results to file %s, terminating: %s", options.output_file, str(e))			
			return								
	else:
		print yaml.dump(results, default_flow_style=False)
	
	
# ===========================================================================================================		

if __name__ == "__main__": 
	main() 

