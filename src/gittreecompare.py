#!/usr/bin/python

## Copyright 2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script compares tags in two Git trees and computes the TLSH distance
between the two tags.

It has two parameters:

* a configuration file that specifies which Git repositories live where on
disk
* a 'tag file' with Git URLs and the tags to compare

The tag file has two columns that are tab separated. The first line *has*
to have the URLs of the Git repositories. Each rown in the column then
specifies a tag in each repository.
'''

import os, os.path, sys, hashlib, subprocess, stat, tempfile
import magic, ConfigParser
from optparse import OptionParser
from multiprocessing import Pool
try:
	import tlsh
	tlshscan = True
except Exception, e:
	tlshscan = False

## This is not necessarily correct, but right now it is the best we have.
extensions = {'.c'      : 'C',
              '.cc'     : 'C',
              '.cpp'    : 'C',
              '.cxx'    : 'C',
              '.c++'    : 'C',
              '.h'      : 'C',
              '.hh'     : 'C',
              '.hpp'    : 'C',
              '.hxx'    : 'C',
              '.l'      : 'C',
              '.qml'    : 'C',
              '.s'      : 'C',
              '.txx'    : 'C',
              '.y'      : 'C',
              #'.dts'    : 'C',
              #'.dtsi'   : 'C',
              '.cs'     : 'C#',
              '.groovy' : 'Java',
              '.java'   : 'Java',
              '.jsp'    : 'Java',
              '.scala'  : 'Java',
              '.as'     : 'ActionScript',
              '.js'     : 'JavaScript',
              '.php'    : 'PHP',
              '.py'     : 'Python',
             }

## compute SHA256 and TLSH
def scanfiles((directory, filename)):
	fullpathname = os.path.join(directory, filename)
	scanfile = open(fullpathname, 'rb')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()

	tlshhash = None
	if not os.stat(fullpathname).st_size < 256:
		tlshdata = open(fullpathname, 'rb').read()
		tlshhash = tlsh.hash(tlshdata)

	return (filehash, tlshhash, filename)

def main(argv):
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-t", "--tagfile", action="store", dest="tagfile", help="path to tag file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.cfg == None:
		parser.error("Need configuration file")

	if options.tagfile == None:
		parser.error("Need tag file")

	if not os.path.exists(options.tagfile):
		print >>sys.stderr, "tag file does not exist"
		sys.exit(1)

	configfile = open(options.cfg, 'r')
	config = ConfigParser.ConfigParser()
	try:
		config.readfp(configfile)
	except Exception, e:
		print >>sys.stderr, e
		configfile.close()
		exit(1)

	## read the configuration file and find out which (package, origin) combinations are trusted.
	## If none is given no packages are trusted.
	gitconfigs = {}
	gitignoredirs = {}
	verbose = False

	for section in config.sections():
		if section == "global":
			continue
		elif section == "sourceverify":
			continue
		else:
			try:
				configtype = config.get(section, 'type')
			except:
				continue
			if configtype != 'project':
				continue
			giturl = None
			try:
				gitdirs = list(set(config.get(section, 'gitdirs').split(':')))
				if len(gitdirs) == 0:
					continue
				## now get the Git URL from the configuration file of the first Git repository
				g = os.path.normpath(gitdirs[0])
				if not os.path.exists(os.path.join(g, '.git')):
					print >>sys.stderr, "directory %s is not a valid Git repository" % g
					continue
				## check if it is the same git repository
				gitconfiglines = open(os.path.join(g, '.git', 'config')).readlines()
				for gc in gitconfiglines:
					if 'url =' in gc:
						gu = gc.split('=', 1)[1].strip()
						giturl = gu
				if giturl != None:
					gitconfigs[giturl] = g
			except:
				continue
			try:
				ignoredirs = list(set(config.get(section, 'gitignoredirs').split(':')))
				gitignoredirs[giturl] = ignoredirs
			except:
				gitignoredirs[giturl] = []
				continue
	configfile.close()

	tagfile = open(options.tagfile, 'rb')
	tagfilelines = tagfile.readlines()
	tagfile.close()

	vals = tagfilelines[0].strip().split('\t')
	if len(vals) != 2:
		print >>sys.stderr, "tag file malformed, exiting"
		sys.exit(1)

	gitrepo1 = vals[0]
	gitrepo2 = vals[1]

	if not gitrepo1 in gitconfigs:
		print >>sys.stderr, "Git repository %s not in configuration file, exiting" % gitrepo1
		sys.exit(1)
	if not gitrepo2 in gitconfigs:
		print >>sys.stderr, "Git repository %s not in configuration file, exiting" % gitrepo2
		sys.exit(1)

	tags1 = []
	tags2 = []

	for i in tagfilelines[1:]:
		vals = i.strip().split('\t')
		if len(vals) != 2:
			print >>sys.stderr, "tag file malformed, exiting"
			sys.exit(1)
		tags1.append(vals[0])
		tags2.append(vals[1])

	pool = Pool()

	## TODO: cache results in case some of the tags are actually the same
	## in subsequent runs.
	for tr in range(0,len(tags1)):
		print "comparing tags %s and %s" % (tags1[tr], tags2[tr])
		sys.stdout.flush()

		sha256filespertag = {}

		filestorepo = {}
		filestorepo[gitrepo1] = set()
		filestorepo[gitrepo2] = set()

		## First switch both Git directories to the right tags
		## Then walk all the files in one directory and compute SHA256 and TLSH
		## Then walk all the files in the other directory and compute SHA256 and TLSH
		for t in [(tags1[tr], gitrepo1), (tags2[tr], gitrepo2)]:
			p = subprocess.Popen(['git', 'checkout', '-f', t[0]], cwd=gitconfigs[t[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()

			filestoscan = set()

			try:
				osgen = os.walk(gitconfigs[t[1]], topdown=True)
				skiplist = set(map(lambda x: os.path.join(gitconfigs[t[1]], x), gitignoredirs[t[1]]))
				while True:
					i = osgen.next()
					if i[0] in skiplist:
						#print "skipping", i[0], skiplist
						continue
					for d in i[1]:
						## make sure we can access all directories first
						if not os.path.islink("%s/%s" % (i[0], d)):
							os.chmod("%s/%s" % (i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
						if d in gitignoredirs[t[1]]:
							i[1].remove(d)
					for filename in i[2]:
						## make sure we can access all files first
						try:
							if not os.path.islink("%s/%s" % (i[0], filename)):
								os.chmod("%s/%s" % (i[0], filename), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
						except Exception, e:
							#print e
							pass
						if os.path.islink("%s/%s" % (i[0], filename)):
							continue
						if os.stat("%s/%s" % (i[0], filename)).st_size == 0:
							continue
						f_nocase = filename.lower()
						process = False
						for extension in extensions.keys():
							if (f_nocase.endswith(extension)):
								process = True
								break
						if not process:
							continue
						relpath = os.path.join(i[0][len(gitconfigs[t[1]])+1:], filename)
						filestoscan.add((gitconfigs[t[1]], relpath))
						filestorepo[t[1]].add(relpath)

			except StopIteration:
				pass

			if verbose:
				print "SCANNING %d files" % len(filestoscan)
				sys.stdout.flush()

			scansha256 = pool.map(scanfiles, filestoscan, 1)
			sha256filespertag[t] = scansha256

		filetohashes1 = {}
		filetohashes2 = {}

		toosmall = set()

		for ta in sha256filespertag[(tags1[tr], gitrepo1)]:
			(filehash, tlshhash, filename) = ta
			if tlshhash == None:
				toosmall.add(filename)
			filetohashes1[filename] = (filehash, tlshhash)

		for ta in sha256filespertag[(tags2[tr], gitrepo2)]:
			(filehash, tlshhash, filename) = ta
			if tlshhash == None:
				toosmall.add(filename)
			filetohashes2[filename] = (filehash, tlshhash)

		identicalfiles = set()
		notfoundfiles = set()
		zerotosixty = set()
		sixtyoneto150 = set()
		over150 = set()

		tlshscore = 0
		for ta in filetohashes1:
			if ta in filetohashes2:
				if filetohashes1[ta] == filetohashes2[ta]:
					identicalfiles.add(ta)
				else:
					if ta in toosmall:
						if verbose:
							print 'too small', ta
						continue
					tmptlsh = tlsh.diff(filetohashes1[ta][1], filetohashes2[ta][1])
					tlshscore += tmptlsh
					if tmptlsh <= 60:
						zerotosixty.add(ta)
					elif tmptlsh <=150:
						sixtyoneto150.add(ta)
					else:
						over150.add(ta)
			else:
				tlshscore += 400

		print "FILES SCANNED: %d" % len(filetohashes1)
		print "TOTAL DISTANCE: %d" % tlshscore
		print "IDENTICAL FILES: %d" % len(identicalfiles)
		print "0-60: %d" % len(zerotosixty)
		print "61-150: %d" % len(sixtyoneto150)
		print "over 150: %d" % len(over150)
		print
		sys.stdout.flush()

	pool.terminate()

if __name__ == "__main__":
	main(sys.argv)
