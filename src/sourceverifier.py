#!/usr/bin/python

## Copyright 2012-2017 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Yaminabe 2 project

This program was originally written for the OSADL License Compliance Audit:

https://www.osadl.org/License-Compliance-Audit.osadl-services-lca.0.html

This program checks source code archives for completeness of source
code (needs database from Binary Analysis Tool), plus optionally scans
licenses using Ninka and optionally FOSSology and compute distances
using TLSH.

It also checks for various "smells", such as:

* binary artefacts (pre-built packages, pre-built tools from SDK)
* leftovers from revision control systems (mainly Subversion)

'''

import os, os.path, sys, hashlib, subprocess, stat, tempfile, psycopg2
import magic, ConfigParser
from optparse import OptionParser
import multiprocessing, Queue
try:
	import tlsh
	tlshscan = True
except Exception, e:
	tlshscan = False

## list of lowercase extensions, plus what language they should be mapped to
## This is not necessarily correct, but right now it is the best we have.
## Keep in sync with createdb.py from BAT
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
              '.dts'    : 'C',
              '.dtsi'   : 'C',
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

def checktrusted(scanqueue, reportqueue, cursor, conn, trustedpackages):
	localcursor = conn.cursor()
        while True:
                filehash = scanqueue.get()
		untrusted = set()
		trusted = set()
		cursor.execute('select distinct package, version from processed_file where checksum=%s', (filehash,))
		conn.commit()
		res = cursor.fetchone()
		next_entry = False

		while res != None:
			(package, version) = res
			localcursor.execute('select origin from processed where package=%s and version=%s', (package,version))
			conn.commit()
			origins = localcursor.fetchall()
			## the package is not in trustedpackages
			for o in origins:
				if package not in trustedpackages.keys():
					untrusted.add(o[0])
					continue
				trusted_origins = trustedpackages[package]
				if o[0] in trusted_origins:
					trusted.add(o[0])
					next_entry = True
					break
				else:
					untrusted.add(o[0])
			if next_entry:
				break
			res = cursor.fetchone()

		reportqueue.put((filehash, trusted, untrusted))
		scanqueue.task_done()

## compute TLSH
def scantlsh((filehash, filedir, filename, cursor, conn, gitconfigs, trustedrepositories)):
	## first check if there is an exact match
	cursor.execute('select filepath, gitrevision, giturl from tlshentries where sha256sum=%s', (filehash,))
	res = cursor.fetchall()
	if len(res) != 0:
		if filter(lambda x: x[2] in trustedrepositories, res) != []:
			results = ('exact', filter(lambda x: x[2] in trustedrepositories, res))
			cursor.close()
			conn.close()
			return results

	## then compute the TLSH hash and search in the database
	## for the closest file.
	tlshfile = os.path.join(filedir, filename)
	tlshdata = open(tlshfile).read()
	tlshhash = tlsh.hash(tlshdata)

	if tlshhash == '':
		## file is either too small or a hash cannot be
		## computed (example: all characters are the same)
		results = ('undetermined', None)
		return results
	cursor.execute('select sha256sum, endindex, tlsh, gitrevision, giturl from tlshentries where filename=?', (os.path.basename(filename),))
	res = cursor.fetchall()
	minhash = sys.maxint
	mostpromising = None
	mostpromisinggitrevision = None
	mostpromisingrepo = None
	mostpromisingindex = None
	for b in res:
		(sha256sum, fileindex, tlshsum, gitrevision, giturl) = b
		if tlshsum == None:
			continue
		if not giturl in trustedrepositories:
			continue
		tlshdiff = tlsh.diff(tlshhash, tlshsum)
		if tlshdiff < minhash:
			minhash = tlshdiff
			mostpromising = sha256sum
			mostpromisinggitrevision = gitrevision
			mostpromisingrepo = giturl
			mostpromisingindex = fileindex

	if mostpromising != None:
		## now compute the patch id in both directions and see if there is
		## a known patch in a Git repository that was perhaps cherry picked
		if mostpromisingrepo in gitconfigs:
			p = subprocess.Popen(['git', 'show', mostpromisingindex], cwd=gitconfigs[mostpromisingrepo], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()
			## TODO: sanity checks
			## create a temporary file with the contents
			## of the closest revision
			tmpgitfile = tempfile.mkstemp()
			os.write(tmpgitfile[0], stanout)
			os.fdopen(tmpgitfile[0]).close()

			## compute the patch between the closest revision and the scan file
			## and look it up in the database
			p = subprocess.Popen(['git', 'diff', tmpgitfile[1], tlshfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()

			p1 = subprocess.Popen(['git', 'patch-id'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p1.communicate(stanout)
			patchid1 = stanout.split()[0]
			res = cursor.execute('select gitrevision, giturl from patchids where patchid=?', (patchid1,)).fetchall()
			if res == []:
				## compute the patch between the scan file and the closest revision
				## and look it up in the database
				p = subprocess.Popen(['git', 'diff', tlshfile, tmpgitfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()

				p1 = subprocess.Popen(['git', 'patch-id'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p1.communicate(stanout)
				patchid2 = stanout.split()[0]
				res = cursor.execute('select gitrevision, giturl from patchids where patchid=?', (patchid2,)).fetchall()
			if res != []:
				print 'blah'
			os.unlink(tmpgitfile[1])
		results = ('notexact', (filedir, filename, mostpromisinggitrevision, minhash, mostpromisingrepo))
		return results 
	return

## run ninka and fossology scans here
def licensescan((filehash, filedir, filename)):
	ninkaversion = "2.0-pre1"
	ninkaenv = os.environ.copy()
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	#ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath
	ninkaenv['PERL5LIB'] = "%s/lib" % ninkabasepath

	ninkares = set()
	fossologyres = set()

	p = subprocess.Popen(["%s/bin/ninka" % ninkabasepath, os.path.join(filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	(stanout, stanerr) = p.communicate()
	ninkasplit = stanout.strip().split(';')[1:]
	## filter out the licenses that cannot be determined.
	if ninkasplit[0] == '':
		ninkares = ['UNKNOWN']
	else:
		ninkares.update(ninkasplit[0].split(','))

	## Also run the stand alone Nomos scanner from FOSSology. This requires FOSSology 2.4 or later.
	p = subprocess.Popen(["/usr/share/fossology/nomos/agent/nomossa", "%s/%s" % (filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	(stanout, stanerr) = p.communicate()
	fosslines = stanout.strip().split("\n")
	for j in range(0,len(fosslines)):
		fossysplit = fosslines[j].strip().rsplit(" ", 1)
		licenses = fossysplit[-1].split(',')
		fossologyres.update(licenses)
	return (filehash, filedir, filename, ninkares, fossologyres)

def scanfiles(scanqueue, reportqueue, cursor, conn):
	while True:
		(directory, filename) = scanqueue.get()

		scanfile = open(os.path.join(directory, filename), 'r')
		h = hashlib.new('sha256')
		h.update(scanfile.read())
		scanfile.close()
		filehash = h.hexdigest()
		cursor.execute('select * from processed_file where checksum=%s LIMIT 1', (filehash,))
		res = cursor.fetchall()
		conn.commit()
		if res == []:
			found = False
		else:
			found = True
		reportqueue.put((filehash, directory, filename, found))
		scanqueue.task_done()

def main(argv):
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-s", "--directory", action="store", dest="scandir", help="path to top level directory to scan", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.scandir == None:
		parser.error("Need top level directory to scan")
	if options.cfg == None:
		parser.error("Need configuration file")

	if not os.path.exists(options.scandir):
		print >>sys.stderr, "Scan directory does not exist"
		exit(1)
	if not os.path.exists(options.cfg):
		print >>sys.stderr, "Configuration file does not exist"
		exit(1)

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
	trustedpackages = {}
	scanlicense = False
	gitconfigs = {}
	tlshdb = None
	verbose = False
	trustedrepositories = set()
	giturltopriority = {}

	for section in config.sections():
		if section == "global":
			continue
		if section == "sourceverify":
			try:
				postgresql_user = config.get(section, 'postgresql_user')
				postgresql_password = config.get(section, 'postgresql_password')
				postgresql_db = config.get(section, 'postgresql_db')
			except:
				print >>sys.stderr, "Configuration file malformed: missing database information"
				configfile.close()
				sys.exit(1)
			try:
				verboseconf = config.get(section, 'verbose')
				if verboseconf == 'yes':
					verbose = True
			except:
				pass
			try:
				scanlicenseconf = config.get(section, 'scanlicense')
				if scanlicenseconf == 'yes':
					scanlicense = True
			except:
				pass
			try:
				trusted = config.get(section, 'trusted')
				trustedsplits = trusted.split(':')
				for t in trustedsplits:
					tsplits = t.split('|')
					if len(tsplits) != 2:
						print >>sys.stderr, "Configuration file malformed: trusted sources"
						configfile.close()
						sys.exit(1)
					(package, origin) = tsplits
					if package in trustedpackages:
						trustedpackages[package].add(origin)
					else:
						trustedpackages[package] = set([origin])
			except:
				## no sources are explicitely trusted, so trust none...
				pass
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
				g = gitdirs[0]
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
				trusteddata = config.get(section, 'trustedrepository')
				if trusteddata == 'yes':
					if giturl != None:
						trustedrepositories.add(giturl)
			except:
				pass
			try:
				priority = int(config.get(section, 'priority'))
			except: 
				print >>sys.stderr, "Priority not specified in configuration for %s. Setting priority to infinity." % section
				priority = sys.maxint
			if giturl != None:
				giturltopriority[giturl] = priority
	configfile.close()

	## sanity checks for the database
	try:
		c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password)
		c.close()
	except:
		print >>sys.stderr, "Database server not running or malconfigured, exiting."
		sys.exit(1)

	filestoscan = set()

	## keep track of which files cannot be found at all in the database
	notfoundfiles = []

	## keep track of which files are found, but not from a trusted source
	untrusted = []

	## keep track of any other smells in the source archive
	smells = {}

	try:
		osgen = os.walk(options.scandir, topdown=True)
		skiplist = set()
		while True:
			i = osgen.next()
			if i[0] in skiplist:
				print "skipping", i[0], skiplist
				continue
			for d in i[1]:
				## make sure we can access all directories first
				if not os.path.islink("%s/%s" % (i[0], d)):
					os.chmod("%s/%s" % (i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				## then search for smells
				if d == '.svn':
					if 'svn' in smells:
						smells['svn'].add(os.path.normpath("%s/.svn" % i[0]))
					else:
						smells['svn'] = set([os.path.normpath("%s/.svn" % i[0])])
					skiplist.add(os.path.normpath("%s/.svn" % i[0]))
					i[1].remove('.svn')
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
				## then do a few more sanity checks for smells, such as
				## * vim swap files
				## * binary files
				## * .gitignore files
				if filename.startswith('.') and filename.endswith('.swp'):
					datafile = open(filename, 'rb')
					databuffer = datafile.read(6)
					datafile.close()
					if databuffer == 'b0VIM\x20':
						if 'vim' in smells:
							smells['vim'].append("%s/%s" % (i[0], filename))
						else:
							smells['vim'] = ["%s/%s" % (i[0], filename)]
					continue
				filestoscan.add((i[0], filename))
			
	except StopIteration:
		pass

	if verbose:
		print "SCANNING %d files" % len(filestoscan)
		sys.stdout.flush()

	number_of_processors = multiprocessing.cpu_count()

	## keep a list of postgresql connections and cursors, for use in separate threads
	postgresql_conns = []
	postgresql_cursors = []

	for i in range(0,number_of_processors):
		c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password)
		cursor = c.cursor()
		postgresql_conns.append(c)
		postgresql_cursors.append(cursor)

	scanmanager = multiprocessing.Manager()
	scanqueue = scanmanager.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.JoinableQueue(maxsize=0)
	processes = []

	## add the files to scan to the scan queue
	map(lambda x: scanqueue.put(x), filestoscan)

	## now create a number of processes
	for i in range(0,number_of_processors):
		p = multiprocessing.Process(target=scanfiles, args=(scanqueue,reportqueue, postgresql_cursors[i], postgresql_conns[i]))
		processes.append(p)

	for p in processes:
		p.start()

	scanqueue.join()

	scansha256 = []

	while True:
		try:
			scansha256.append(reportqueue.get_nowait())
			reportqueue.task_done()
		except Queue.Empty, e:
			## Queue is empty
			break

	reportqueue.join()

	for p in processes:
		p.terminate()

	notfoundfiles = map(lambda x: x[:3], filter(lambda x: x[3] == False, scansha256))
	if verbose:
		print "%d FILES NOT FOUND IN DATABASE" % len(notfoundfiles)
		sys.stdout.flush()

	foundfiles = map(lambda x: x[:3], filter(lambda x: x[3] == True, scansha256))

	sha256tofiles = {}
	for f in foundfiles:
		if f[0] in sha256tofiles:
			sha256tofiles[f[0]].append((f[1], f[2]))
		else:
			sha256tofiles[f[0]] = [(f[1], f[2])]
	
	trust_tmp = []

	## new queues
	scanqueue = scanmanager.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.JoinableQueue(maxsize=0)

	## now find out if this file is from any of the "trusted" sources.
	map(lambda x: scanqueue.put(x[0]), foundfiles)

	## now create a number of processes
	processes = []

	for i in range(0,number_of_processors):
		p = multiprocessing.Process(target=checktrusted, args=(scanqueue,reportqueue, postgresql_cursors[i], postgresql_conns[i], trustedpackages))
		processes.append(p)

	for p in processes:
		p.start()

	scanqueue.join()

	while True:
		try:
			trust_tmp.append(reportqueue.get_nowait())
			reportqueue.task_done()
		except Queue.Empty, e:
			## Queue is empty
			break

	reportqueue.join()

	for p in processes:
		p.terminate()

	untrusted_tmp = filter(lambda x: x[1] == [], trust_tmp)
	for u in untrusted_tmp:
		untrusted_sha256s = sha256tofiles[u[0]]
		for ut in untrusted_sha256s:
			untrusted.append((u[0],) + ut)

	## If tlsh is enabled then try to find out if the file can be found in a directory
	## with TLSH hashes extracted from a Git repository
	exactmatchescount = 0
	exactuntrustedmatchescount = 0
	notexacts = []
	exactmatches = []
	exactuntrustedmatches = []
	nomatches = []
	undetermined = []
	tlshscore = 0
	if tlshscan != None and False:
		if verbose:
			print "COMPUTING AND COMPARING TLSH OF FILES NOT FOUND IN DATABASE\n"
			sys.stdout.flush()
		for t in untrusted:
			filehash = t[0]
			results = scantlsh(t + (postgresql_cursors[0], postgresql_conns[0], gitconfigs, trustedrepositories))
			if results != None:
				(resulttype, resultentries) = results
				if resulttype == 'exact':
					exactmatchescount += 1
					exactmatches.append((filehash, resultentries))
				elif resulttype == 'exactuntrusted':
					exactuntrustedmatchescount += 1
					exactuntrustedmatches.append((filehash, resultentries))
				elif resulttype == 'notexact':
					notexacts.append(resultentries)
				elif resulttype == 'undetermined':
					undetermined.append(t)
			else:
				nomatches.append(t)
		for t in notfoundfiles:
			filehash = t[0]
			## filehash, filedir, filename
			results = scantlsh(t + (postgresql_cursors[0], postgresql_conns[0], gitconfigs, trustedrepositories))
			if results != None:
				(resulttype, resultentries) = results
				if resulttype == 'exact':
					exactmatchescount += 1
					exactmatches.append((filehash, resultentries))
				elif resulttype == 'exactuntrusted':
					exactuntrustedmatchescount += 1
					exactuntrustedmatches.append((filehash, resultentries))
				elif resulttype == 'notexact':
					notexacts.append(resultentries)
				elif resulttype == 'undetermined':
					undetermined.append(t)
			else:
				nomatches.append(t)
		
		for n in notexacts:
			(filedir, filename, mostpromisinggitrevision, minhash, mostpromisinggiturl) = n
			if verbose:
				print "CLOSEST REVISION FOR %s IS %s FROM %s WITH DISTANCE %d\n" % (filedir[len(options.scandir):] + "/" + filename, mostpromisinggitrevision, mostpromisinggiturl, minhash)
				#print "CLOSEST REVISION FOR %s %s %d\n" % (filedir[len(options.scandir):] + "/" + filename, mostpromisinggiturl, minhash)
			tlshscore += minhash
		for t in nomatches:
			(filehash, filedir, filename) = t
			if verbose:
				print "NO MATCH FOR %s\n" % (filedir[len(options.scandir):] + "/" +  filename)
			tlshscore += 400
		for t in undetermined:
			(filehash, filedir, filename) = t
			if verbose:
				print "COULD NOT DETERMINE CLOSEST FOR %s\n" % (filedir[len(options.scandir):] + "/" +  filename)
			tlshscore += 400
		for t in exactmatches:
			(filehash, exactresults) = t
			bestresult = None
			for n in exactresults:
				(filepath, gitrevision, giturl) = n
				if bestresult == None:
					bestresult = n
					continue
				if giturltopriority[giturl] < giturltopriority[bestresult[2]]:
					bestresult = n
			if verbose:
				(filepath, gitrevision, giturl) = bestresult
				print "EXACT MATCH FOR %s IS %s IN %s FROM %s" % (filehash, filepath, gitrevision, giturl)
			if verbose:
				print
		for t in exactuntrustedmatches:
			(filehash, exactresults) = t
			for n in exactresults:
				(filepath, gitrevision, giturl) = n
				if verbose:
					print "EXACT UNTRUSTED MATCH FOR %s IS %s IN %s FROM %s" % (filehash, filepath, gitrevision, giturl)
			if verbose:
				print

		if verbose:
			print "EXACT MATCHES: %d\n" % exactmatchescount
			print "TOTAL TLSH SCORE: %d\n" % tlshscore
			sys.stdout.flush()

	if scanlicense and False:
		if verbose:
			print "DETERMINING LICENSE OF FILES NOT FOUND"
			sys.stdout.flush()
		notfoundfiles = pool.map(licensescan, notfoundfiles, 1)
	else:
		notfoundfiles = map(lambda x: x + ([], []), notfoundfiles)

	if verbose:
		if smells != {}:
			print "Smells found:\n"
			for i in smells:
				if i == 'vim':
					print "* Vim swap files found:"
					for s in smells[i]:
						print "  -", s
				if i == 'svn':
					print "* Subversion directories found:"
					for s in smells[i]:
						print "  -", s
				print

		## each entry in notfound files:
		## (filehash, filedir, filename, ninkares, fossologyres)
		if notfoundfiles != []:
			notfoundfiles = map(lambda x: (x[1][len(options.scandir):], x[2], x[3], x[4]), notfoundfiles)
			notfoundfiles.sort()
		for i in notfoundfiles:
			(filedir, filename, ninkares, fossologyres) = i
			#print "NOT FOUND\t%s\tNinka:\t%s\tFOSSology:\t%s" % (os.path.normpath(os.path.join(filedir, filename)), reduce(lambda x, y: x + y, ninkares), list(fossologyres))
			print "NOT FOUND\t%s\tNinka:\t%s\tFOSSology:\t%s" % (os.path.normpath(os.path.join(filedir, filename)), list(ninkares), list(fossologyres))
		if untrusted != []:
			untrusted = map(lambda x: (x[1][len(options.scandir):], x[2]), untrusted)
			untrusted.sort()
		for i in untrusted:
			continue
			#print "NOT TRUSTED", os.path.normpath(os.path.join(i[0], i[1]))
			#sys.stdout.flush()
	if tlshscan and tlshdb != None:
		print "TOTAL TLSH SCORE: %d\n" % tlshscore
		sys.stdout.flush()

if __name__ == "__main__":
	main(sys.argv)
