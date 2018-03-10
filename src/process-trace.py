#!/usr/bin/python3

## Yaminabe 3 project: Trace processor
##
## Background information:
##
## * http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
## * http://rebels.ece.mcgill.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html
##
## SPDX-License-Identifier: GPL-3.0
##
## Copyright 2017-2018 - Armijn Hemel for Tjaldur Software Governance Solutions
##
## ---- USAGE ----
##
## First trace a Linux kernel build with (for example) the following command:
##
## strace -e trace=%file,process,dup,dup2,close,pipe,fchdir -y -qq -f -s 256 make 2> ../linux-strace
##
## and then run this script on the output.
##
## Make sure there is enough disk space available, as trace files for the
## Linux kernel tend to be quite big.

import sys, os, re, datetime, copy, shutil
import argparse, configparser

## regular expression for process IDs (PIDs)
pidre = re.compile('\[pid\s+(\d+)\]')

## some precompiled regular expressions for interesting system calls
## valid filename characters:
## <>\w/\-+,.*$:;
chdirre = re.compile("chdir\(\"([\w/\-_+,.]+)\"\s*\)\s+=\s+(\d+)")
fchdirre = re.compile("fchdir\((\d+)<(.*)>\s*\)\s+=\s+(\d+)")
getcwdre = re.compile("getcwd\(\"([\w/\-_+,.]+)\", \d+\)\s+=\s+")
openre = re.compile("open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
openatre = re.compile("openat\((\w+), \"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
openatre2 = re.compile("openat\((\w+)<(.*)>, \"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
renamere = re.compile("rename\(\"([\w/\-+,.]+)\",\s+\"([\w/\-+,.]+)\"\)\s+=\s+(\-?\d+)")
clonere = re.compile("clone\([\w/\-+,.=]+,\s+[\w|=]+,\s+[\w=]+?\)\s+=\s+(\-?\d+)")
cloneresumedre = re.compile("clone\s*resumed>\s*.*=\s+(\-?\d+)$")
vforkresumedre = re.compile("vfork\s*resumed>\s*\)\s*=\s*(\d+)")
vforkre = re.compile("vfork\(\s*\)\s*=\s*(\d+)")

def processline(traceline, defaultpid, pidtocwd, directories, ignorefiles, openfiles, basepath, defaultcwd):
	## then look at the 'regular' lines
	if '+++ exited with' in traceline:
		## this message can be in the trace file unless -qq is passed
		## as a parameter
		return
	if '--- SIGCHLD' in traceline:
		## The child process has exited, so remove information from the
		## data structures in case of PID wrapping (which can easily happen)
		sigchldres = re.search("si_pid=(\w+),", traceline)
		if sigchldres != None:
			sigchldpid = int(sigchldres.groups()[0])
			## remove this pid from everywhere
			del pidtocwd[sigchldpid]
		return

	syscallres = re.search("(\w+)\(", traceline)
	if syscallres != None:
		syscall = syscallres.groups()[0]
	else:
		## something really weird happening here, so exiting
		return

	## there are only a few syscalls that are interesting at the moment
	if syscall not in ['open', 'openat', 'chdir', 'fchdir', 'getcwd', 'rename', 'clone']:
		return

	## first determine the pid of the line
	if traceline.startswith('[pid '):
		pid = int(pidre.match(traceline).groups()[0])
	else:
		## This is the top level pid. It actually is possible to
		## later reconstruct the pid if the top level process
		## forks a process and the process returns, or if a vfork
		## call is resumed.
		if defaultpid != None:
			pid = defaultpid
		else:
			pid = 'default'

	if not pid in pidtocwd and pid != 'default':
		pidtocwd[pid] = defaultcwd

	if 'chdir(' in traceline:
		if 'fchdir(' in traceline:
			fchdirres = fchdirre.search(traceline)
			if fchdirres != None:
				fchdirfd = int(fchdirres.groups()[0])
				fullchdirpath = fchdirres.groups()[1]
				fchdirresult = fchdirres.groups()[2]
				pidtocwd[pid] = fullchdirpath
				directories.add(fullchdirpath)
		else:
			chdirres = chdirre.search(traceline)
			if chdirres != None:
				chdirpath = chdirres.groups()[0]
				chdirresult = int(chdirres.groups()[1])
				if chdirresult != 0:
					return
				if chdirpath == '.':
					return
				if chdirpath.startswith('/'):
					pidtocwd[pid] = chdirpath
					directories.add(chdirpath)
				else:
					if pid in pidtocwd:
						pidtocwd[pid] = os.path.normpath(os.path.join(basepath, pidtocwd[pid], chdirpath))
	if 'open(' in traceline:
		openres = openre.search(traceline)
		if openres != None:
			openreturn = openres.groups()[2]
			if openreturn == '-1':
				## -1 means "No such file or directory" so ignore
				return
			openpath = os.path.normpath(openres.groups()[0])
			openflags = set(openres.groups()[1].split('|'))
			fullopenpath = openres.groups()[3]

			if fullopenpath in directories:
				## directories can be safely ignored
				return

			## ignore files that should be ignored
			if fullopenpath in ignorefiles:
				return

			## if files have already been recorded they are not interesting
			if fullopenpath in openfiles:
				return

			## directories are not interesting, except to store the
			## file descriptor
			if 'O_DIRECTORY' in openflags:
				directories.add(fullopenpath)
				return
			## absolute paths are only relevant if
			## coming from the same source code directory
			if openpath.startswith('/'):
				if not openpath.startswith(basepath):
					return
			## now check the flags to see if a file is new. If so, it can
			## be added to ignorefiles
			if "O_RDWR" in openflags or "O_WRONLY" in openflags:
				if "O_CREAT" in openflags:
					if "O_EXCL" in openflags or "O_TRUNC" in openflags:
						ignorefiles.add(fullopenpath)
						return
			## add the full reconstructed path, relative to root
			openfiles.add(fullopenpath)

	if 'openat(' in traceline:
		openres = openatre.search(traceline)
		if openres != None:
			openfd = os.path.normpath(openres.groups()[0])
			openpath = os.path.normpath(openres.groups()[1])
			openflags = set(openres.groups()[2].split('|'))
			openreturn = openres.groups()[3]
			fullopenpath = openres.groups()[4]
		else:
			openres = openatre2.search(traceline)
			if openres != None:
				openfd = os.path.normpath(openres.groups()[0])
				openpath = os.path.normpath(openres.groups()[2])
				openflags = set(openres.groups()[3].split('|'))
				openreturn = openres.groups()[4]
				fullopenpath = openres.groups()[5]
		if openres != None:
			if fullopenpath in directories:
				## directories can be safely ignored
				return

			## ignore files that should be ignored
			if fullopenpath in ignorefiles:
				return

			## if files have already been recorded they are not interesting
			if fullopenpath in openfiles:
				return
			## directories are not interesting, so record them to ignore them
			if 'O_DIRECTORY' in openflags:
				directories.add(fullopenpath)
				return
			if openpath.startswith('/'):
				if not openpath.startswith(basepath):
					return
			## now check the flags to see if a file is new
			if "O_RDWR" in openflags or "O_WRONLY" in openflags:
				if "O_CREAT" in openflags:
					if "O_EXCL" in openflags or "O_TRUNC" in openflags:
						ignorefiles.add(fullopenpath)
						return
			## add the full reconstructed path, relative to root
			openfiles.add(fullopenpath)
	if 'rename(' in traceline:
		renameres = renamere.search(traceline)
		if renameres != None:
			sourcefile = os.path.normpath(os.path.join(pidtocwd[pid], renameres.groups()[0]))
			targetfile = os.path.normpath(os.path.join(pidtocwd[pid],renameres.groups()[1]))
			## check if sourcefile is in ignorefiles. If so, then targetfile should be as well.
			if sourcefile in ignorefiles:
				ignorefiles.add(targetfile)

def main(argv):
	parser = argparse.ArgumentParser()

	## the following options are provided on the commandline
	#parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_argument("-f", "--tracefile", action="store", dest="tracefile", help="path to trace file", metavar="FILE")
	parser.add_argument("-b", "--basepath", action="store", dest="basepath", help="base path of Linux kernel source directory", metavar="BASEPATH")
	parser.add_argument("-t", "--tempdir", action="store", dest="tempdir", help="directory to write temporary files", metavar="DIR")
	args = parser.parse_args()

	if args.tracefile == None:
		parser.error("Trace file missing")

	if not os.path.exists(args.tracefile):
		parser.error("Trace file does not exist")

	if not os.path.isfile(args.tracefile):
		parser.error("Trace file is not a file")

	if args.basepath == None:
		parser.error("basepath for source directory missing")

	if not os.path.isabs(args.basepath):
		parser.error("basepath not an absolute path")

	## TODO: symbolic links are actually resolved by strace when using
	## the -y option, so make sure that the basepath is first resolved as
	## well.
	basepath = os.path.normpath(args.basepath)

	tempdir = None
	if args.tempdir != None:
		if not os.path.exists(args.tempdir):
			parser.error("directory to write temporary files does not exist")
		tempdir = args.tempdir

	tracefile = open(args.tracefile, 'r')

	defaultcwd = ''
	firstgetcwd = False

	pidtocwd = {}
	#pidtocwd['default'] = defaultcwd

	directories = set()

	## the pid of the first process is not shown in the trace file until after
	## returning from the first clone/execve/etc.
	## It is easy to find out what the top level PID is by keeping track of
	## which PIDs are known. When a system call is resumed for an unknown PID
	## that will be the top level PID.
	knownpids = set()

	## set a dummy value for the first PID
	defaultpid = None

	openfiles = set()

	## a list of files created or overwritten, so can be ignored later on
	ignorefiles = set()

	backlog = []
	backlogged = False

	for i in tracefile:
		## either there is an exit code, or the system call is unfinished. The rest
		## is irrelevant garbage.
		## Assume that strace is running in English. Right now (March 8, 2018) strace
		## has not been translated, so this is a safe assumption.
		if not ('=' in i or 'unfinished' in i):
			continue

		## first determine the pid of the line
		if i.startswith('[pid '):
			pid = int(pidre.match(i).groups()[0])
		else:
			## This is the top level pid. It actually is possible to
			## later reconstruct the pid if the top level process
			## forks a process and the process returns, or if a vfork
			## call is resumed.
			if defaultpid != None:
				pid = defaultpid
			else:
				pid = 'default'

		if 'getcwd(' in i:
			if not firstgetcwd:
				cwd = getcwdre.match(i).groups()[0]
				defaultcwd = cwd
				firstgetcwd = True
				if not 'default' in pidtocwd:
					pidtocwd['default'] = cwd
					directories.add(cwd)
				continue

		## cloned processes inherit the cwd of the parent process
		elif 'clone(' in i:
			if '<unfinished ...>' in i:
				backlog.append(i.strip())
				backlogged = True
				continue
			cloneres = clonere.search(i)
			if cloneres != None:
				clonepid = int(cloneres.groups()[0])
				pidtocwd[clonepid] = copy.deepcopy(pidtocwd[pid])

		## look through the lines with 'resumed' to find the PIDs of child processes
		## and store them.
		if " resumed>" in i:
			## This is an alternative way to get to the first PID in some circumstances
			if pid not in knownpids:
				defaultpid = pid
				pidtocwd[pid] = copy.deepcopy(pidtocwd['default'])
			if 'vfork' in i:
				vforkres = vforkresumedre.search(i)
				if vforkres != None:
					vforkpid = int(vforkres.groups()[0])
					pidtocwd[vforkpid] = copy.deepcopy(pidtocwd[pid])
			elif 'clone' in i:
				cloneres = cloneresumedre.search(i.strip())
				if cloneres != None:
					clonepid = int(cloneres.groups()[0])
					pidtocwd[clonepid] = copy.deepcopy(pidtocwd[pid])
					if backlog != []:
						for traceline in backlog:
							processline(traceline, defaultpid, pidtocwd, directories, ignorefiles, openfiles, basepath, defaultcwd)
						backlog = []
						backlogged = False

		if backlogged:
			backlog.append(i.strip())
			continue

		## add the pid to the list of known PIDs
		knownpids.add(pid)

		## then look at the lines that have either 'unfinished' or 'resumed'
		## Because the -y flag to strace is doing the heavy lifting just a bit of processing
		## needs to be done for open() and openat() to make sure that false positives are
		## not included.
		if "<unfinished ...>" in i or " resumed>" in i:
			if not ' resumed>' in i:
				if 'open(' in i or 'openat(' in i:
					processopen = False
					if 'openat(' in i:
						openatres = re.search("openat\((\w+), \"([<>\w/\-+,.]+)\", ([\w|]+)", i.strip())
						if openatres != None:
							openfd = os.path.normpath(openatres.groups()[0])
							openpath = os.path.normpath(openatres.groups()[1])
							openflags = set(openatres.groups()[2].split('|'))
							processopen = True
					elif 'open(' in i:
						openres = re.search("open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)", i.strip())
						if openres != None:
							openpath = os.path.normpath(openres.groups()[0])
							openflags = set(openres.groups()[1].split('|'))
							processopen = True

					if processopen:
						## now check the flags to see if a file is new. If so, it can
						## be added to ignorefiles
						## Don't look at directories here, as sometimes regular files are
						## opened with O_DIRECTORY and will fail with -1, which can only
						## be found out later. This is too risky and could lead to files
						## being ignored that should not be ignored.
						if "O_RDWR" in openflags or "O_WRONLY" in openflags:
							if "O_CREAT" in openflags:
								if "O_EXCL" in openflags or "O_TRUNC" in openflags:
									openpath = os.path.normpath(os.path.join(pidtocwd[pid], openpath))
									ignorefiles.add(openpath)
			else:
				## look at 'resumed'
				if '<... open' in i:
					openres = re.search('<... open(?:at)? resumed> \)\s+=\s+(?P<return>\-?\d+)', i)
					if openres != None:
						openreturn = openres.group('return')
						if openreturn != '-1':
							## only look at files that can be succesfully opened
							openres = re.search('<... open(:?at)? resumed> \)\s+=\s+\d+<(?P<path>.*)>$', i)
							if openres != None:
								openpath = openres.group('path')

								## absolute paths are only relevant if
								## coming from the same source code directory
								if openpath.startswith('/'):
									if not openpath.startswith(basepath):
										continue

								if openpath in ignorefiles:
									## not interested in files that have been created by
									## the process, as they will not have been in the
									## original source code tree
									continue

								if openpath in openfiles:
									## files that are already recorded as open
									## can be ignored
									continue

								if openpath in directories:
									## directories can be safely ignored
									continue

								## add the full reconstructed path, relative to root
								openfiles.add(openpath)
		else:
			processline(i.strip(), defaultpid, pidtocwd, directories, ignorefiles, openfiles, basepath, defaultcwd)

	print("END RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

	targetdir = '/tmp/busy'
	for i in openfiles:
		if not os.path.exists(i):
			continue
		basedir = os.path.dirname(i[len(basepath)+1:])
		if basedir != '':
			try:
				os.makedirs(os.path.join(targetdir, basedir))
			except:
				pass
			shutil.copy(i, os.path.join(targetdir, basedir))
		else:
			shutil.copy(i, targetdir)

if __name__ == "__main__":
	main(sys.argv)
