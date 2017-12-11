#!/usr/bin/python3

## Yaminabe 3 project: Trace processor
##
## SPDX-License-Identifier: GPL-3.0
##
## Copyright 2017 - Armijn Hemel for Tjaldur Software Governance Solutions
##
## ---- USAGE ----
##
## First trace a Linux kernel build with (for example) the following command:
##
## strace -e trace=file,process,dup,dup2,close,pipe -q -f -s 256 make 2> ../linux-strace
##
## and then run this script.
##
## Make sure there is enough disk space available, as trace files for the
## Linux kernel tend to be quite big.

import sys, os, re, datetime, copy
import argparse, configparser, tempfile
from collections import deque

## regular expression for process IDs (PIDs)
pidre = re.compile('\[pid\s+(\d+)\]')

## some precompiled regular expressions for interesting system calls
chdirre = re.compile("chdir\(\"([\w/\-_+,.]+)\"\s*\)\s+=\s+")
getcwdre = re.compile("getcwd\(\"([\w/\-_+,.]+)\", \d+\)\s+=\s+")
openre = re.compile("open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)")
openatre = re.compile("openat\((\w+), \"([<>\w/\-+,.]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)")
renamere = re.compile("rename\(\"([\w/\-+,.]+)\",\s+\"([\w/\-+,.]+)\"\)\s+=\s+(\-?\d+)")

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
		parser.error("basepath for Linux kernel source directory missing")

	if not os.path.isabs(args.basepath):
		parser.error("basepath for Linux kernel not an absolute path")

	basepath = os.path.normpath(args.basepath)

	tempdir = None
	if args.tempdir != None:
		if not os.path.exists(args.tempdir):
			parser.error("directory to write temporary files does not exist")
		tempdir = args.tempdir

	## The first step is to reconstruct some lines in the file and write them out to a file
	temporary_file = tempfile.mkstemp(dir=args.tempdir)
	reconstructed_file = open(temporary_file[1], 'w')
	tracefile = open(args.tracefile, 'r')

	## the pid of the first process is not shown in the trace file until after
	## returning from the first clone/execve/etc.
	## It is easy to find out what the top level PID is by keeping track of
	## which PIDs are known. When a system call is resumed for an unknown PID
	## that will be the top level PID.
	knownpids = set()

	## keep track of which syscalls are unfinished per PID
	unfinishedsyscalls = {}

	## set a dummy value for the first PID
	defaultpid = None

	linecounter = 0
	lines = deque([])

	## keep track of how many reconstructions are still pending
	pendingreconstruction = 0

	print("BEGIN RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

	for i in tracefile:
		if "<unfinished ...>" in i or " resumed>" in i:
			## grab the pid
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
			if " resumed>" in i:
				## This is an easy way to get to the first PID
				if pid not in knownpids:
					defaultpid = pid
					if 'default' in unfinishedsyscalls:
						unfinishedsyscalls[pid] = copy.deepcopy(unfinishedsyscalls['default'])
						del unfinishedsyscalls['default']
			knownpids.add(pid)
		## if <unfinished ...> is encountered
		## find a matching resumed> for the system call
		if "<unfinished ...>" in i:
			if pid == 'default':
				if defaultpid != None:
					pid == defaultpid
			## grab the name of the system call
			syscall = re.search("(\w+)\(", i).groups()[0]
			if syscall in ['vfork', 'open', 'openat', 'dup2', 'chdir', 'clone', 'pipe', 'fcntl']:
				if not pid in unfinishedsyscalls:
					unfinishedsyscalls[pid] = {}
				if not syscall in unfinishedsyscalls[pid]:
					unfinishedsyscalls[pid][syscall] = []
				unfinishedsyscalls[pid][syscall].append(linecounter)
				#print(linecounter)
				pendingreconstruction += 1
				lines.append(i.strip())
				linecounter += 1
			else:
				pass
		elif " resumed>" in i:
			## grab the name of the system call
			syscall = re.search("(\w+) resumed>", i).groups()[0]
			## then reconstruct and replace the original line with 'unfinished' with the
			## reconstructed line, but only for certain system calls
			if syscall in ['vfork', 'open', 'openat', 'dup2', 'chdir', 'clone', 'pipe', 'fcntl']:
				offset = unfinishedsyscalls[pid][syscall][-1]
				#print(i.strip(), offset)
				front = lines[offset].split(' <unfinished ...>', 1)[0]
				tail = i.split(' resumed> ', 1)[-1]
				reconstructed = front + tail
				lines[offset] = reconstructed
				unfinishedsyscalls[pid][syscall].remove(offset)
				pendingreconstruction -= 1
			else:
				pass
		else:
			if pendingreconstruction == 0:
				## no reconstructions pending, so flush everything
				## to a file and reset counters
				for l in lines:
					print(l, file=reconstructed_file)
				lines = deque([])
				linecounter = 0
				print(i.strip(), file=reconstructed_file)
			else:
				lines.append(i.strip())
				linecounter += 1

	## flush whatever is left in the buffer
	if pendingreconstruction == 0:
		## no reconstructions pending, so flush everything
		## to a file and reset counters
		for l in lines:
			print(l, file=reconstructed_file)

	tracefile.close()
	reconstructed_file.close()

	print("END RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

	openfiles = set()

	## a list of files created or overwritten, so can be ignored later on
	ignorefiles = set()

	firstcwd = ''
	defaultcwd = ''
	firstgetcwd = False
	pidtocwd = {}

	tracefile = open(temporary_file[1], 'r')
	for t in tracefile:
		## first determine the pid of the line
		if t.startswith('[pid '):
			pid = int(pidre.match(t).groups()[0])
		else:
			## This is the top level pid.
			if defaultpid != None:
				pid = defaultpid
			else:
				pid = 'default'

		if not pid in pidtocwd:
			pidtocwd[pid] = defaultcwd
		if 'getcwd(' in t:
			if not firstgetcwd:
				cwd = getcwdre.match(t).groups()[0]
				defaultcwd = cwd
				firstcwd = cwd
				firstgetcwd = True
				continue
		if 'chdir(' in t:
			res = chdirre.search(t)
			if res != None:
				chdirpath = res.groups()[0]
				chdirresult = res.groups()
				if chdirpath == '.':
					continue
				if chdirpath.startswith('/'):
					pidtocwd[pid] = chdirpath
				else:
					if pid in pidtocwd:
						pidtocwd[pid] = os.path.normpath(os.path.join(pidtocwd[pid], chdirpath))
		if 'rename(' in t:
			## check if files are renamed. If so, see if they are in 'ignored',
			## and if so add the renamed file to ignored as well
			res = renamere.search(t)
			if res != None:
				(orig, target, returncode) = res.groups()
				if returncode == 0:
					if orig.startswith('/'):
						orig = os.path.normpath(orig)
					else:
						orig = os.path.normpath(os.path.join(pidtocwd[pid], orig))
					if orig in ignored:
						if target.startswith('/'):
							target = os.path.normpath(target)
						else:
							target = os.path.normpath(os.path.join(pidtocwd[pid], target))
						ignored.add(target)
		if not ('open(' in t or 'openat(' in t):
			continue
		if 'open(' in t:
			res = openre.search(t.strip())
			if res != None:
				openpath = os.path.normpath(res.groups()[0])
				openflags = set(res.groups()[1].split('|'))
				openreturn = res.groups()[2]
				## ignore files in /proc and /dev as they are not interesting
				if openpath.startswith('/dev/') or openpath.startswith('/proc/'):
					continue
				if openreturn != '-1':
					if openpath in ignorefiles:
						continue
					## now check the flags to see if a file is new
					if "O_RDWR" in openflags or "O_WRONLY" in openflags:
						if "O_CREAT" in openflags:
							if "O_EXCL" in openflags or "O_TRUNC" in openflags:
								ignorefiles.add(openpath)
					else:
						## add the full reconstructed path, relative to root
						if 'O_DIRECTORY' in openflags:
							continue
						openfiles.add(openpath)
			#else:
				#print(t.strip())
		elif 'openat(' in t:
			pass
			## this needs some more work
			#res = openatre.search(t.strip())
			#if res != None:
				#print(res[0])
			#else:
				#print(t.strip())
	tracefile.close()

	for i in openfiles:
		print(i, file='/tmp/openfiles')

	#print(firstgetcwd)
	#for k in pidtocwd:
		#print(k, pidtocwd[k])


if __name__ == "__main__":
	main(sys.argv)
