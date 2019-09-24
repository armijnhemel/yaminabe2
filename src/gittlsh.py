#!/usr/bin/env python3

# Copyright 2015-2019 Armijn Hemel for Tjaldur Software Governance Solutions
# Licensed under Apache 2.0, see LICENSE file for details

'''
Walk a set of Git repositories and store:

* SHA256 and TLSH of each revision in a series of tags from a Git forest
* normalized hash of each patch (result of "git patch-id")
'''

import os
import os.path
import sys
import re
import subprocess
import hashlib
import sqlite3
import pickle
import copy
import multiprocessing
import configparser
import collections
import functools
import argparse
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array
import tlsh

numstatre = re.compile('\d+\t\d+\t(.*)')

# one process grabs the results from the queue and writes them to the database
def writeresults(reportqueue, gitdatabase, project, giturl, sha256seendict, patchiddict):
    conn = sqlite3.connect(gitdatabase)
    counter = 1
    cursor = conn.cursor()

    while True:
        res = reportqueue.get()
        (gitrevision, results, patchids, mergecommit, hascontent) = res
        if results == []:
            # record revisions that are not relevant, for example
            # revisions in which there is no interesting content or where
            # just some metadata (permissions, etc.) were changed.
            if hascontent:
                cursor.execute('insert into deletedrevisions (gitrevision, project, giturl) values (?,?,?)', (gitrevision, project, giturl))
            else:
                cursor.execute('insert into emptyrevisions (gitrevision, project, giturl) values (?,?,?)', (gitrevision, project, giturl))
            conn.commit()
        else:
            for result in results:
                (filename, sha256sum, tlshhash, endindex) = result
                if mergecommit:
                    # if the file is coming from a merge commit and
                    # it was already seen in another merge commit, then
                    # skip it.
                    if (filename, sha256sum) in sha256seendict:
                        continue
                    revisiontype = "merge"
                else:
                    revisiontype = "non-merge"
                cursor.execute('insert into tlshentries (filepath, endindex, sha256sum, tlsh, filename, project, gitrevision, revisiontype, giturl) values (?,?,?,?,?,?,?,?,?)',
                               (filename, endindex, sha256sum, tlshhash, os.path.basename(filename), project, gitrevision, revisiontype, giturl))
                sha256seendict[(filename, sha256sum)] = None

            # store all the patch ids for each individual patch into the
            # database as well.
            for patchid in patchids:
                if mergecommit:
                    if patchid in patchiddict:
                        continue
                cursor.execute('insert into patchids (patchid, gitrevision, giturl) values (?,?,?)',
                               (patchid, gitrevision, giturl))
                patchiddict[patchid] = None
            conn.commit()
        if counter % 200 == 0:
            print("processed revisions: %d" % counter)
            sys.stdout.flush()
        counter += 1
        reportqueue.task_done()

def gitscan(scanqueue, reportqueue, gitdir, lock, seendict, gitpath):
    threshold = 0.1
    while True:
        # get a new revision from the queue
        gitrevision = scanqueue.get()
        hashfiles = set()

        filternames = set()
        # get all the files that are affected
        p = subprocess.Popen([gitpath, 'show', '--pretty=oneline', '--numstat', gitrevision],
                             cwd=gitdir, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        for s in stanout.split(b'\n')[1:]:
            blameres = numstatre.match(s.decode())
            if blameres is None:
                # probably binary files such as gifs
                continue
            blamename = blameres.groups()[0]
            filternames.add(blamename)

        mergecommit = False
        p = subprocess.Popen([gitpath, 'show', '-s', gitrevision], cwd=gitdir,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        for s in stanout.split(b'\n'):
            if s.startswith(b'Merge:'):
                mergecommit = True
                break

        # first find out the total amount of files in the commit
        p = subprocess.Popen([gitpath, 'show', '--pretty=oneline', '--numstat', '-m', gitrevision],
                             cwd=gitdir, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        newtotalfiles = 0
        for s in stanout.split(b'\n')[1:]:
            blameres = numstatre.match(s.decode())
            if blameres is None:
                # probably binary files such as gifs
                continue
            newtotalfiles += 1

        hascontent = False
        if filternames != set():

            # get all the data from the merge commits (with/without
            # combined diff)
            # In some cases it is actually much faster to just look at
            # individual files that were changed, than processing all
            # the content of the entire revision.
            relative = False
            if len(filternames)/(newtotalfiles*1.0) <= threshold:
                if newtotalfiles > 400:
                    relative = True
            stopprocessing = False
            filenametoindex = {}
            for filtername in filternames:
                if stopprocessing:
                    break
                if relative:
                    p = subprocess.Popen([gitpath, 'show', '-m', gitrevision, '--relative=%s' % filtername],
                                         cwd=gitdir, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    p = subprocess.Popen([gitpath, 'show', '-m', gitrevision], cwd=gitdir,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

                (stanout, stanerr) = p.communicate()
                checkdiff = False
                gitsplit = set()
                currentpatch = []
                addpatch = False
                inpatch = False
                seendiff = False
                ignorepatch = False
                deletedfile = False
                endindex = None

                patchids = []
                for s in stanout.split(b'\n'):
                    if s.startswith(b'diff --git'):
                        # new patch starts here, so first store any patches
                        # that might already have been processsed
                        seendiff = True
                        if addpatch and currentpatch != []:
                            if newfilename in filternames:
                                # compute the Git patch id (SHA1) for the patches
                                pl = functools.reduce(lambda x, y: x + '\n' + y, currentpatch)
                                p2 = subprocess.Popen([gitpath, 'patch-id'], cwd=gitdir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                (pstanout, pstanerr) = p2.communicate(pl)
                                patchids.append(pstanout.decode().split()[0])
                                filenametoindex[newfilename] = endindex
                                hashfiles.update(gitsplit)

                        # reset some data
                        currentpatch = []
                        addpatch = False
                        inpatch = False
                        deletedfile = False
                        ignorepatch = False
                        endindex = None

                        checkdiff = True
                        if not relative:
                            # gitlen = len('diff --git a/') :: this is always 13
                            gitsplit = set(s[13:].split(b' b/'))
                            newgitsplit = set()
                            namefound = False
                            for g in gitsplit:
                                if not namefound and not g in filternames:
                                    ignorepatch = True
                                    break
                                newgitsplit.add(g)
                                namefound = True
                            gitsplit = newgitsplit
                        else:
                            gitsplit = set([filtername])
                        currentpatch.append(s)
                        continue
                    if not seendiff:
                        continue
                    if ignorepatch:
                        continue
                    currentpatch.append(s)
                    if checkdiff:
                        checkdiff = False

                        # some patches are simply not interesting
                        # at all: deleted files, symbolic links,
                        # permission changes, etc.
                        if s.startswith(b'deleted file'):
                            deletedfile = True
                            continue
                        elif s.startswith(b'new file mode 120000'):
                            ignorepatch = True
                            continue
                        elif s.startswith(b'index') and s.endswith(b'120000'):
                            ignorepatch = True
                            continue
                    if s.startswith(b'@@'):
                        inpatch = True
                    if s.startswith(b'index '):
                        hascontent = True
                        if mergecommit:
                            lock.acquire()
                            inseendict = s in seendict
                            lock.release()
                            if inseendict:
                                ignorepatch = True
                                continue
                        lock.acquire()
                        seendict[s] = None
                        lock.release()
                        endindex = s.rsplit(b'.', 1)[-1].split(b' ')[0]
                    if s.startswith(b'+++') and not inpatch and not deletedfile:
                        # only add if there actually is a modification
                        if not relative:
                            newfilename = s.split(b' b/', 1)[1]
                        else:
                            newfilename = filtername
                        addpatch = True

                if addpatch and currentpatch != []:
                    if newfilename in filternames:
                        pl = functools.reduce(lambda x, y: x + '\n' + y, currentpatch)
                        p2 = subprocess.Popen([gitpath, 'patch-id'], cwd=gitdir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        (pstanout, pstanerr) = p2.communicate(pl)
                        patchids.append(pstanout.split()[0])
                        filenametoindex[newfilename] = endindex
                        hashfiles.update(gitsplit)
                if not relative:
                    break

        res = []

        # compute the SHA256 and (if applicable) TLSH hashes for
        # each file after the patches have been applied (use the
        # end index for this)
        if hashfiles != set():
            for hf in hashfiles:
                try:
                    p = subprocess.Popen([gitpath, 'show', filenametoindex[hf]], cwd=gitdir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except Exception as e:
                    print('cannot git show', gitrevision, e, hf, filenametoindex[hf])
                (stanout, stanerr) = p.communicate()

                h = hashlib.new('sha256')
                h.update(stanout)
                filehash = h.hexdigest()
                tlshhash = None
                # only compute TLSH for files that are 256 bytes are more
                if len(stanout) >= 256:
                    tlshhash = tlsh.hash(stanout)
                res.append((hf, filehash, tlshhash, filenametoindex[hf]))

        # put all the results for this git revision into the report queue
        reportqueue.put((gitrevision, res, patchids, mergecommit, hascontent))
        scanqueue.task_done()

# The main method
def main(argv):
    optionparser = argparse.ArgumentParser()
    optionparser.add_argument("-c", "--config", action="store", dest="cfg",
                              help="path to configuration file", metavar="FILE")
    options = optionparser.parse_args()

    if options.cfg is not None:
        try:
            configfile = open(options.cfg, 'r')
        except:
            print("path '%s' does not exist. Exiting." % options.cfg, file=sys.stderr)
            sys.exit(1)
    else:
        optionparser.error("configuration file not supplied. Exiting.")

    # create a configuration parser and load the open configuration file
    # into it and then parse all options
    config = configparser.ConfigParser()
    config.readfp(configfile)

    # Process the configuration file. First process the global section
    # as other sections might depend on some of the values defined in it.
    for section in config.sections():
        if section != "global":
            continue
        try:
            gitdatabase = config.get(section, 'gitdatabase')
        except:
            print("Database for writing Git results not specified in configuration. Exiting.", file=sys.stderr)
            configfile.close()
            sys.exit(1)
        try:
            optimizedb = False
            getconf = config.get(section, 'optimizedb')
            if getconf == 'yes':
                optimizedb = True
        except:
            optimizedb = False
        try:
            # extract the location of the git binary, do some sanity checks
            # It can be useful to copy the 'git' binary to ramdisk to reduce
            # disk I/O as well
            gitpath = config.get(section, 'gitpath')
            if not os.path.exists(gitpath):
                gitpath = 'git'
        except:
            gitpath = 'git'
        try:
            processors = int(config.get(section, 'processors'))
        except:
            # one thread for writing
            processors = max(multiprocessing.cpu_count() - 1, 1)

    if not os.path.exists(os.path.dirname(os.path.normpath(gitdatabase))):
        print("Directory for storing database does not exist. Exiting.", file=sys.stderr)
        sys.exit(1)

    projects = []

    # Process the configuration file, other sections
    for section in config.sections():
        if section == "sourceverify":
            # "sourceverify" is used for another script so can be
            # be ignored here
            continue
        if section == "global":
            continue
        try:
            configtype = config.get(section, 'type')
        except:
            continue
        if configtype == 'project':
            enabled = False
            try:
                enabledconf = config.get(section, 'enabled')
                if enabledconf == 'yes':
                    enabled = True
            except:
                pass
            try:
                restorestate = False
                getconf = config.get(section, 'restorestate')
                if getconf == 'yes':
                    restorestate = True
            except:
                restorestate = False
            try:
                statefile = config.get(section, 'statefile')
            except:
                restorestate = False
            try:
                ramdisk = False
                getconf = config.get(section, 'ramdisk')
                if getconf == 'yes':
                    ramdisk = True
            except:
                ramdisk = False
            try:
                gitdirs = config.get(section, 'gitdirs').split(':')
            except:
                print("Git directories not specified in configuration. Skipping.", file=sys.stderr)
                continue
            giturl = None
            try:
                giturl = config.get(section, 'giturl')
            except:
                print("Git URL in %s not provided, extracting from source." % section, file=sys.stderr)
            try:
                project = config.get(section, 'project')
            except:
                print("Project name not specified in configuration. Skipping.", file=sys.stderr)
                continue
            try:
                priority = int(config.get(section, 'priority'))
            except:
                print("Priority not specified in configuration for %s. Setting priority to infinity." % section, file=sys.stderr)
                priority = sys.maxsize


            projects.append((project, gitdirs, ramdisk, statefile, restorestate, priority, enabled, giturl))

    configfile.close()

    if projects == []:
        print("No valid projects for scanning found. Exiting.", file=sys.stderr)
        sys.exit(1)

    if filter(lambda x: x[-2] == True, projects) == []:
        print("No projects for scanning found. Exiting.", file=sys.stderr)
        sys.exit(1)

    giturltopriority = {}
    newprojects = []

    for pr in projects:
        (project, gitdirs, ramdisk, statefile, restorestate, priority, enabled, origgiturl) = pr

        if not enabled:
            if origgiturl is not None:
                giturltopriority[origgiturl] = (project, priority)
            continue

        if ramdisk and len(gitdirs) == 1:
            gitdirs = gitdirs*processors

        print("Checking validity of Git repositories for project %s" % project)
        sys.stdout.flush()

        exitgit = False
        giturl = None
        headrevision = None
        for g in set(gitdirs):
            if not os.path.exists(os.path.join(g, '.git')):
                print("directory %s is not a valid Git repository" % g, file=sys.stderr)
                exitgit = True
                continue
            # check if it is the same git repository
            gitconfiglines = open(os.path.join(g, '.git', 'config'), 'r').readlines()
            for gc in gitconfiglines:
                if 'url =' in gc:
                    gu = gc.split('=', 1)[1].strip()
                    if giturl is None:
                        giturl = gu
                    else:
                        if giturl != gu:
                            print("config url %s for %s does not match %s" % (gu, g, giturl), file=sys.stderr)
                            exitgit = True
                            continue
        if giturl != origgiturl:
            exitgit = True
        if exitgit:
            if origgiturl is not None:
                giturltopriority[origgiturl] = (project, priority)
            print("Errors found in Git directories for project %s, continuing with configuration for next project" % project, file=sys.stderr)
            continue

        # TODO: make parallel
        if len(gitdirs) > 1:
            for g in set(gitdirs):
                # now check if the repositories are all up to date for the HEAD branch
                p = subprocess.Popen([gitpath, 'checkout', '-f', 'HEAD'], cwd=g, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (stanout, stanerr) = p.communicate()
                p = subprocess.Popen([gitpath, 'rev-list', '--max-count=1', 'HEAD'], cwd=g, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (stanout, stanerr) = p.communicate()
                githeadrevision = stanout.strip()
                if headrevision is None:
                    headrevision = githeadrevision
                if headrevision != githeadrevision:
                    print("directory %s does not match HEAD revision %s" % (g, headrevision), file=sys.stderr)
                    exitgit = True

        if exitgit:
            print("Errors found in Git directories for project %s, continuing with configuration for next project" % project, file=sys.stderr)
            continue

        if origgiturl is None:
            newprojects.append(pr[:-1] + (giturl,))
            giturltopriority[giturl] = (project, priority)
        else:
            newprojects.append(pr)
            giturltopriority[origgiturl] = (project, priority)

    if newprojects == []:
        print("No valid projects for scanning found. Exiting.", file=sys.stderr)
        sys.exit(1)

    # set the database and create database tables
    print("Setting up database")

    conn = sqlite3.connect(gitdatabase)
    cursor = conn.cursor()

    # Create the database table to store all the entries for each file in each Git revision
    cursor.execute('create table if not exists tlshentries (filepath text, endindex text, sha256sum text, tlsh text, filename text, project text, gitrevision text, revisiontype text, giturl text);')
    cursor.execute('create index if not exists tlshentries_filepath on tlshentries(filepath, sha256sum, giturl);')
    cursor.execute('create index if not exists tlshentries_endindex on tlshentries(endindex);')
    cursor.execute('create index if not exists tlshentries_sha256sum on tlshentries(sha256sum);')
    cursor.execute('create index if not exists tlshentries_project on tlshentries(project);')
    cursor.execute('create index if not exists tlshentries_gitrevision on tlshentries(gitrevision);')
    cursor.execute('create index if not exists tlshentries_filename on tlshentries(filename);')
    cursor.execute('create index if not exists tlshentries_tlsh on tlshentries(tlsh);')
    cursor.execute('create index if not exists tlshentries_giturl on tlshentries(giturl);')

    # Create a table to store the "empty revisions" which are revisions where there is no
    # interesting data, but files are either moved, permissions are changed, or files are
    # merely deleted.
    cursor.execute('create table if not exists emptyrevisions (gitrevision text, project text, giturl text);')
    cursor.execute('create index if not exists emptyrevisions_gitrevision on emptyrevisions(gitrevision);')
    cursor.execute('create index if not exists emptyrevisions_project on emptyrevisions(project);')
    cursor.execute('create index if not exists emptyrevisions_giturl on emptyrevisions(giturl);')

    # Create a table to store revisions that are deleted by the program if the database is optimized
    cursor.execute('create table if not exists deletedrevisions (gitrevision text, project text, giturl text);')
    cursor.execute('create index if not exists deletedrevisions_gitrevision on deletedrevisions(gitrevision);')
    cursor.execute('create index if not exists deletedrevisions_project on deletedrevisions(project);')
    cursor.execute('create index if not exists deletedrevisions_giturl on deletedrevisions(giturl);')

    cursor.execute('create table if not exists patchids (patchid text, gitrevision text, giturl text);')
    cursor.execute('create index if not exists patchids_gitrevision on patchids(gitrevision);')
    cursor.execute('create index if not exists patchids_patchid on patchids(patchid);')
    conn.commit()
    cursor.close()
    conn.close()

    for pr in newprojects:
        (project, gitdirs, ramdisk, statefile, restorestate, priority, enabled, giturl) = pr
        if not enabled:
            continue

        print("Scanning project %s with priority %d" % (project, priority))

        if ramdisk and len(gitdirs) == 1:
            gitdirs = gitdirs*processors

        p = subprocess.Popen([gitpath, 'rev-list', '--all'], cwd=gitdirs[0], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        gitrevisions = stanout.decode().strip().split('\n')
        processamount = len(gitdirs)

        if gitrevisions == []:
            print("No revisions to process, continuing with next project")
            sys.stdout.flush()
            continue

        print("Filtering revisions")
        sys.stdout.flush()

        # First select revisions that already have been processed before and filter them out
        # TODO: take priorities into account
        conn = sqlite3.connect(gitdatabase)
        cursor = conn.cursor()

        seenpatchids = []

        ignorerevisions = set()
        for g in gitrevisions:
            res = cursor.execute('select distinct giturl from tlshentries where gitrevision=?', (g,)).fetchall()
            if res != []:
                gitres = map(lambda x: x[0], res)
                if giturl in gitres:
                    ignorerevisions.add(g)
                    continue
                for r in gitres:
                    if r in giturltopriority:
                        if project == giturltopriority[r][0]:
                            if priority >= giturltopriority[r][1]:
                                ignorerevisions.add(g)
            res = cursor.execute('select distinct giturl from emptyrevisions where gitrevision=?', (g,)).fetchall()
            if res != []:
                gitres = map(lambda x: x[0], res)
                if giturl in gitres:
                    ignorerevisions.add(g)
                    continue
                for r in gitres:
                    if r in giturltopriority:
                        if project == giturltopriority[r][0]:
                            if priority >= giturltopriority[r][1]:
                                ignorerevisions.add(g)
            res = cursor.execute('select distinct giturl from deletedrevisions where gitrevision=?', (g,)).fetchall()
            if res != []:
                gitres = map(lambda x: x[0], res)
                if giturl in gitres:
                    ignorerevisions.add(g)
                    continue
                for r in gitres:
                    if r in giturltopriority:
                        if project == giturltopriority[r][0]:
                            if priority >= giturltopriority[r][1]:
                                ignorerevisions.add(g)
        #seenpatchids = map(lambda x: x[0], cursor.execute('select distinct patchid from patchids where giturl=?', (giturl,)))
        cursor.close()
        conn.close()

        gitrevisions = list(filter(lambda x: x not in ignorerevisions, gitrevisions))

        if gitrevisions == []:
            print("No revisions to process, continuing with next project")
            sys.stdout.flush()
            continue

        print("Processing %d revisions" % len(gitrevisions))
        sys.stdout.flush()

        lock = Lock()
        scanmanager = multiprocessing.Manager()
        if restorestate:
            if os.path.exists(statefile):
                statepicklefile = open(statefile, 'rb')
                (dumpgiturl, dumpdict, dumpsha256seendict, dumppatchiddict) = pickle.load(statepicklefile)
                statepicklefile.close()
                seendict = scanmanager.dict(dumpdict)
                sha256seendict = scanmanager.dict(dumpsha256seendict)
                patchiddict = scanmanager.dict(dumppatchiddict)
            else:
                seendict = scanmanager.dict()
                sha256seendict = scanmanager.dict()
                patchiddict = scanmanager.dict()
        else:
            seendict = scanmanager.dict()
            sha256seendict = scanmanager.dict()
            patchiddict = scanmanager.dict()

        for p in seenpatchids:
            patchiddict[p] = None

        scanqueue = scanmanager.JoinableQueue(maxsize=0)
        reportqueue = scanmanager.JoinableQueue(maxsize=0)
        processpool = []

        for g in gitrevisions:
            scanqueue.put(g)

        for i in range(0, processamount):
            p = multiprocessing.Process(target=gitscan,
                                        args=(scanqueue, reportqueue, gitdirs[i], lock, seendict, gitpath))
            processpool.append(p)

        r = multiprocessing.Process(target=writeresults,
                                    args=(reportqueue, gitdatabase, project, giturl, sha256seendict, patchiddict))
        processpool.append(r)

        for p in processpool:
            p.start()

        scanqueue.join()
        reportqueue.join()

        for p in processpool:
            p.terminate()

        # clean up the database. Search for files that are the same and which
        # occur in both merge commits and non-merge commits. Favour non-merge
        # commits. Leave non-merge commits alone.
        deletecandidates = set()
        if optimizedb:
            deletecandidates.update(gitrevisions)
            print("Cleaning up database")
            sys.stdout.flush()
            conn = sqlite3.connect(gitdatabase)
            cursor = conn.cursor()
            # check if any revisions were merged in both merge and non-merge variants.
            cursor.execute("select sha256sum, filepath from tlshentries where giturl=?", (giturl,))
            filechecksums = cursor.fetchall()
            optimizecounter = collections.Counter()
            optimizecounter.update(filechecksums)
            for f in filter(lambda x: x[1] != 1, optimizecounter.most_common()):
                (sha256sum, filepath) = f[0]
                cursor.execute("select revisiontype, gitrevision, giturl from tlshentries where sha256sum=? and filepath=?", (sha256sum, filepath))
                res = cursor.fetchall()
                if res != []:
                    nonmerges = filter(lambda x: x[0] == 'non-merge', res)
                    merges = filter(lambda x: x[0] != 'non-merge', res)
                    bestrepo = None
                    bestscore = None
                    if nonmerges != []:
                        # there are two or more non-merges with the same contents
                        # remove the ones that are least important
                        if len(set(map(lambda x: x[2], nonmerges))) == 1:
                            continue
                        bestrepo = nonmerges[0][2]
                        if bestrepo in giturltopriority:
                            bestscore = giturltopriority[bestrepo][1]
                        for r in nonmerges:
                            if not r[2] in giturltopriority:
                                continue
                            bestscoreandproject = giturltopriority[r[2]]
                            if bestscoreandproject[0] != project:
                                continue
                            if bestscore is None:
                                bestscore = bestscoreandproject[1]
                                bestrepo = r[2]
                            if bestscoreandproject[1] < bestscore:
                                bestrepo = r[2]
                                bestscore = bestscoreandproject[1]
                        if bestscore is not None:
                            # filter all the revisions that are not from the best repository
                            filteredres = filter(lambda x: x[2] != bestrepo, nonmerges)
                            filtered2 = filter(lambda x: x[2] in giturltopriority, filteredres)
                            for f2 in filtered2:
                                # revision = f2[1]
                                # url = f2[2]
                                # TODO: fix this, as it is unindexed right now :-/
                                cursor.execute("delete from tlshentries where sha256sum=? and filepath=? and giturl=? and gitrevision=?", (sha256sum, filepath, f2[2], f2[1]))
                            deletecandidates.update(map(lambda x: x[1], filtered2))

                    if merges != []:
                        if nonmerges != []:
                            # first clean up all merge commits for each repo for
                            # which there are also non-merge commits
                            for n in nonmerges:
                                cursor.execute("delete from tlshentries where sha256sum=? and filepath=? and giturl=? and revisiontype='merge'", (sha256sum, filepath, n[2]))
                            deletecandidates.update(map(lambda x: x[1], res))

                        if bestrepo is None:
                            bestrepo = merges[0][2]
                        if bestrepo in giturltopriority:
                            bestscore = giturltopriority[bestrepo][1]
                        for r in merges:
                            if not r[2] in giturltopriority:
                                continue
                            bestscoreandproject = giturltopriority[r[2]]
                            if bestscoreandproject[0] != project:
                                continue
                            if bestscore is None:
                                bestscore = bestscoreandproject[1]
                                bestrepo = r[2]
                            if bestscoreandproject[1] < bestscore:
                                bestrepo = r[2]
                                bestscore = bestscoreandproject[1]
                        if bestscore is None:
                            continue
                        # filter all the revisions that are not from the best repository
                        filteredres = filter(lambda x: x[2] != bestrepo, merges)
                        filtered2 = filter(lambda x: x[2] in giturltopriority, filteredres)
                        for f2 in filtered2:
                            # revision = f2[1]
                            # url = f2[2]
                            # TODO: fix this, as it is unindexed right now :-/
                            cursor.execute("delete from tlshentries where sha256sum=? and filepath=? and gitrevision=? and giturl=?", (sha256sum, filepath, f2[1], f2[2]))
                        deletecandidates.update(map(lambda x: x[1], filtered2))

            conn.commit()

            # now check if the there is still data left for the revisions.
            # If not, add it to the deleted revisions list.
            for gitrevision in deletecandidates:
                res = cursor.execute("select * from tlshentries where gitrevision=? LIMIT 1",
                                     (gitrevision,)).fetchall()
                if res != []:
                    continue
                res = cursor.execute("select * from emptyrevisions where gitrevision=? LIMIT 1",
                                     (gitrevision,)).fetchall()
                if res != []:
                    continue
                cursor.execute('insert into deletedrevisions (gitrevision, project, giturl) values (?,?,?)',
                               (gitrevision, project, giturl))
                conn.commit()
            cursor.close()
            conn.close()

        # write a copy of seendict and sha256seendict to pickle so they can
        # be reused in subsequent scans
        if restorestate:
            print("Storing cached data for future runs")
            sys.stdout.flush()
            dumpdict = copy.deepcopy(seendict)
            dumpsha256dict = copy.deepcopy(sha256seendict)
            dumppatchiddict = copy.deepcopy(patchiddict)
            statepicklefile = open(statefile, 'wb')
            pickle.dump((giturl, dumpdict, dumpsha256dict, dumppatchiddict), statepicklefile)
            statepicklefile.close()

    # TODO: configure this
    # Vacuum the database. For big databases this can take quite a long time.
    if optimizedb:
        conn = sqlite3.connect(gitdatabase)
        cursor = conn.cursor()

        vacuum = False
        if vacuum:
            cursor.execute('vacuum')
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main(sys.argv)
