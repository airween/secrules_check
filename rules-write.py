#!/usr/bin/env python3

import sys
import os, os.path
import yaml
import difflib

import msc_pyparser
from msc_pyparser import MSCUtils as u

if len(sys.argv) < 2:
    print("Argument missing!")
    print("Use: %s /path/to/exported/rules" % (sys.argv[0]))
    sys.exit(-1)

srcobj = os.path.join(os.path.dirname(os.path.realpath(__file__)), "export")
dstobj = os.path.join(os.path.dirname(os.path.realpath(__file__)), "re-export")
rules = sys.argv[1]

dt = u.getpathtype(dstobj)
if dt == u.UNKNOWN:
    os.mkdir(dstobj)
if dt == u.IS_FILE:
    print("Dest path is file!")
    sys.exit(-1)

st = u.getpathtype(srcobj)
if st == u.UNKNOWN:
    print("Unknown source path!")
    sys.exit()

configs = []
if st == u.IS_DIR:
    for f in os.listdir(srcobj):
        fp = os.path.join(srcobj, f)
        if os.path.isfile(fp) and os.path.basename(fp)[-5:] == ".yaml":
            configs.append(fp)
if st == u.IS_FILE:
    configs.append(srcobj)

configs.sort()

for c in configs:
    print("Writing CRS config: %s" % c)
    cname = os.path.basename(c)
    dname = cname.replace(".yaml", ".conf")

    try:
        with open(c) as file:
            if yaml.__version__ >= "5.1":
                data = yaml.load(file, Loader=yaml.FullLoader)
            else:
                data = yaml.load(file)
    except:
        print("Exception catched - ", sys.exc_info())
        sys.exit(-1)

    try:
        mwriter = msc_pyparser.MSCWriter(data)
    except:
        print(sys.exc_info()[1])
        sys.exit(-1)

    o = os.path.join(dstobj, dname)
    try:
        with open(o, "w") as file:
            mwriter.generate()
            # add extra new line at the end of file
            mwriter.output.append("")
            file.write("\n".join(mwriter.output))
    except:
        print("Exception catched - ", sys.exc_info())
        sys.exit(-1)

for c in configs:
    differrcnt = 0
    cname = os.path.basename(c)
    dname = cname.replace(".yaml", ".conf")
    o = os.path.join(dstobj, dname)
    with open(o, 'r') as f:
        fromlines = f.readlines()
    with open(os.path.join(rules, dname), 'r') as f:
        tolines = f.readlines()
    diff = difflib.unified_diff(fromlines, tolines)
    for d in diff:
        print(d.strip())
        differrcnt += 1

sys.exit(differrcnt)
