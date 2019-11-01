#!/usr/bin/env python3

import sys
import os, os.path
import yaml

import msc_pyparser
from msc_pyparser import MSCUtils as u

if len(sys.argv) < 2:
    print("Argument missing!")
    print("Use: %s /path/to/crs/confdir" % (sys.argv[0]))
    sys.exit(-1)


class Beautifier(object):
    def __init__(self, data):
        self.data = data
        self.offset = 0
 
    def beautify(self):
        writed_trans = 0
        for d in self.data:
            if d['type'] in ["SecRule", "SecAction"]:
                # save the original lineno, check later the action's lineno
                # if they are equals, it means that rule is in one line
                lineno = d['lineno']
                d['oplineno'] += self.offset
                d['lineno'] += self.offset
                if "actions" in d:
                    aidx = 0
                    last_trans = ""
                    while aidx < len(d["actions"]):
                        # if action is 't':
                        if d['actions'][aidx]['act_name'] == "t":
                            # writed_trans could be used to limit the number of actions
                            # to place in one line
                            writed_trans += 1

                            # the tirst 't' will placed the original line
                            # the next ones will placed the same line
                            if last_trans == "t":
                                # check wheter the new 't' is in same line
                                # like the previous
                                if d['actions'][aidx]['lineno'] == last_lineno:
                                    pass
                                else:
                                    # decrement the offset, because the next 't'
                                    # actions will placed to the same line like
                                    # the first
                                    self.offset -= (d['actions'][aidx]['lineno'] - last_lineno)
                                # finally, set the new 't' line number to the
                                # first 't'
                                d['actions'][aidx]['lineno'] = last_lineno
                            else:
                                # compare again the action lineno with the
                                # SecRule lineno (inline rule)
                                #
                                # if it's > then SecRule lineno
                                if d['actions'][aidx]['lineno'] > lineno:
                                    # first check wheter the current line
                                    # is next one
                                    if (d['actions'][aidx]['lineno'] - last_lineno) == 1:
                                        pass
                                    else:
                                        # push the next action to the next line
                                        self.offset += (d['actions'][aidx]['lineno'] - last_lineno) + 1
                        # action is not 't'
                        else:
                            # check wheter action is in same line like
                            # rule other parts
                            if d['actions'][aidx]['lineno'] > lineno:
                                # first check wheter the current line
                                # is next one
                                if (d['actions'][aidx]['lineno'] - last_lineno) == 1:
                                    pass
                                else:
                                    # push the next action to the next line
                                    self.offset += (d['actions'][aidx]['lineno'] - last_lineno) + 1
                            writed_trans = 0
                        last_lineno = d['actions'][aidx]['lineno']
                        d['actions'][aidx]['lineno'] += self.offset
                        last_trans = d['actions'][aidx]['act_name']
                        aidx += 1
            else:
                d['lineno'] += self.offset

srcobj = sys.argv[1]
dstobj = os.path.join(os.path.dirname(os.path.realpath(__file__)), "export")

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
        if os.path.isfile(fp) and os.path.basename(fp)[-5:] == ".conf":
            configs.append(fp)
if st == u.IS_FILE:
    configs.append(srcobj)

configs.sort()

for c in configs:
    print("Parsing CRS config: %s" % c)
    cname = os.path.basename(c)
    dname = cname.replace(".conf", ".yaml")

    try:
        with open(c) as file:
            data = file.read()
    except:
        print("Exception catched - ", sys.exc_info())
        sys.exit(-1)

    try:
        mparser = msc_pyparser.MSCParser()
        mparser.parser.parse(data)
    except:
        print(sys.exc_info()[1])
        sys.exit(-1)

    o = os.path.join(dstobj, dname)
    try:
        with open(o, "w") as file:
            t = Beautifier(mparser.configlines)
            t.beautify()
            yaml.dump(t.data, file, default_flow_style=False)
            # to ignore the beautidier, use the parsed structure:
            #yaml.dump(mparser.configlines, file, default_flow_style=False)
    except:
        print("Exception catched - ", sys.exc_info())
        sys.exit(-1)
