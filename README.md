owasp-crs-check
===============

Welcome to the `owasp-crs-check` documentation.

Prerequisites
=============

To run the tool, you need:

+ a **Python 3** interpreter
+ **YAML** and for **Python 3**
+ **msc_pyparser** - a SecRule parser

`msc_pyparser` was written in Python 3 and has not been tested with Python 2, therefore you have to use Python 3.

The best way to install the required packages just run

```
pip3 install -r requirements.txt
```

Check rules
===========

The checking method divided to three parts:

* generate structures
  * re-formatting rules (beautifier)
* run checks
  * check the case sensitive format of operators, actions, transformations and ctl methods
  * check the order of actions - [see the wiki](https://github.com/SpiderLabs/owasp-modsecurity-crs/wiki/Order-of-ModSecurity-Actions-in-CRS-rules)
* write the parsed structure
  * make a diff with the original rules

Run these steps:

```
./rules-read.py /path/to/rules
./rules-check.py
./rules-write.py /path/to/rules
```

Generate structures
===================

For a correct work it's necessary that the rule sets must be syntactically (and of course lexically) correct. This step does a syntax check, and build a structure (in YAML format), which will be used in the next step. You have to pass an argument with the path of the rules. The exported structure will be stored in export/ directory. The reader method passes the parsed structure through a beautifier. This method modifies the structure following this rules:
* formats only the `SecRule` and `SecAction` lines/blocks
* if a `SecRule` is an inline rule (see the PL setting rules), it stays as is
* if there are more that one `t` (transform) actions, then it will be placed on one line
* all other actions will be placed id the next line

See some examples.

This stays the way it was:
```
SecRule ARGS "@rx .*" "id:1,phase:1,pass,nolog"
```

This will be modified:
```
SecRule ARGS "@rx .*" \
  "id:1\,
  \
  phase:1,\
  t:none,\
  t:urlDecodeUni,\
  pass,nolog"
```
```
SecRule ARGS "@rx .*" \
    "id:1\,
    phase:1,\
    t:none,t:urlDecodeUni,\
    pass,\
    nolog"
```
Please note the differences:
* the identations are four spaces
* the empty line missing
* the transformations are in same line
* the other actions are in different lines

Run checks
==========

Actually in this step, the tool will run these methods:

* case-sensitive check for configuration directives, variables, operators, and actions
* order check for actions - see the related wiki and doc

This script will search the YAML files under export/ directory.


Write the parsed structure
==========================

The writer of parser class is very strict. I mean it uses predefined (hard-coded) indentations, leading and trailing spaces (eg. before the trailing \ at the end of lines, and so on...), so with help of the re-generated rule set, we can use a simple `diff` to detect the hidden (or missing) spaces, tabs and other annoying characters. Note, that the tool uses Python's `difflib` (standard) library. You have to pass an argument with the path of the rules. The reverse exported structure will be stored in re-export/ directory. Then the script will compare the re-exported config files with the original rules.

Testing the tool
================

To run a complete test, see the attached RULE1.conf file. That contains a comment, an inline rule and a wrong formatted rule. Run the steps:
```
$ ./rules-read.py . 
Parsing CRS config: RULE1.conf
$ ./rules-check.py 
Checking config: /path/to/secrules_check/export/RULE1.yaml
Transform case mismatch in rule id 2: 'None'
Transform case mismatch in rule id 2: 'UrlDecodeUni'
Operator case mismatch in rule id 2: '@Rx'
Rule ID: 2, action 't' at pos 3 is wrong place against 'pass' at pos 4
$ ./rules-write.py .
Writing CRS config: /path/to/secrules_check/export/RULE1.yaml
---
+++
@@ -3,8 +3,10 @@
SecRule ARGS "@rx .*" "id:1,phase:1,pass,nolog"

SecRule ARGS "@rx .*" \
-    "id:1,\
-    phase:1,\
-    t:none,t:urlDecodeUni,\
-    pass,\
-    nolog"
+  "id:1,\
+  \
+  phase:1,\
+  t:none,\
+  t:urlDecodeUni,\
+  pass,nolog"
+
```