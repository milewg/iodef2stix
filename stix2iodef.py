#!/usr/bin/env python
# -*- coding:utf-8 -*-

from lxml import etree as ET
import sys
import os

if __name__ == '__main__':
    args = sys.argv
    if len(args) != 2:
        print "usage: {0} input.xml".format(args[0])
	sys.exit()

    for file in args[1:1]:
        if not os.path.exists(file):
            print "file {0} not exist.".format(file)
            sys.exit()
    
    tree = ET.parse(args[1])
#    print(ET.tostring(tree, pretty_print=True))
    xslt = ET.parse("./xslfiles/stix2iodef.xsl")
#    print(ET.tostring(xslt, pretty_print=True))
    transform = ET.XSLT(xslt)
    result = transform(tree)
    print(ET.tostring(result, pretty_print=True))

#    print(transform.error_log)
