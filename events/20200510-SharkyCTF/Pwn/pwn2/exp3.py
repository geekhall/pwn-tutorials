#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

def local(argv=[], *a, **kw):
    print 'run at local'
    if args.GDB:
        print "GDB..."
        return "gdb"
    else :
        print "PROCESS..."
        return "process"


def remote(argv=[], *a, **kw):
    print 'run at remote'


def start(argv=[], *a, **kw):
    print 'start function'
    if args.LOCAL:
        print 'start LOCAL function'
        return local(argv, *a, **kw)
    else:
        print 'start REMOTE function'
        return remote(argv, *a, **kw)


start()
                
