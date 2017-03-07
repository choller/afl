#!/usr/bin/env python
# encoding: utf-8
'''
Stats module for AFL fuzzing modules

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

from __future__ import print_function
import random

from xml.etree import ElementTree

total_iterations = 0
exceptions = {}

def record_exc(e):
    if not repr(e) in exceptions:
        exceptions[repr(e)] = 0
    exceptions[repr(e)] += 1
    
def record_iter():
    global total_iterations
    total_iterations += 1
    return total_iterations
    
def format_stats():
    global exceptions
    ret = "Total Iterations: %s\nExceptions:\n" % total_iterations
    
    for e in exceptions:
        ret += "    %s: %s\n" % (e,exceptions[e])
    
    return ret