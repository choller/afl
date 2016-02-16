#!/usr/bin/env python
# encoding: utf-8
'''
Example Python Module for AFLFuzz

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

import random

def init(seed):
    '''
    Called once when AFLFuzz starts up. Used to seed our RNG.
    
    @type seed: int
    @param seed: A 32-bit random value
    '''
    random.seed(seed)
    return 0

def fuzz(buf, add_buf):
    '''
    Called per fuzzing iteration.
    
    @type buf: bytearray
    @param buf: The buffer that should be mutated.
    
    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.
    
    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    '''
    ret = bytearray(buf)
    # Do something interesting with ret

    return ret
