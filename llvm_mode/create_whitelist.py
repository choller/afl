#!/usr/bin/env python

import sys
import os

target_dirs = sys.argv[1:]
whitelist = []

def is_source_file(filename):
  source_exts = ['.cpp', '.cc', '.cxx', '.c', '.h', '.hxx']
  for source_ext in source_exts:
    if filename.endswith(source_ext):
      return True
  return False

for target_dir in target_dirs:
  for current_dir, sub_dirs, files in os.walk(target_dir):
    whitelist.extend([os.path.join(current_dir, x) for x in files if is_source_file(x)])

for entry in whitelist:
  print(entry)
