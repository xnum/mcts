#!/usr/bin/python

import sys
import angr
import simuvex
import logging

logging.getLogger("angr.path_group").setLevel("DEBUG")
logging.getLogger("angr.DFS").setLevel("DEBUG")

# cp -r a b

def main(name, method, limit):
    proj = angr.Project(name, load_options={"auto_load_libs": False})
    initial_state = proj.factory.entry_state(args=[name]
            ,remove_options={simuvex.s_options.LAZY_SOLVES}) 

    path_group = proj.factory.path_group(initial_state, method=method, limit=limit)
    path_group.run()

if __name__ == '__main__':
    main('/usr/local/bin/cpp-markdown', sys.argv[1], int(sys.argv[2]))
