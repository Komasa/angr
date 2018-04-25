#!/usr/bin/env python
import claripy
import angr
import logging 
from angr.state_plugins.context_view import ContextView as cv

logging.getLogger('angr.manager').setLevel('DEBUG')
logging.getLogger('angr.state_plugins.context_view').setLevel('DEBUG')


project = angr.Project("/vagrant/m0rph/morph", 
#support_selfmodifying_code=True, 
load_options={'auto_load_libs':False})

memset = angr.SIM_PROCEDURES['libc']['memset']
memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
strlen = angr.SIM_PROCEDURES['libc']['strlen']
srand = angr.SIM_PROCEDURES['libc']['srand']
rand = angr.SIM_PROCEDURES['libc']['rand']
time = angr.SIM_PROCEDURES['linux_kernel']['time']

class null(angr.SimProcedure):
    def run(self):
        return 0

project.hook_symbol('memset', memset())
project.hook_symbol('memcpy', memcpy())
project.hook_symbol('strlen', strlen())
project.hook_symbol('srand', null())
project.hook_symbol('rand', null())
project.hook_symbol('time', null())

argv1 = claripy.BVS("input", 8*23)
state = project.factory.entry_state(args=["/vagrant/m0rph/morph", argv1])

simgr = project.factory.simgr(state)
stdout = "What are you waiting for, go submit that flag!"

state.register_plugin("context_view", cv())

print "Running explore"
simgr.explore(find=lambda s: stdout in s.posix.dumps(1))
print "Explore done"
simgr.found[0].context_view.pprint()
simgr.deadended[0].context_view.pprint()
import IPython; IPython.embed()


