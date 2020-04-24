from angr import Project, SimProcedure
from angr import sim_options as so
import libc

##### constraint #####
# 1. have symbol
# 2. have win function [system('/bin/sh')]
# 3. pie disable
# 4. dynamic loading libc

project = Project('../challenges/tcache_dup')
#project.hook_symbol('malloc', libc.fakeMalloc())
#project.hook_symbol('free', libc.fakeFree())

extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
es = project.factory.entry_state(add_options=extras)
print(f'entry_state: {es}')
simgr = project.factory.simulation_manager(es, save_unconstrained=True)

#simgr.run()
def overflow_filter(simgr):
        print(simgr)
        if len(simgr.unconstrained) > 0:
            print("[+] found some unconstrained states, checking exploitability")
            for state in simgr.unconstrained:
                eip = state.regs.pc
                bits = state.arch.bits
                state_copy = state.copy()
                print(f'eip: {eip}')
                print(f'bits: {bits}')
                print(f'state_copy: {state_copy}')

simgr.explore(find=lambda s: b"malloc" in s.posix.dumps(2), step_func=overflow_filter)
s = simgr.found[0]
print(s.posix.dumps(2))