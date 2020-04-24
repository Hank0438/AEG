from __future__ import print_function
import angr
import claripy
import time
import timeout_decorator
import IPython

from angr import sim_options as so

def checkOverflow(binary_name,inputType="STDIN"):

    class hookFour(angr.SimProcedure):
        IS_FUNCTION = True
        def run(self):
            return 4 # Fair dice roll

    p = angr.Project(binary_name,load_options={"auto_load_libs": False})
    #Hook rands
    p.hook_symbol('rand',hookFour)
    p.hook_symbol('srand',hookFour)




    #Setup state based on input type
    argv = [binary_name]
    if inputType == "STDIN":
        #state = p.factory.full_init_state(args=argv)
        extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
        state = p.factory.entry_state(add_options=extras)
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol('handle_connection')
        #print(f'handle_connection: {handle_connection}')
        state = p.factory.entry_state(addr=handle_connection.rebased_addr)
    else:
        arg = claripy.BVS("arg1", 300 * 8)
        argv.append(arg)
        state = p.factory.full_init_state(args=argv)
        state.globals['arg'] = arg
    state.globals['inputType'] = inputType
    #print(f'state: {state}')





    print("[+] looking for vulnerability")

    def overflow_filter(simgr):
        print(simgr)
        if len(simgr.unconstrained) > 0:
            print("[+] found some unconstrained states, checking exploitability")
            for state in simgr.unconstrained:
                eip = state.regs.pc
                bits = state.arch.bits
                state_copy = state.copy()
                #print(f'eip: {eip}')
                #print(f'bits: {bits}')
                #print(f'state_copy: {state_copy}')

                #Constrain pc to 0x41414141 or 0x41414141414141
                constraints = []
                for i in range(bits // 8):
                    curr_byte = eip.get_byte(i)
                    print(f'curr_byte: {curr_byte}')
                    constraint = claripy.And(curr_byte == 0x41)
                    constraints.append(constraint)

                #Check satisfiability
                if state_copy.se.satisfiable(extra_constraints=constraints):
                    for constraint in constraints:
                        state_copy.add_constraints(constraint)

                    #Check by input
                    if state_copy.globals['inputType'] == "STDIN" or state_copy.globals['inputType'] == "LIBPWNABLE":
                        stdin_str = state_copy.posix.dumps(0)
                        print(f'stdin_str: {stdin_str}')
                        if b'A' in stdin_str:

                            # Constrain EIP to 0x41414141 or 0x4141414141414141
                            constraints = []
                            for i in range(bits // 8):
                                curr_byte = eip.get_byte(i)
                                constraint = claripy.And(curr_byte == 0x41)
                                constraints.append(constraint)

                            #Constrain STDIN to printable if we can
                            if state.se.satisfiable(extra_constraints=constraints):
                                for constraint in constraints:
                                    state.add_constraints(constraint)


                            # #Constrain rest of input to be printable
                            # print(f'state.posix.fd: {state.posix.fd}')
                            # #stdin = state.posix.fd[0]
                            # print(f'state.posix.fd[0]: {state.posix.fd[0]}')
                            # #stdin = state.posix.stdin
                            # constraints = []
                            # #stdin_size = len(stdin.all_bytes())
                            # #stdin_size = 300
                            # #stdin.length = stdin_size
                            # #stdin.seek(0)
                            # #stdin_bytes = stdin.all_bytes()
                            # stdin_bytes = state.posix.stdin.load(0, state.posix.stdin.size)
                            # print(f'state.posix.stdin.size: {state.posix.stdin.size}')
                            # input_data = state.solver.eval(stdin_bytes, cast_to=bytes)
                            # print(f'input_data: {input_data}')
                            # for i in range(state.posix.stdin.size):
                            #     curr_byte = stdin.read_from(1)
                            #     constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                            #     if state.se.satisfiable(extra_constraints=[constraint]):
                            #         constraints.append(constraint)
        
                            # #Constrain STDIN to printable if we can
                            # if state.se.satisfiable(extra_constraints=constraints):
                            #     for constraint in constraints:
                            #         state.add_constraints(constraint)

                            #Get the string coming into STDIN
                            stdin_str = repr(state.posix.dumps(0))
                            print("[+] Vulnerable state found {}".format(stdin_str))
                            state.globals['type'] = "Overflow"
                            state.globals['input'] = stdin_str
                            simgr.stashes['found'].append(state)
                            simgr.stashes['unconstrained'].remove(state)


                    if state_copy.globals['inputType'] == "ARG":
                        arg = state.globals['arg']
                        arg_str = str(state_copy.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01','')
                        if 'A' in arg_str:
                            constraints = []
                            for i in range(bits / 8):
                                curr_byte = eip.get_byte(i)
                                constraint = claripy.And(curr_byte == 0x41)
                                constraints.append(constraint)

                            for i in range(arg.length):
                                curr_byte = arg.read_from(1)
                                constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                                if state.se.satisfiable(extra_constraints=[constraint]):
                                    constraints.append(constraint)
        
                            #Constrain STDIN to printable if we can
                            if state.se.satisfiable(extra_constraints=constraints):
                                for constraint in constraints:
                                    state.add_constraints(constraint)
                            

                            arg_str = repr(str(state.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01',''))
                            print("[+] Vulnerable path found {}".format(arg_str))
                            state.globals['type'] = "Overflow"
                            simgr.stashes['found'].append(path)
                            simgr.stashes['unconstrained'].remove(path)
        return simgr

    run_environ = {}
    run_environ['type'] = None
    end_state = None
    #Lame way to do a timeout
    simgr = p.factory.simulation_manager(state, save_unconstrained=True)
    try:
        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            simgr.explore(find=lambda s: b'type' in s.globals,step_func=overflow_filter)

        
        exploreBinary(simgr)
        if 'found' in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ['type'] = end_state.globals['type']
        
        # run_environ['type'] = "Overflow"
        # stdin_str = b'0000000000000000000000000000000000000000000000000000000000000000\xef\xbe\xad\xde000000000000\x1b\x86\x04\x080000000000000000'
        # end_state = 1

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        print("[~] Keyboard Interrupt")



    stdin_str = end_state.globals['input']
    if (inputType == "STDIN" or inputType == "LIBPWNABLE") and end_state is not None:
        #stdin_str = repr(str(end_state.posix.dumps(0).replace('\x00','').replace('\x01','')))
        run_environ['input'] = stdin_str
        print("[+] Triggerable with STDIN : {}".format(stdin_str))
    elif inputType == "ARG" and end_state is not None:
        #arg_str = repr(str(end_state.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01',''))
        run_environ['input'] = arg_str
        print("[+] Triggerable with arg : {}".format(arg_str))

    return run_environ
