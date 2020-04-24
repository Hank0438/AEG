import angr
import claripy
import IPython
import os, sys
import logging, coloredlogs
import cle

'''
create logger
'''
coloredlogs.install()
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


# binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/menu_uaf"
# binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/uaf"
binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/simple_uaf"
#binary_name = "/media/sf_Documents/AEG/heaphopper/tests/how2heap_fastbin_dup/fastbin_dup.bin"
allocator_path = "/media/sf_Documents/AEG/heaphopper/tests/libc-2.23/libc.so.6"
libc_path = "/media/sf_Documents/AEG/heaphopper/tests/libc-2.23/libc.so.6"
proj = angr.Project(binary_name, 
                        load_options={'ld_path':[os.path.dirname(allocator_path), os.path.dirname(libc_path)],
                                              'auto_load_libs':True})
libc = proj.loader.shared_objects["libc.so.6"]
allocator = proj.loader.shared_objects["libc.so.6"]
malloc_addr = allocator.get_symbol('malloc').rebased_addr
malloc_plt = proj.loader.main_object.plt.get('malloc')
free_addr = allocator.get_symbol('free').rebased_addr
free_plt = proj.loader.main_object.plt.get('free')
read_addr = allocator.get_symbol('read').rebased_addr
read_plt = proj.loader.main_object.plt.get('read')
# print("malloc_addr: ", hex(malloc_addr))
# print("free_addr: ", hex(free_addr))
#bye_func = proj.loader.main_object.get_symbol('bye_func').rebased_addr
# print("bye_func: ", bye_func)

'''
Follow HeapHopper Setting
'''

added_options = set()
added_options.add(angr.options.REVERSE_MEMORY_NAME_MAP)             # I don't know wtf
# added_options.add(angr.options.STRICT_PAGE_ACCESS)                  # I don't know wtf
added_options.add(angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES) # I don't know wtf
added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)      # make unknown regions hold null
added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)   # make unknown regions hold null
state = proj.factory.entry_state(add_options=added_options)


bss = proj.loader.main_object.sections_map['.bss']
heap_base = ((bss.vaddr + bss.memsize) & ~0xfff) + 0x1000
heap_size = 64 * 4096
new_brk = claripy.BVV(heap_base + heap_size, proj.arch.bits)
print(bss)
print(hex(heap_base))
print(new_brk)
heap = angr.SimHeapBrk(heap_base=heap_base, heap_size=heap_size)
set_brk_ret = state.posix.set_brk(new_brk)

state.register_plugin('heap', heap)



is_UAF = False
state.globals['alloc_list'] = []
'''
alloc_status['addr'] = 0xdeadbeef
alloc_status['free'] = False  ### double-free means when this is true, and still free this
'''

secret = claripy.BVS("secret", 6*8)

state.globals['malloc_count'] = 0
class MallocInspect(angr.SimProcedure):
    def run(self, size, malloc_addr=None):
        state.globals['malloc_count'] += 1
        print(f"malloc: {state.globals['malloc_count']}, size: {size}")
        self.call(malloc_addr, (size,), 'check_malloc')

    def check_malloc(self, size, malloc_addr):
        chunk_addr = self.state.regs.rax
        chunk_addr = self.state.solver.eval(chunk_addr)
        print("chunk_addr: ", hex(chunk_addr))

        # update alloc list
        malloc_status = {}
        malloc_status['addr'] = chunk_addr
        malloc_status['free'] = False
        malloc_status['size'] = self.state.solver.eval(size)
        state.globals['alloc_list'].append(malloc_status)

        print("state.globals['alloc_list']: ", state.globals['alloc_list'])

        self.state.memory.store(chunk_addr, secret)


state.globals['free_count'] = 0
class FreeInspect(angr.SimProcedure):
    def run(self, ptr, free_addr=None):
        state.globals['free_count'] += 1
        print(f"free: {state.globals['free_count']}, free_addr: {hex(free_addr)}")
        self.call(free_addr, (ptr,), 'check_free')
            

    def check_free(self, ptr, free_addr):
        free_chunk_addr = self.state.solver.eval(ptr)
        print("free_chunk_addr: ", hex(free_chunk_addr))

        for chunk_idx in range(len(self.state.globals['alloc_list'])):
            if (state.globals['alloc_list'][chunk_idx]['addr'] == free_chunk_addr):
                state.globals['alloc_list'][chunk_idx]['free'] = True

        for chunk in self.state.globals['alloc_list']:
            print(state.memory.load(chunk['addr'], 8, endness=proj.arch.memory_endness))

        print("state.globals['alloc_list']: ", state.globals['alloc_list'])
        input("@")

class ReadInspect(angr.SimProcedure):
    def run(self, fd, read_addr, size):
        global is_UAF
        read_addr = self.state.solver.eval(read_addr)
        print('read_addr: ', read_addr)
        for chunk in state.globals['alloc_list']:
            if (chunk['addr'] <= read_addr) and ((chunk['addr']+chunk['size']) > read_addr) and (chunk['free'] is True) and (is_UAF is False):
                print('UAF in read!!!')
                is_UAF = True
                IPython.embed()


proj.hook(addr=malloc_plt, hook=MallocInspect(malloc_addr=malloc_addr))
proj.hook(addr=free_plt, hook=FreeInspect(free_addr=free_addr))
proj.hook(addr=read_plt, hook=ReadInspect())


# class ProjectSummary(angr.Analysis):
#     def __init__(self):
#         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

# angr.register_analysis(ProjectSummary, 'ProjectSummary')
# summary = proj.analyses.ProjectSummary()
# print(summary.result)




def check_mem_write(state):
    global is_UAF
    print('Write ', state.inspect.mem_write_expr, 'to ', state.inspect.mem_write_address, ",length: ",state.inspect.mem_write_length)
    print("condition: ", state.inspect.mem_write_condition)
    # if (state.solver.eval(state.inspect.mem_write_address) == 0xc0000f20):
    #     print("mem_write_expr: ", state.inspect.mem_write_expr)
    #     print("mem_write_length: ", state.inspect.mem_write_length) 
    write_mem_addr = state.solver.eval(state.inspect.mem_write_address)
    for chunk in state.globals['alloc_list']:
        if (chunk['addr'] <= write_mem_addr) and ((chunk['addr']+chunk['size']) > write_mem_addr) and (chunk['free'] is True) and (is_UAF is False):
            print('UAF in mem_write!!!')
            is_UAF = True
            IPython.embed()

def check_mem_read(state):
    global is_UAF
    #print("mem_read_address: ", state.inspect.mem_read_address)
    read_mem_addr = state.solver.eval(state.inspect.mem_read_address)
    for chunk in state.globals['alloc_list']:
        if (chunk['addr'] <= read_mem_addr) and ((chunk['addr']+chunk['size']) > read_mem_addr) and (chunk['free'] is True) and (is_UAF is False):
            print('UAF in mem_read!!!')
            is_UAF = True
            IPython.embed()

### For Debugging ###
def check_instruction(state):
    global is_UAF, bye_func
    instruction_addr = state.inspect.instruction
    if bye_func == instruction_addr:
        print("instruction: ", hex(state.inspect.instruction))

### For Debugging ###
def check_call(state):
    print("function_address: ", state.inspect.function_address)

simgr = proj.factory.simulation_manager(state)
while len(simgr.active) > 0:
    succ = simgr.step()
    print("succ.successors: ", succ.successors)
    # print("simgr.active: ", simgr.active)
    # print("simgr.unconstrained: ", simgr.unconstrained)
    # IPython.embed()
    # if len(succ.successors) >= 2:
    #     for successor in succ.successors:
    #         input_data = successor.posix.stdin.load(0, state.posix.stdin.size)
    #         print("successor: ", successor.solver.eval(input_data, cast_to=bytes))
    if (len(simgr.active) > 0): # & (is_UAF is False):
        # print("simgr.active[0].globals: ", simgr.active[0].globals)
        simgr.active[0].inspect.b('mem_write', when=angr.BP_AFTER, action=check_mem_write)
        simgr.active[0].inspect.b('mem_read', when=angr.BP_AFTER, action=check_mem_read)
        
        ### For Debugging ###
        #simgr.active[0].inspect.b('instruction', when=angr.BP_AFTER, action=check_instruction)
        #simgr.active[0].inspect.b('call', when=angr.BP_AFTER, action=check_call)
        
        #stdout_data = simgr.active[0].posix.stdout.load(0, simgr.active[0].posix.stdout.size)
        #print(stdout_data)
        print(simgr.active[0].posix.dumps(1))


# simgr.explore(find=lambda s: b"good job!" in s.posix.dumps(1))

# # simgr.explore(find=0x4006c6)

# if simgr.found:
#     s = simgr.found[0]
#     solution = s.solver.eval(secret)
#     print(hex(solution))
#     print(s.posix.dumps(1))

#     flag = s.posix.dumps(0)
#     print(flag)




# for chunk in state.globals['alloc_list']:
#     # Set memory concretization strategies
#     state.memory.read_strategies = [
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(16),
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(4096,
#                                                                                                                 chunk['addr']),
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(4096)]
#     state.memory.write_strategies = [
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(16),
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(4096,
#                                                                                                                 chunk['addr']),
#         angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(4096)]

#     print(state.memory.load(chunk['addr'], 8, endness='Iend_LE'))