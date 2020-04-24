import angr
import claripy
import IPython
import os, sys
import logging
import cle
from utils import protectionDetector

# find a pointer is free but not null 
'''
eg. 
char *heap_pointer[20];
char *input;
read(0, input, 2);
int idx = 0; //atoi(input); 
heap_pointer[idx] = malloc(0x30);
free(heap_pointer[0])
'''

class HeapConditionTracker(angr.state_plugins.SimStatePlugin):
    def __init__(self, alloc_list=None, malloc_count=0, free_count=0, **kwargs):  # pylint:disable=unused-argument
        super(HeapConditionTracker, self).__init__()
        self.alloc_list = list() if alloc_list is None else list(alloc_list)
        self.malloc_list = list()
        self.free_list = list()
        self.malloc_count = 0
        self.free_count = 0
        self.vuln = {
            'uaf': False,
            'overflow': False,
            'arb_write': False,
            'overlap': False,

        }

    @angr.state_plugins.SimStatePlugin.memo
    def copy(self, _memo):
        return HeapConditionTracker(**self.__dict__)

class MallocInspect(angr.SimProcedure):
    def run(self, size, malloc_addr=None):
        self.call(malloc_addr, (size,), 'check_malloc')

    def check_malloc(self, size, malloc_addr):
        chunk_addr = self.state.regs.rax
        chunk_addr = self.state.solver.eval(chunk_addr)
        malloc_size = self.state.solver.eval(size)

        # update alloc list
        
        self.state.heap_tracker.malloc_list.append({
            'chunk_addr': chunk_addr,
            'size': malloc_size,
            'malloc_addr': malloc_addr,
        })
        self.state.heap_tracker.malloc_count += 1
    
        self.state.heap_tracker.alloc_list.append({
            'chunk_addr': chunk_addr,
            'size': malloc_size,
            'malloc_id': self.state.heap_tracker.malloc_count,
            'free_id': None,
        })
    
        print(f"malloc({malloc_size}): {self.state.heap_tracker.malloc_count}, chunk_addr: {hex(chunk_addr)}")
        print("state.heap_tracker.alloc_list: ", self.state.heap_tracker.alloc_list)


class FreeInspect(angr.SimProcedure):
    def run(self, ptr, free_addr=None):
        self.call(free_addr, (ptr,), 'check_free')
        
            

    def check_free(self, ptr, free_addr):
        free_chunk_addr = self.state.solver.eval(ptr)

        
        self.state.heap_tracker.free_list.append({
            'chunk_addr': free_chunk_addr,
            'free_addr': free_addr,
        })
        self.state.heap_tracker.free_count += 1
        
        
        
        ### [TODO] hash table to speed up 
        for chunk_idx in range(len(self.state.heap_tracker.alloc_list)):
            if (self.state.heap_tracker.alloc_list[chunk_idx]['chunk_addr'] == free_chunk_addr):
                if (self.state.heap_tracker.alloc_list[chunk_idx]['free_id'] == None):
                    self.state.heap_tracker.alloc_list[chunk_idx]['free_id'] = self.state.heap_tracker.free_count
                else:
                    print('UAF in free()!!!')
                    print("it is Double Free!!!")
                    self.state.heap_tracker.alloc_list[chunk_idx]['free_id'] = -1
                    self.state.heap_tracker.vuln['uaf'] = True
                    IPython.embed()
                break


            if (chunk_idx == len(self.state.heap_tracker.alloc_list)-1):
                print("it is Fake Free in non-heap!!!")
                IPython.embed()
        


        print(f"free({hex(free_chunk_addr)}): {self.state.heap_tracker.free_count}")
        print("state.heap_tracker.free_list: ", self.state.heap_tracker.free_list)
        print("state.heap_tracker.alloc_list: ", self.state.heap_tracker.alloc_list)

    

class ReadInspect(angr.SimProcedure):
    def run(self, fd, read_addr, size):
        read_addr = self.state.solver.eval(read_addr)
        print('read_addr: ', hex(read_addr))
        for chunk in self.state.heap_tracker.alloc_list:
            if (chunk['chunk_addr'] <= read_addr) and ((chunk['chunk_addr']+chunk['size']) > read_addr) and (chunk['free_id'] is not None) and (self.state.heap_tracker.vuln['uaf'] is False):
                print('UAF in read()!!!')
                self.state.heap_tracker.vuln['uaf'] = True
                IPython.embed()


def check_mem_write(state):
    global is_UAF
    # print('Write ', state.inspect.mem_write_expr, 'to ', state.inspect.mem_write_address, ",length: ",state.inspect.mem_write_length)
    # print("condition: ", state.inspect.mem_write_condition)
    # if (state.solver.eval(state.inspect.mem_write_address) == 0xc0000f20):
    #     print("mem_write_expr: ", state.inspect.mem_write_expr)
    #     print("mem_write_length: ", state.inspect.mem_write_length) 
    write_mem_addr = state.solver.eval(state.inspect.mem_write_address)
    for chunk in state.heap_tracker.alloc_list:
        if (chunk['chunk_addr'] <= write_mem_addr) and ((chunk['chunk_addr']+chunk['size']) > write_mem_addr) and (chunk['free_id'] is not None) and (state.heap_tracker.vuln['uaf'] is False):
            print('UAF in mem_write!!!')
            state.heap_tracker.vuln['uaf'] = True
            IPython.embed()

    ### if mem_write chunk header == heap overflow (off one by null)
    ### if mem_write more than chunk size == heap overflow 

def check_mem_read(state):
    global is_UAF
    print("mem_read_address: ", state.inspect.mem_read_address)
    read_mem_addr = state.solver.eval(state.inspect.mem_read_address)
    for chunk in state.heap_tracker.alloc_list:
        if (chunk['chunk_addr'] <= read_mem_addr) and ((chunk['chunk_addr']+chunk['size']) > read_mem_addr) and (chunk['free_id'] is not None) and (state.heap_tracker.vuln['uaf'] is False):
            print('UAF in mem_read!!!')
            state.heap_tracker.vuln['uaf'] = True
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

def use_sim_procedure(name):
    print("name: ", name)
    if name in ['puts', 'printf', '__libc_start_main']:
        return False
    else:
        return True

class UseAfterFree(angr.Analysis):
    def __init__(self):
        self.libc = self.project.loader.shared_objects["libc.so.6"]
        self.allocator = self.project.loader.shared_objects["libc.so.6"]
        self.malloc_addr = self.allocator.get_symbol('malloc').rebased_addr
        self.malloc_plt = self.project.loader.main_object.plt.get('malloc')
        self.free_addr = self.allocator.get_symbol('free').rebased_addr
        self.free_plt = self.project.loader.main_object.plt.get('free')
        self.read_addr = self.allocator.get_symbol('read').rebased_addr
        self.read_plt = self.project.loader.main_object.plt.get('read')
        

        added_options = set()
        # added_options.add(angr.options.REVERSE_MEMORY_NAME_MAP)             # I don't know wtf
        # # added_options.add(angr.options.STRICT_PAGE_ACCESS)                  # I don't know wtf
        # added_options.add(angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES) # I don't know wtf
        added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)      # make unknown regions hold null
        added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)   # make unknown regions hold null
        self.state = self.project.factory.entry_state(add_options=added_options)
        # self.state = self.project.factory.entry_state()


        # set heap location right after bss
        ### just to know the malloc addr should inside the heap
        ### nothing about heap content
        bss = self.project.loader.main_object.sections_map['.bss']
        heap_base = ((bss.vaddr + bss.memsize) & ~0xfff) + 0x1000
        heap_size = 64 * 4096
        new_brk = claripy.BVV(heap_base + heap_size, self.project.arch.bits)
        print(bss)
        print(hex(heap_base))
        print(new_brk)
        
        heap = angr.SimHeapBrk(heap_base=heap_base, heap_size=heap_size)
        self.state.register_plugin('heap', heap)
        self.state.register_plugin('heap_tracker', HeapConditionTracker())


    def uaf_analysis(self):
        if (self.malloc_plt):
            self.project.hook(addr=self.malloc_plt, hook=MallocInspect(malloc_addr=self.malloc_addr))
        if (self.free_plt):
            self.project.hook(addr=self.free_plt, hook=FreeInspect(free_addr=self.free_addr))
        if (self.read_plt):
            self.project.hook(addr=self.read_plt, hook=ReadInspect())

        simgr = self.project.factory.simulation_manager(self.state)
        while len(simgr.active) > 0:
            succ = simgr.step()
            print("succ.successors: ", succ.successors)
            # print("simgr.active: ", simgr.active)
            if self.state.heap_tracker.malloc_count == 1:
                chunk_addr = self.state.heap_tracker.malloc_list[self.state.heap_tracker.malloc_count-1]['chunk_addr']
                print("memory.load: ", self.state.memory.load(chunk_addr, 0x20, endness='Iend_LE') )
            if (len(simgr.active) > 0):
                simgr.active[0].inspect.b('mem_write', when=angr.BP_AFTER, action=check_mem_write)
                simgr.active[0].inspect.b('mem_read', when=angr.BP_AFTER, action=check_mem_read)
                print(simgr.active[0].posix.dumps(1))

            if (len(simgr.active) > 1):
                input_0 = simgr.active[0].posix.dumps(0)
                input_1 = simgr.active[1].posix.dumps(0)
                print(input_0)
                print(input_1)



        # simgr.explore(find=0x40092c)
        # if simgr.found:
        #     s = simgr.found[0]
        #     solution = s.solver.eval(secret)
        #     print(hex(solution))
        #     print(s.posix.dumps(1))

        #     flag = s.posix.dumps(0)
        #     print(flag)

def main():
    angr.register_analysis(UseAfterFree, 'UseAfterFree')

    binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/menu_uaf"
    # binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/uaf"
    # binary_name = "/media/sf_Documents/AEG/Zeratool/challenges/uaf/simple_uaf"
    #binary_name = "/media/sf_Documents/AEG/heaphopper/tests/how2heap_fastbin_dup/fastbin_dup.bin"
    allocator_path = "/media/sf_Documents/AEG/heaphopper/tests/libc-2.23/libc.so.6"
    libc_path = "/media/sf_Documents/AEG/heaphopper/tests/libc-2.23/libc.so.6"
    proj = angr.Project(binary_name,
                    exclude_sim_procedures_func=use_sim_procedure, 
                    load_options={'ld_path':[os.path.dirname(allocator_path), os.path.dirname(libc_path)],
                                    'auto_load_libs':True})

    

    protectionDetector.getProperties(binary_name)
    detect = proj.analyses.UseAfterFree()
    detect.uaf_analysis()












# find a function allow to use the free pointer
'''
eg. did not check the pointer is free or not

heap_pointer[0] = malloc(0x30); //uaf
'''