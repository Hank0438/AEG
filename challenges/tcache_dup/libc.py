from angr import SimProcedure

class fakeMalloc(SimProcedure):
    def run(self, argc, argv):
        #print('Program running with argc=%s and argv=%s' % (argc, argv))
        print("[+] Call malloc()")
        return 0

class fakeCalloc(SimProcedure):
    def run(self, argc, argv):
        #print('Program running with argc=%s and argv=%s' % (argc, argv))
        print("[+] Call calloc()")
        return 0

class fakeRealloc(SimProcedure):
    def run(self, argc, argv):
        #print('Program running with argc=%s and argv=%s' % (argc, argv))
        print("[+] Call realloc()")
        return 0

class fakeFree(SimProcedure):
    def run(self, argc, argv):
        #print('Program running with argc=%s and argv=%s' % (argc, argv))
        print("[+] Call free()")
        return 0