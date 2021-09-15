import subprocess
import fcntl
import os, time

linux_server = None

# ida_linux_dbg_server/linux_server64 -i192.168.0.104 < p1 |xxd
try:
    os.mkfifo('p1')
except Exception:
    pass
finally:
    w_pipe = os.open('p1', os.O_SYNC | os.O_CREAT | os.O_RDWR)

def init_linux_server(path, params):
    global linux_server
    try:
        stop_linux_server()
    except Exception:
        pass
    finally:
        linux_server = subprocess.Popen(
            [path, *params],  
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE,
            shell=True,
        )#
        fcntl.fcntl(linux_server.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

def stop_linux_server():
    linux_server.terminate()

def get_linux_server():
    return linux_server

def has_inited(func):
    def new_func(*args, **kargs):
        if linux_server is None:
            raise Exception('尚未初始化linux_server')
        # print(args, kargs)
        func(*args, **kargs)
    return new_func

@has_inited
def stdin_write(*strings, waittime=0.3):
#     print(strings)
    for s in strings:
        if type(s) is not bytes:
            s = bytes(str(s), 'utf-8')
        linux_server.stdin.write(s)
        linux_server.stdin.flush()
        time.sleep(waittime)

@has_inited        
def print_stdout(p=True):
    lines = linux_server.stdout.readlines()
    if not p: return
    for l in lines:
        try:
            print(l.decode('utf-8'), end="")
        except Exception:
            print(l)
    print("")

def write_pipe(*strings, waittime=0, end=''):
    for s in strings:
        if type(s) is not bytes:
            s = bytes(str(s) + end, 'utf-8')
        else:
            s += bytes(end, 'utf-8')
        os.write(w_pipe, s)
        time.sleep(waittime)

class FuncNoBrac():
    def __init__(self, func):
        self.func = func

    def __call__(self):
        self.func()

    def __repr__(self):
        s = self.func()
        return str(s)
        
@has_inited
def _flush():
    linux_server.stdin.flush()
    return linux_server.stdout.readlines()

flush = FuncNoBrac(_flush)

def send_line(s):
    stdin_write(s + '\n')
    print_stdout()

def send_line2(s):
    write_pipe(s + '\n')

def print_hex(data, per_cnt=0x10, start_offset=0x0, format="hex"):
    one_line = ""
    j = 0
    for i, b in enumerate(data):
        if i % per_cnt == 0:
            print(one_line)
            if i <= len(data) - 1:
                print('%x: ' % (start_offset + j), end="")
            one_line = ""
            j = i
        if format == 'hex':
            one_line += (bytes([b]).hex() + ' ')
        elif format == 'char':
            one_line += (chr(b) + ' ')
            
    print(one_line)

def reverse_str(s, per=2):
    s = s.replace(' ', '')
    i = 0
    s1 = []
    for i, _ in enumerate(s):
        if i % 2 == 1:
            s1.insert(0, s[i-1 : i+1])
    s1 = ''.join(s1)
    return s1