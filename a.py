#!/usr/bin/python

import os, sys
if __name__ == "__main__":
    print("Try commands below")
    print("$ echo 'foobar' > /proc/{0}/fd/0".format(os.getpid()))
    while True:
        print("read :: [" + sys.stdin.readline() + "]")
        pass
