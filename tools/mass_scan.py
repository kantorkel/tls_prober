#!/usr/bin/python

import sys
import os

cmd = '../prober.py -l -p %s %s > results/%s-%s.fp'

if __name__ == '__main__':
    f = open(sys.argv[1])
    for line in f:
        line = line[:-1]
        port,ip = line.split(',')
        print ip, port

        os.system(cmd % (port, ip, ip, port))


