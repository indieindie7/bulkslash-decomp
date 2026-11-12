# ptr.py <prog> <base hex> addr...: print 32-bit big-endian word at each address
import sys,struct
b=open('bin/%s.BIN'%sys.argv[1],'rb').read(); base=int(sys.argv[2],16)
for a in sys.argv[3:]:
    o=int(a,16)-base; print(a, '%08x'%struct.unpack('>I',b[o:o+4])[0])
