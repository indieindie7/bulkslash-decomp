# orph.py <ghidra dir> <prog> <base hex> <lo hex> <hi hex>: sts.l pr,@-r15 (4f22) prologues inside [lo,hi) not covered by any function body in funcinfo -> prints addresses
import sys,os
g,prog,base,lo,hi=sys.argv[1],sys.argv[2],int(sys.argv[3],16),int(sys.argv[4],16),int(sys.argv[5],16)
b=open(os.path.join(g,'bin',prog+'.BIN'),'rb').read()
fs=sorted((int(l.split(' ')[1],16),int(l.split(' ')[4])) for l in open(os.path.join(g,'funcinfo_%s.tsv'%prog),encoding='utf-8',errors='replace') if l.startswith('F '))
cov=[(a,a+s) for a,s in fs]
import bisect
starts=[c[0] for c in cov]
def covered(x):
    i=bisect.bisect_right(starts,x)-1
    return i>=0 and cov[i][0]<=x<cov[i][1]
out=[]
for a in range(max(lo,base),min(hi,base+len(b))-1,2):
    o=a-base
    if b[o:o+2]==b'\x4f\x22' and not covered(a):
        prev=b[o-2:o]
        if prev in (b'\x00\x09',b'\x00\x0b',) or True: out.append(a)
print(' '.join('%x'%a for a in out))
