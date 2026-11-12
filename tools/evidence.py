# evidence.py <ghidra dir> <prog> <base hex>: per function: referenced strings (literal-pool pointers) and hardware register regions -> work/evidence_<prog>.txt
import sys,os,re,struct
g,prog,base=sys.argv[1],sys.argv[2],int(sys.argv[3],16)
b=open(os.path.join(g,'bin',prog+'.BIN'),'rb').read()
fs=sorted((int(l.split(' ')[1],16),int(l.split(' ')[4])) for l in open(os.path.join(g,'funcinfo_%s.tsv'%prog),encoding='utf-8',errors='replace') if l.startswith('F '))
strs={}
for m in re.finditer(rb'[\x20-\x7e]{4,}',b):
    strs[base+m.start()]=m.group().decode()
HW=[(0x20100000,0x20100080,'smpc'),(0x25890000,0x25900000,'cdblock'),(0x25b00000,0x25b00fff,'scsp'),(0x25a00000,0x25a80000,'sndram'),(0x25d00000,0x25d00020,'vdp1reg'),(0x25c00000,0x25c80000,'vdp1ram'),(0x25e00000,0x25e80000,'vdp2vram'),(0x25f00000,0x25f01000,'vdp2cram'),(0x25f80000,0x25f81000,'vdp2reg'),(0x25fe0000,0x25fe0100,'scu'),(0x25f80000,0x25f80200,'vdp2reg'),(0xfffffe00,0xffffffff,'sh2reg'),(0x05fe0000,0x05fe0100,'scu'),(0x05f80000,0x05f81000,'vdp2reg'),(0x05d00000,0x05d00020,'vdp1reg'),(0x05c00000,0x05c80000,'vdp1ram'),(0x05e00000,0x05e80000,'vdp2vram'),(0x05a00000,0x05a80000,'sndram'),(0x05b00000,0x05b00fff,'scsp'),(0x00100000,0x00100080,'smpc'),(0x05800000,0x05900000,'cdblock')]
out=[]
for i,(a,sz) in enumerate(fs):
    end=min(a+sz+int(os.environ.get('POOL','96')),fs[i+1][0] if i+1<len(fs) else base+len(b))
    seg=b[a-base:end-base]
    ss=[];hw=set()
    for k in range(0,len(seg)-3,4):
        v=struct.unpack('>I',seg[k:k+4])[0]
        if v in strs and len(strs[v])>=5 and sum(c.isalpha() for c in strs[v])>=0.5*len(strs[v]): ss.append(strs[v][:40])
        for lo,hi,n in HW:
            if lo<=v<hi: hw.add(n)
    out.append('%08x %d | %s | %s'%(a,end-a,','.join(sorted(hw)),' ; '.join(ss[:4])))
open(os.path.join(g,'work','evidence_%s.txt'%prog),'w',encoding='utf-8').write('\n'.join(out))
print(prog,len(out),sum(1 for o in out if o.split('|')[1].strip()),sum(1 for o in out if o.split('|')[2].strip()))
