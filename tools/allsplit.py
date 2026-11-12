# allsplit.py <file> [outdir]: parse 16-byte dir entries (startSector,nSectors,dest,0), list RAM-dest entries with prologue density, optionally write them
import sys,struct,os
f=sys.argv[1]; b=open(f,'rb').read(); out=sys.argv[2] if len(sys.argv)>2 else None
n=os.path.basename(f).replace('.','_')
i=0;ents=[]
while i+16<=len(b):
    s,c,d,z=struct.unpack('>IIII',b[i:i+16])
    if s==0 and c==0: break
    ents.append((s,c,d)); i+=16
    if i>=ents[0][0]*2048: break
def dens(x):
    pro=sum(1 for k in range(0,len(x)-1,2) if x[k:k+2] in (b'\x4f\x22',b'\x2f\xe6',b'\x2f\xd6',b'\x2f\xc6',b'\x2f\x86'))
    return pro
for k,(s,c,d) in enumerate(ents):
    x=b[s*2048:(s+c)*2048]; ram=(d>>24)==6 or (d>>20)==2
    print(f"{n} e{k} sec={s} n={c} bytes={c*2048} dest={d:08x} {'RAM' if ram else 'vram'} prol={dens(x) if ram else '-'} per64k={dens(x)*65536//max(1,len(x)) if ram else '-'}")
    if out and ram and dens(x)>20:
        os.makedirs(out,exist_ok=True); open(f"{out}/{n}_e{k}_{d:08x}.bin",'wb').write(x)
