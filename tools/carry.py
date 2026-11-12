# carry.py <ghidra dir> <prog> <base hex>: carry hand names from sibling Saturn projects (Black Fire, Alien Trilogy) where the
# instruction stream (pc-relative/branch displacements masked) up to the first rts+delay slot is identical. -> work/names_<prog>.txt additions (tag [carry <game> <addr>])
import sys,os,struct,re,collections
g,prog,base=sys.argv[1],sys.argv[2],int(sys.argv[3],16)
D='C:/Users/john/Documents/'
srcs=[('BulkSlash','BS','MAIN',0x06004000),('BulkSlash','BS','ST1',0x06026000),('Congo','CG','KERN',0x06004000),('BlackDawn','BD','MAIN',0x06004000),('BlackFire','BF','PROG',0x06010000),('AlienTrilogy','AT','PROG',0x06004000)]
def norm(w):
    hi=w>>12
    if hi in (0x9,0xD,0xA,0xB): return w&0xF000
    if (w>>8) in (0x8B,0x89,0x8F,0x8D,0xC7): return w&0xFF00
    return w
def stream(b,o):
    out=[];i=o
    while i+2<=len(b) and len(out)<400:
        w=struct.unpack('>H',b[i:i+2])[0]; out.append(norm(w)); i+=2
        if w==0x000B:
            if i+2<=len(b): out.append(norm(struct.unpack('>H',b[i:i+2])[0]))
            break
    return tuple(out)
def funcs(gd,p):
    r=[]
    for l in open(os.path.join(gd,'funcinfo_%s.tsv'%p),encoding='utf-8',errors='replace'):
        t=l.split(' ')
        if t[0]=='F': r.append(int(t[1],16))
    return r
idx=collections.defaultdict(list)
for gm,tag,p,bs in srcs:
    gd=D+gm+'/ghidra'; b=open(gd+'/bin/%s.BIN'%p,'rb').read()
    hand={}
    for l in open(gd+'/work/names_%s.txt'%p,encoding='utf-8'):
        t=l.rstrip('\n').split(' ',2)
        if len(t)>1 and l[0]!='#': hand[int(t[0],16)]=t[1]
    for a in funcs(gd,p):
        if a in hand:
            s=stream(b,a-bs)
            if len(s)>=8: idx[s].append((hand[a],tag,a))
b=open(os.path.join(g,'bin',prog+'.BIN'),'rb').read()
res={}
for a in funcs(g,prog):
    s=stream(b,a-base)
    if s in idx:
        names=set(n for n,_,_ in idx[s])
        if len(names)==1:
            n,t,aa=idx[s][0]; res[a]=(n,'%s %08x'%(t,aa))
for a,(n,s) in sorted(res.items()): print('%08x %s carried from %s identical instruction stream [carry %s]'%(a,n,s,s))
sys.stderr.write('%s carried %d\n'%(prog,len(res)))
