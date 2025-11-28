import os
import re

indir="raw_flawfinder"
outdir="flawfinder"
os.makedirs(outdir,exist_ok=True)

hit_re=re.compile(r"^[^:]+:\d+:")
nohits_re=re.compile(r"No hits found")
min_re=re.compile(r"Minimum risk level")

for fn in os.listdir(indir):
    if not fn.endswith("_report.txt"):
        continue
    p=os.path.join(indir,fn)
    out=[]
    with open(p,"r") as f:
        for line in f:
            s=line.rstrip("\n")
            if hit_re.search(s):
                out.append(s)
            elif nohits_re.search(s):
                out.append(s)
            elif min_re.search(s):
                out.append(s)
    with open(os.path.join(outdir,fn.replace("_report.txt","_report.txt")),"w") as g:
        for x in out:
            g.write(x+"\n")
