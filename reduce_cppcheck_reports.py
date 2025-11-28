import os
import re

indir="raw_cppcheck"
outdir="cppcheck"
os.makedirs(outdir,exist_ok=True)

critical_re=re.compile(r"^nofile:0:0: information: Active checkers: There was critical errors \(use --checkers-report=<filename> to see details\) \[checkersReport\]$")
active_re=re.compile(r"^nofile:0:0: information: Active checkers: \d+/592 \(use --checkers-report=<filename> to see details\) \[checkersReport\]$")

for fn in os.listdir(indir):
    if not fn.endswith("_report.txt"):
        continue
    p=os.path.join(indir,fn)
    out=[]
    flag_replace=False
    with open(p,"r") as f:
        for line in f:
            s=line.rstrip("\n")
            if critical_re.match(s):
                flag_replace=True
                break
            if not active_re.match(s) and s.strip():
                out.append(s)
    if flag_replace or not out:
        out=["No detected issues"]
    with open(os.path.join(outdir,fn.replace("_report.txt","_report.txt")),"w") as g:
        for x in out:
            g.write(x+"\n")
