#!/bin/bash
# usage: apply.sh <IP|KERN|DUCK>: autoname -> hand file, apply names, re-export (funcinfo + decomp)
cd /c/Users/john/Documents/BulkSlash/ghidra
p=$1; G='C:\Users\john\Documents\BulkSlash\ghidra'; L=/c/Users/john/Documents/BulkSlash/ghidra/logs
if [ "$p" != IP ]; then py -3.13 -I ../tools/autoname.py . $p >/dev/null; cp work/auto_$p.txt hand_$p.txt; fi
bash run.sh $L/apply_$p.log -process $p.BIN -noanalysis -postScript ApplyNames.java "$G\hand_$p.txt" >/dev/null 2>&1
bash run.sh $L/export_$p.log -process $p.BIN -noanalysis -readOnly -postScript ExportFuncInfo.java "$G\funcinfo_$p.tsv" >/dev/null 2>&1
echo "$p FUN_ left: $(awk '$1=="F" && $3 ~ /^FUN_/' funcinfo_$p.tsv | wc -l) total $(awk '$1=="F"' funcinfo_$p.tsv | wc -l)"
