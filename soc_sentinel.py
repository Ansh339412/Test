#!/usr/bin/env python3
"""SOC Sentinel: rule-based authentication log analyzer."""
import argparse
import csv
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Accepts common Linux auth.log/secure-style messages with an ISO timestamp.
ISO_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)?)\s+(?P<body>.*)$")
FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SUCCESS_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
ALT_RE = re.compile(r"(?P<event>FAILED|SUCCESS)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)", re.I)

def parse_line(line):
    line=line.strip()
    m=ISO_RE.match(line)
    if m:
        raw=m.group("ts").replace("Z","+00:00")
        try:
            ts=datetime.fromisoformat(raw)
            if ts.tzinfo is None: ts=ts.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        body=m.group("body")
    else:
        # Skip lines without a parseable timestamp instead of guessing.
        return None
    f=FAIL_RE.search(body); s=SUCCESS_RE.search(body); a=ALT_RE.search(body)
    if f: event, user, ip="FAILED", f["user"], f["ip"]
    elif s: event, user, ip="SUCCESS", s["user"], s["ip"]
    elif a: event, user, ip=a["event"].upper(), a["user"], a["ip"]
    else: return None
    return {"timestamp":ts, "event":event, "user":user, "ip":ip}

def analyze(records, threshold=5, window_minutes=10):
    failures=defaultdict(deque)
    alerts=[]
    window=timedelta(minutes=window_minutes)
    for r in sorted(records, key=lambda x:x["timestamp"]):
        key=r["ip"]
        q=failures[key]
        cutoff=r["timestamp"]-window
        while q and q[0]["timestamp"] < cutoff: q.popleft()
        if r["event"]=="FAILED":
            q.append(r)
            if len(q)==threshold:
                alerts.append({"severity":"HIGH","type":"Possible brute-force",
                    "source_ip":key,"user":r["user"],"time":r["timestamp"].isoformat(),
                    "evidence":f"{len(q)} failed logins within {window_minutes} minutes"})
        elif r["event"]=="SUCCESS" and q:
            alerts.append({"severity":"MEDIUM","type":"Successful login after failures",
                "source_ip":key,"user":r["user"],"time":r["timestamp"].isoformat(),
                "evidence":f"Successful login observed after {len(q)} recent failure(s)"})
    return alerts

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",required=True); p.add_argument("--threshold",type=int,default=5)
    p.add_argument("--window",type=int,default=10); p.add_argument("--out",default="reports")
    args=p.parse_args()
    if args.threshold<2 or args.window<1: p.error("threshold must be >=2 and window >=1")
    records=[]
    for line in Path(args.input).read_text(encoding="utf-8",errors="replace").splitlines():
        r=parse_line(line)
        if r: records.append(r)
    alerts=analyze(records,args.threshold,args.window)
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    (out/"alerts.json").write_text(json.dumps(alerts,indent=2),encoding="utf-8")
    with (out/"alerts.csv").open("w",newline="",encoding="utf-8") as f:
        cols=["severity","type","source_ip","user","time","evidence"]
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(alerts)
    print(f"Parsed {len(records)} events; generated {len(alerts)} alert(s).")
    print(f"Reports: {out.resolve()}")

if __name__=="__main__": main()
