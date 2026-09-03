"""Compare Python CVSS with the vendored FIRST engine; requires Node.js."""
import json
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.cvss_reference import ReferenceCVSS4
js = """import {metricOrder,metricValues,vectorFromMetrics,evaluateVector} from './app/static/assessments/cvss4.js';
let seed=127,rows=[];
for(let n=0;n<4096;n++){
 const m=Object.fromEntries(metricOrder.map(k=>{
  seed=(Math.imul(seed,1664525)+1013904223)>>>0;
  const v=metricValues[k]; return [k,v[seed%v.length]];
 }));
 const vector=vectorFromMetrics(m);
 rows.push([vector,evaluateVector(vector).score]);
}
console.log(JSON.stringify(rows));"""
rows=json.loads(subprocess.check_output(['node','--input-type=module','-e',js],cwd=ROOT,text=True))
for vector, expected in rows:
 actual=ReferenceCVSS4(vector).scores()[0]
 assert actual == expected, (vector, expected, actual)
print(f'FIRST reference parity: {len(rows)} vectors passed')
