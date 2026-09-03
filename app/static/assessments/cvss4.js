import {cvss_score,macroVector,cvssLookup_global,maxSeverity,expectedMetricOrder} from './vendor/cvss4/engine.js';

export const metricValues=expectedMetricOrder;
export const metricOrder=Object.keys(metricValues);
export const baseMetrics=metricOrder.slice(0,11);
export const environmentalMetrics=metricOrder.slice(12,26);

// Accept whitespace around separators from copied/wrapped text, without relaxing
// metric validation or changing the strict vector format accepted by the API.
export function normalizeVectorInput(value){
 return String(value??'').trim().replace(/\s*([/:])\s*/g,'$1');
}

export function parseVector(vector){
 if(typeof vector!=='string'||!vector.trim())throw Error('Vector masih kosong. Tempel vector CVSS 4.0 atau pilih seluruh 11 metrik Base.');
 if(typeof vector!=='string'||!vector.startsWith('CVSS:4.0/'))throw Error('Gunakan vector CVSS:4.0 lengkap. CVSS 3.x tidak didukung.');
 const metrics=Object.fromEntries(metricOrder.map(key=>[key,'X']));
 let previous=-1;
 for(const part of vector.split('/').slice(1)){
  const [key,value,...extra]=part.split(':');
  const index=metricOrder.indexOf(key);
  if(extra.length||index<0||!metricValues[key].includes(value))throw Error(`Metrik CVSS 4.0 tidak valid: ${part}`);
  if(index<=previous)throw Error('Urutan metrik CVSS 4.0 tidak valid atau ada metrik duplikat.');
  metrics[key]=value;previous=index;
 }
 if(baseMetrics.some(key=>metrics[key]==='X'))throw Error('Lengkapi seluruh 11 metrik Base CVSS 4.0.');
 return metrics;
}
export function vectorFromMetrics(metrics){
 if(baseMetrics.some(key=>!metrics[key]||metrics[key]==='X'))throw Error('Lengkapi seluruh 11 metrik Base CVSS 4.0.');
 const vector='CVSS:4.0/'+metricOrder.filter(key=>baseMetrics.includes(key)||(metrics[key]&&metrics[key]!=='X')).map(key=>`${key}:${metrics[key]}`).join('/');
 parseVector(vector);return vector;
}
export function severityForScore(score){
 if(!Number.isFinite(score)||score<0||score>10)throw Error('Skor CVSS di luar rentang 0–10.');
 return score===0?'None':score<4?'Low':score<7?'Medium':score<9?'High':'Critical';
}
export function evaluateVector(vector){
 const metrics=parseVector(vector);
 const score=cvss_score(metrics,cvssLookup_global,maxSeverity,macroVector(metrics));
 const threat=metrics.E!=='X',environment=environmentalMetrics.some(key=>metrics[key]!=='X');
 return {vector:vectorFromMetrics(metrics),score,severity:severityForScore(score),nomenclature:`CVSS-B${threat?'T':''}${environment?'E':''}`,metrics};
}

export const metricNames={
 AV:'Attack Vector',AC:'Attack Complexity',AT:'Attack Requirements',PR:'Privileges Required',UI:'User Interaction',
 VC:'Vulnerable System Confidentiality',VI:'Vulnerable System Integrity',VA:'Vulnerable System Availability',
 SC:'Subsequent System Confidentiality',SI:'Subsequent System Integrity',SA:'Subsequent System Availability',
 E:'Exploit Maturity',CR:'Confidentiality Requirement',IR:'Integrity Requirement',AR:'Availability Requirement',
 S:'Safety',AU:'Automatable',R:'Recovery',V:'Value Density',RE:'Vulnerability Response Effort',U:'Provider Urgency'
};
for(const key of environmentalMetrics.filter(key=>key.startsWith('M')))metricNames[key]='Modified '+metricNames[key.slice(1)];
const choices={
 AV:{N:'Network — melalui jaringan',A:'Adjacent — jaringan berdekatan',L:'Local — akses lokal',P:'Physical — akses fisik'},
 AC:{L:'Low — kompleksitas rendah',H:'High — kompleksitas tinggi'},
 AT:{N:'None — tanpa kondisi tambahan',P:'Present — perlu kondisi deployment tertentu'},
 PR:{N:'None — tanpa hak akses',L:'Low — hak akses rendah',H:'High — hak akses tinggi'},
 UI:{N:'None — tanpa interaksi pengguna',P:'Passive — interaksi pasif',A:'Active — tindakan aktif pengguna'},
 E:{A:'Attacked — serangan telah dilaporkan',P:'Proof-of-Concept — PoC tersedia',U:'Unreported — belum ada laporan'},
 S:{N:'Negligible — tidak signifikan',P:'Present — berdampak pada keselamatan'},
 AU:{N:'No — tidak dapat diotomatisasi',Y:'Yes — dapat diotomatisasi'},
 R:{A:'Automatic — pulih otomatis',U:'User — perlu tindakan pengguna',I:'Irrecoverable — tidak dapat dipulihkan'},
 V:{D:'Diffuse — tersebar',C:'Concentrated — terkonsentrasi'},
 RE:{L:'Low — upaya rendah',M:'Moderate — upaya sedang',H:'High — upaya tinggi'},
 U:{Clear:'Clear',Green:'Green',Amber:'Amber',Red:'Red'}
};
export function optionLabel(key,value){
 if(value==='X')return 'Not Defined — belum ditentukan';
 const base=key.startsWith('M')?key.slice(1):key;
 return choices[base]?.[value]||{H:'High — tinggi',L:'Low — rendah',N:'None — tidak ada',M:'Medium — sedang',S:'Safety — keselamatan'}[value]||value;
}
