import {metricOrder,metricValues,metricNames,baseMetrics,environmentalMetrics,optionLabel,vectorFromMetrics,evaluateVector,normalizeVectorInput} from './cvss4.js';

const escape=value=>String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const color=severity=>({None:'slate',Low:'blue',Medium:'amber',High:'orange',Critical:'red'}[severity]);
const readMetrics=root=>Object.fromEntries([...root.querySelectorAll('[data-cvss]')].map(select=>[select.dataset.cvss,select.value]));

export function readCvssCalculator(root){
 // The import handler validates drafts and copies valid metrics into the controls.
 // Save those controls, which are also the source of the displayed calculation.
 if(root.querySelector('#cvssImport').getAttribute('aria-invalid')==='true'){
  throw Error(root.querySelector('#cvssImportError').textContent||'Perbaiki vector CVSS 4.0 sebelum menyimpan.');
 }
 return evaluateVector(vectorFromMetrics(readMetrics(root)));
}

export function mountCvssCalculator(root,initialVector=''){
 const fields=keys=>`<div class="factorGrid">${keys.map(key=>`<label class="field">${metricNames[key]} (${key})<select data-cvss="${key}">${baseMetrics.includes(key)?'<option value="">Pilih metrik…</option>':''}${metricValues[key].map(value=>`<option value="${value}">${escape(optionLabel(key,value))} [${value}]</option>`).join('')}</select></label>`).join('')}</div>`;
 root.innerHTML=`<h2>Kalkulator CVSS 4.0</h2>
 <div class="score cvss-score" aria-live="polite"><div><span id="cvssType">CVSS-B</span><b id="cvssScore">—</b></div><div id="cvssSeverity" class="severity slate">Belum lengkap</div></div>
 <p id="cvssCompletion" class="cvss-help">Pilih seluruh 11 metrik Base untuk menghitung skor.</p>
 <details open data-group="import"><summary>Gunakan vector CVSS 4.0 yang sudah ada</summary><label class="field">Tempel vector CVSS 4.0<textarea id="cvssImport" rows="3" placeholder="Tempel vector lengkap di sini untuk menghitung otomatis" spellcheck="false" aria-describedby="cvssImportHelp cvssImportError"></textarea></label><p id="cvssImportHelp" class="cvss-help">Vector yang valid langsung mengisi metrik dan menghitung skor. Atau pilih seluruh 11 metrik Base di bawah.</p><button type="button" class="secondary" id="applyCvssVector">Terapkan vector</button><p id="cvssImportError" role="alert"></p></details>
 <h3>Base — karakteristik eksploitasi</h3>${fields(baseMetrics.slice(0,5))}
 <h3>Dampak pada sistem rentan</h3>${fields(['VC','VI','VA'])}
 <h3>Dampak pada sistem berikutnya</h3><p class="cvss-help">Sistem lain yang terdampak setelah sistem rentan berhasil dieksploitasi.</p>${fields(['SC','SI','SA'])}
 <details data-group="threat"><summary>Threat — kondisi eksploitasi (opsional)</summary>${fields(['E'])}</details>
 <details data-group="environment"><summary>Environmental — konteks lingkungan (opsional)</summary>${fields(environmentalMetrics)}</details>
 <details data-group="supplemental"><summary>Supplemental — informasi tambahan (opsional)</summary><p class="cvss-help">Metrik ini dicatat dalam vector dan tidak mengubah skor.</p>${fields(metricOrder.slice(26))}</details>
 <label class="field">Vector CVSS 4.0<textarea id="cvssVector" rows="3" readonly placeholder="Dihasilkan setelah metrik Base lengkap"></textarea></label>
 <p class="cvss-help">Perhitungan mengikuti <a href="https://www.first.org/cvss/v4.0/specification-document" target="_blank" rel="noopener noreferrer">CVSS 4.0 FIRST</a>. Threat dan Environmental yang belum ditentukan mengikuti nilai default standar.</p>`;
 const input=root.querySelector('#cvssImport');
 const error=root.querySelector('#cvssImportError');
 function clearError(){error.textContent='';input.removeAttribute('aria-invalid');}
 function unavailable(label,message){
  root.querySelector('#cvssScore').textContent='—';
  const severity=root.querySelector('#cvssSeverity');severity.textContent=label;severity.className='severity slate';
  root.querySelector('#cvssCompletion').textContent=message;
  root.querySelector('#cvssType').textContent='CVSS 4.0';root.querySelector('#cvssVector').value='';
 }
 function update(){
  const metrics=readMetrics(root);
  const remaining=baseMetrics.filter(key=>!metrics[key]).length;
  const severity=root.querySelector('#cvssSeverity');
  if(remaining){
   unavailable('Belum lengkap',`${remaining} metrik Base belum dipilih. Pilih metrik atau tempel vector lengkap.`);return;
  }
  const rating=evaluateVector(vectorFromMetrics(metrics));
  root.querySelector('#cvssScore').textContent=rating.score.toFixed(1);
  root.querySelector('#cvssType').textContent=rating.nomenclature;
  severity.textContent=rating.severity;severity.className=`severity ${color(rating.severity)}`;
  root.querySelector('#cvssVector').value=rating.vector;
  root.querySelector('#cvssCompletion').textContent='Skor dan severity dihitung otomatis dari vector ini.';
 }
 function apply(vector){
  const parsed=evaluateVector(normalizeVectorInput(vector));
  for(const select of root.querySelectorAll('[data-cvss]'))select.value=parsed.metrics[select.dataset.cvss];
  for(const [group,keys] of [['threat',['E']],['environment',environmentalMetrics],['supplemental',metricOrder.slice(26)]]){
   root.querySelector(`[data-group="${group}"]`).open=keys.some(key=>parsed.metrics[key]!=='X');
  }
  update();
 }
 function importVector(explicit=false){
  clearError();
  if(!input.value.trim()&&!explicit){update();return;}
  try{apply(input.value);}
  catch(cause){
   error.textContent=cause.message;
   if(input.value.trim()){
    input.setAttribute('aria-invalid','true');
    unavailable('Vector belum valid','Perbaiki vector atau ubah metrik Base untuk melanjutkan perhitungan.');
   }
  }
 }
 // Read the current controls and handle both keyboard/input and select changes.
 // Property handlers are replaced when remounting, so listeners cannot accumulate.
 root.oninput=root.onchange=event=>{
  if(event.target===input){importVector();return;}
  if(event.target.matches('[data-cvss]')){
   clearError();update();input.value=root.querySelector('#cvssVector').value;
  }
 };
 root.querySelector('#applyCvssVector').onclick=()=>importVector(true);
 update();
 if(initialVector){input.value=initialVector;importVector();}
}
