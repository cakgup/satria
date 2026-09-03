// Images stay in the editor until the checklist is saved; cancel never uploads them.
window.WSTG_EVIDENCE={create(root,initial=[],options={}){
 const baseUrl=options.baseUrl||'/assessments/api/evidence',saveLabel=options.saveLabel||'Simpan hasil pengujian';
 let images=initial.map(image=>({...image})),pending=Promise.resolve();
 const list=root.querySelector('.evidence-previews');
 const message=root.querySelector('.evidence-message');
 const picker=root.querySelector('input[type=file]');
 const busy=()=>Boolean(options.isBusy?.())||Boolean(root.querySelector('#tEvidence')?.disabled)||Boolean(root.closest('.modal')?.querySelector('.actions .primary')?.disabled);
 function render(){
  list.replaceChildren();
  images.forEach((item,index)=>{
   const card=document.createElement('figure');card.className='evidence-preview';
   const img=document.createElement('img');img.src=item.id?`${baseUrl}/${item.id}`:item.dataUrl;img.alt=item.name;
   const caption=document.createElement('figcaption');
   const name=document.createElement('span');name.textContent=`${item.name} (${Math.ceil(item.size/1024)} KB)`;
   const remove=document.createElement('button');remove.type='button';remove.className='secondary';remove.textContent='Hapus gambar';
   remove.setAttribute('aria-label',`Hapus gambar ${index+1}`);
   remove.onclick=()=>{if(busy())return;images.splice(index,1);render();message.textContent=`Perubahan gambar akan diterapkan saat ${saveLabel} ditekan.`;};
   caption.append(name,remove);card.append(img,caption);list.append(card);
  });
 }
 const read=file=>new Promise((resolve,reject)=>{
  const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(Error('Gambar gagal dibaca. Coba paste kembali.'));reader.readAsDataURL(file);
 });
 function add(files){
  if(busy())return;
  const incoming=Array.from(files);
  pending=pending.then(async()=>{
   if(!root.isConnected)return;
   message.textContent='Membaca gambar…';
   try{
    if(images.length+incoming.length>5)throw Error('Maksimal 5 gambar per catatan.');
    let total=images.reduce((sum,image)=>sum+image.size,0);
    const additions=[];
    for(const file of incoming){
     if(!['image/png','image/jpeg','image/webp'].includes(file.type))throw Error('Gunakan gambar PNG, JPEG, atau WebP.');
     if(file.size>5*1024*1024)throw Error('Ukuran setiap gambar maksimal 5 MB.');
     total+=file.size;if(total>15*1024*1024)throw Error('Total gambar maksimal 15 MB.');
     const dataUrl=await read(file);
     const image=new Image();image.src=dataUrl;
     try{await image.decode();}catch{throw Error('Berkas gambar tidak dapat dibaca.');}
     additions.push({name:(file.name||`Screenshot-${Date.now()}.png`).slice(0,200),size:file.size,dataUrl});
    }
    if(!root.isConnected)return;
    images.push(...additions);render();
    message.textContent=`${images.length} gambar siap. Klik ${saveLabel} untuk menyimpannya.`;
   }catch(error){message.textContent=error.message;}
  });
 }
 root.addEventListener('paste',event=>{
  const files=Array.from(event.clipboardData?.items||[]).filter(item=>item.kind==='file'&&item.type.startsWith('image/')).map(item=>item.getAsFile()).filter(Boolean);
  if(files.length){event.preventDefault();add(files);}
 });
 picker.addEventListener('change',()=>{if(picker.files.length)add(picker.files);picker.value='';});
 render();
 return {async collect(){await pending;return images.map(image=>image.id?{id:image.id}:{name:image.name,dataUrl:image.dataUrl});}};
}};
