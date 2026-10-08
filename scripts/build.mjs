/* SPDX-License-Identifier: GPL-3.0-or-later */
import {copyFile,mkdir,readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
if(Number(process.versions.node.split('.')[0])!==24)throw new Error('Node 24 requis');
await mkdir('dist',{recursive:true});
const files={};
for(const name of ['index.html','app.mjs','app.css','recipe-import-link.mjs']){
  const data=await readFile('web/'+name);await copyFile('web/'+name,'dist/'+name);
  files[name]={sha256:createHash('sha256').update(data).digest('hex'),size:data.length};
}
await writeFile('dist/build.json',JSON.stringify({schema:1,files},null,2)+'\n');
