// Validate the standalone page without a browser or third-party dependencies.
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const html=readFileSync(new URL('architecture.html',import.meta.url),'utf8');
const code=html.match(/<script>([\s\S]*)<\/script>/)[1];
class Element{
 constructor(){this.children=[];this.style={};this.classList={toggle(){}};this.svg={style:{}}}
 append(...items){this.children.push(...items)}
 replaceChildren(...items){this.children=items}
 querySelector(q){assert.equal(q,'svg');return this.svg}
 click(){this.clicked=true}
}
const elements=new Map();const document={getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id)},createElement(){return new Element()},querySelectorAll(){return []}};
const context=vm.createContext({document,console,Blob,URL:{createObjectURL(){return 'blob:test'},revokeObjectURL(){}},setTimeout(fn){fn()}});
new vm.Script(code).runInContext(context);
assert.equal(elements.get('nav').children.length,9);
for(let i=0;i<9;i++){
 elements.get('nav').children[i].onclick();
 assert.match(elements.get('canvas').innerHTML,/<svg/);
 assert(elements.get('title').textContent.startsWith('0'+(i+1)));
 assert.equal(elements.get('detail').children.length,3);
 assert(elements.get('detail').children[1].textContent.length>40);
 assert(elements.get('notes').children[0].children.length>0);
 elements.get('plus').onclick();assert.equal(elements.get('scale').textContent,'125%');
 elements.get('minus').onclick();assert.equal(elements.get('scale').textContent,'100%');
 elements.get('export').onclick();
}
assert(!/<script[^>]+src=|<link[^>]+href=/.test(html),'page must be standalone');
const svg=readFileSync(new URL('architecture-overview.svg',import.meta.url),'utf8');assert(svg.startsWith('<svg'));assert(svg.endsWith('</svg>'));
console.log('PASS: 9 navigation views, details, zoom controls, SVG export, standalone assets and JavaScript syntax.');
