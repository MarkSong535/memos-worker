import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const html = readFileSync(new URL('../src/public/index.html', import.meta.url), 'utf8');
const start = html.indexOf('        if (note.is_admin) {');
const end = html.indexOf('        return noteElement;', start);
assert.ok(start !== -1 && end > start);
for (const isAdmin of [true, false]) {
  test(`note access icon placement and visibility for admin=${isAdmin}`, () => {
    const edit = {}, menu = {}, children = [edit, menu];
    const actions = { insertBefore(node, before) { children.splice(children.indexOf(before), 0, node); } };
    vm.runInNewContext(html.slice(start, end), {
      note: { id: 42, is_admin: isAdmin },
      document: { createElement(tag) { assert.equal(tag, 'a'); return { setAttribute(name, value) { this[name] = value; } }; } },
      noteElement: { querySelector(selector) { return selector === '.note-actions' ? actions : menu; } },
    });
    assert.equal(children.length, isAdmin ? 3 : 2);
    if (isAdmin) {
      assert.equal(children[0], edit); assert.equal(children[2], menu);
      const icon = children[1];
      assert.equal(icon.href, '/admin.html?note=42');
      assert.equal(icon['aria-label'], 'Manage access');
      assert.match(icon.innerHTML, /viewBox="0 0 24 24"/);
      assert.match(icon.innerHTML, /M6 22q-/);
    }
  });
}
test('centralized access navigation and stale references are removed', () => {
  assert.doesNotMatch(html, /permissions-link|Manage note access/);
});
for (const [isAdmin, isDeleted, expected] of [[true,true,'#dc2626'],[true,false,'#000000'],[false,true,'#000000'],[false,false,'#000000']]) {
  test(`delete icon precedes edit and respects admin-only flag status (${isAdmin}, ${isDeleted})`, () => {
    const start = html.indexOf("        const deleteButton = document.createElement('button');");
    const end = html.indexOf('        if (note.is_admin) {', start);
    const edit = {}, menu = {}, children = [edit, menu]; let click, deleted;
    vm.runInNewContext(html.slice(start,end), {
      note: {id:42,is_admin:isAdmin,is_deleted:isDeleted},
      document: {createElement: () => ({style:{},setAttribute(name,value){this[name]=value},addEventListener(name,fn){click=fn}})},
      noteElement: {querySelector(selector){return selector === '.edit' ? edit : selector === '.more-actions-btn' ? menu : {insertBefore(node,before){children.splice(children.indexOf(before),0,node)}}}},
      deleteNoteFromEntry(id){deleted=id},
    });
    assert.equal(children.length,3);assert.equal(children[1],edit);
    assert.equal(children[0].style.color,expected);
    assert.match(children[0].innerHTML,/M7.616 20q-/);
    click({stopPropagation(){}});assert.equal(deleted,42);
  });
}
test('access page has no all-notes list or loading requests', () => {
  const page=readFileSync(new URL('../src/public/admin.html',import.meta.url),'utf8');
  const script=readFileSync(new URL('../src/public/admin.js',import.meta.url),'utf8');
  assert.doesNotMatch(page,/All notes|Archived notes are listed|id="more"|id="choose"/);
  assert.doesNotMatch(script,/listNotes|\/api\/notes\?page/);
});
