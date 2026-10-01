# -*- coding: utf-8 -*-
"""Check the published document graph and basic accessibility contracts."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit,unquote
from content import PAGES,chapter
from catalog import SOURCES
ROOT=Path(__file__).parent
class Page(HTMLParser):
    def __init__(self):super().__init__();self.ids=[];self.links=[];self.h1=0;self.lang=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.append(a['id'])
        if tag=='h1':self.h1+=1
        if tag=='html':self.lang=a.get('lang')
        for key in ('href','src'):
            if key in a:self.links.append(a[key])
pages={}
for path in ROOT.glob('*.html'):
    doc=Page();doc.feed(path.read_text(encoding='utf-8'));pages[path.name]=doc
    assert doc.h1==1,(path,'H1 count',doc.h1)
    assert len(doc.ids)==len(set(doc.ids)),(path,'duplicate IDs')
    assert doc.lang==('zh-CN' if '.zh.' in path.name else 'en'),(path,'language')
    assert '\ufffd' not in path.read_text(),(path,'replacement characters')
for name,doc in pages.items():
    for link in doc.links:
        u=urlsplit(link)
        if u.scheme or u.netloc:continue
        target=unquote(u.path) or name
        path=ROOT/target
        assert path.is_file(),(name,'missing target',link)
        if u.fragment and path.suffix=='.html':assert unquote(u.fragment) in pages[path.name].ids,(name,'missing anchor',link)
for lang in ('en','zh'):
    for page in PAGES:
        name=page+('.zh' if lang=='zh' else '')+'.html'
        assert name in pages,('missing bilingual page',name)
        for row in chapter(page,lang):
            for ref in row[4]:assert ref in SOURCES,(page,'unknown source',ref)
assert len(pages)==len(PAGES)*2
for lang in ('en','zh'):
    suffix='.zh' if lang=='zh' else ''
    text=(ROOT/f'labs{suffix}.html').read_text()
    assert all(f'data-action="{a}"' in text for a in ('hash','block','curve'))
print(f'PASS: {len(pages)} bilingual pages; local targets/anchors, unique IDs, H1, language and exercise wiring')

import zipfile
with zipfile.ZipFile(ROOT/'examples.zip') as z:
    for name in z.namelist():
        assert "node_modules" not in name and ".env" not in name
        relative=name.split('/',1)[1]
        assert z.read(name)==(ROOT/'examples'/relative).read_bytes(),('zip content mismatch',name)
    assert len(z.namelist())==4
print('PASS: downloadable project matches source and excludes dependency folders')
