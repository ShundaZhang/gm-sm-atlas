# -*- coding: utf-8 -*-
"""Build a bilingual GM / SM cryptography learning atlas with Python standard library."""
from pathlib import Path
from html import escape
from diagrams import diagram
from content import PAGES, NAV, SOURCES, chapter
ROOT = Path(__file__).parent
SITE = 'GM / SM Cryptography Atlas'
REPO = 'gm-sm-atlas'
def pick(lang, en, zh): return zh if lang == 'zh' else en

def href(page, lang, anchor=''):
    return f'{page}{".zh" if lang == "zh" else ""}.html' + (f'#{anchor}' if anchor else '')

def cite(lang, *ids):
    return '<p class="references">' + pick(lang, 'Read the source: ', '对应资料：') + ' · '.join(f'<a href="{SOURCES[i][2]}" target="_blank" rel="noopener noreferrer">{SOURCES[i][1 if lang == "zh" else 0]} ↗</a>' for i in ids) + '</p>'

def para(*texts): return ''.join(f'<p>{t}</p>' for t in texts)

def table(headers, rows):
    return '<div class="table-wrap" tabindex="0"><table><thead><tr>' + ''.join(f'<th scope="col">{h}</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{c}</td>' for c in r) + '</tr>' for r in rows) + '</tbody></table></div>'

def cards(items):
    return '<div class="cards">' + ''.join(f'<article class="card"><span class="eyebrow">{tag}</span><h3>{title}</h3><p>{text}</p></article>' for tag, title, text in items) + '</div>'

def callout(title, text): return f'<aside class="callout"><strong>{title}</strong><p>{text}</p></aside>'

def code(text): return '<pre><code>' + escape(text) + '</code></pre>'

def section(label, title, intro, content, ident):
    return f'<section class="chapter-section" id="{ident}"><span class="eyebrow">{label}</span><h2>{title}</h2><p class="lead">{intro}</p>{content}</section>'

def hero(lang, page, title, text, anchors=()):
    jumps = ''.join(f'<a href="#{ident}">{label}</a>' for ident, label in anchors)
    return f'<section class="page-intro"><div class="wrap"><span class="eyebrow">{NAV[lang][PAGES.index(page)]} / FIELD GUIDE</span><h1>{title}</h1><p>{text}</p><nav class="jump-links" aria-label="{pick(lang, "On this page", "本页目录")}">{jumps}</nav></div></section>'

def shell(lang, page, body):
    current = 'aria-current="page"'
    nav = ''.join(f'<a href="{href(p,lang)}" {current if p == page else ""}>{n}</a>' for p,n in zip(PAGES,NAV[lang]))
    langs = ''.join(f'<a data-atlas-lang="{l}" href="{href(page,l)}" {current if l == lang else ""}>{label}</a>' for l,label in [('en','EN'),('zh','中文')])
    title = SITE if page == 'index' else f'{NAV[lang][PAGES.index(page)]} · {SITE}'
    desc = pick(lang, 'Understand SM2, SM3 and SM4 internals and compare NIST curves, SHA-2 / SHA-3 and AES with diagrams and runnable reference code.', '通过图解与参考实现，理解 SM2 / SM3 / SM4，详细比较 NIST 曲线、SHA-2 / SHA-3 与 AES。')
    scripts = '<script src="crypto.js" defer></script><script src="labs.js" defer></script>' if page == 'labs' else '<script src="tools.js" defer></script>' if page == 'tools' else ''
    prevnext = ''
    if page != 'index':
        idx=PAGES.index(page)
        prevnext = '<nav class="chapter-pager" aria-label="' + pick(lang,'Chapters','章节') + '">'
        prevnext += f'<a href="{href(PAGES[idx-1],lang)}">← {NAV[lang][idx-1]}</a>'
        if idx < len(PAGES)-1: prevnext += f'<a href="{href(PAGES[idx+1],lang)}">{NAV[lang][idx+1]} →</a>'
        prevnext += '</nav>'
    return f'''<!doctype html>
<html lang="{'zh-CN' if lang == 'zh' else 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#182638"><meta name="description" content="{desc}"><title>{escape(title)} · ShundaZhang</title><link rel="icon" href="favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="diagrams.css"><script src="language.js"></script>{scripts}</head>
<body><div class="topbar"><div class="wrap"><a href="https://shundazhang.github.io/">← {pick(lang,'Personal home','个人主页')}</a><nav class="languages" aria-label="{pick(lang,'Language selection','语言选择')}">{langs}</nav></div></div><a class="skip" href="#main">{pick(lang,'Skip to content','跳至正文')}</a><header><div class="wrap brand-row"><a class="brand" href="{href('index',lang)}"><span class="brand-mark">SM/</span><span>{pick(lang,'GM / SM CRYPTOGRAPHY','国密算法')}<small>LEARNING ATLAS</small></span></a><a class="repo-link" href="https://github.com/ShundaZhang/{REPO}">GitHub ↗</a></div><nav class="chapter-nav wrap" aria-label="{pick(lang,'Main navigation','主导航')}">{nav}</nav></header><main id="main">{body}{'<div class="reading wrap">'+prevnext+'</div>' if prevnext else ''}</main><footer><div class="wrap"><div><strong>{pick(lang,SITE,'国密算法知识地图')}</strong><p>{pick(lang,'Algorithms, representations and implementation choices','算法、编码与实现选择')}</p></div><p>{pick(lang,'Reviewed 1 Oct 2026 · EN / 中文','复核于 2026 年 10 月 1 日 · EN / 中文')}</p></div></footer></body></html>'''
