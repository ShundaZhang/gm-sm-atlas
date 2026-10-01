# -*- coding: utf-8 -*-
"""Accessible, bilingual HTML diagrams; no external renderer required."""
from html import escape


def tr(lang, en, zh):
    return zh if lang == 'zh' else en


def node(title, text='', tone='', tag=''):
    return f'<div class="viz-node {tone}">{f"<span class=viz-tag>{tag}</span>" if tag else ""}<strong>{title}</strong>{f"<small>{text}</small>" if text else ""}</div>'


def arrow(label='', direction='right'):
    symbol = '↓' if direction == 'down' else '→'
    return f'<div class="viz-arrow {direction}"><span aria-hidden="true">{symbol}</span><small>{label}</small></div>'


def frame(lang, ident, title, body, caption, url, source):
    return f'<figure class="knowledge-viz" id="{ident}" aria-labelledby="{ident}-title"><div class="viz-heading"><span>VISUAL GUIDE</span><h3 id="{ident}-title">{title}</h3></div>{body}<figcaption>{caption}<a href="{url}" target="_blank" rel="noopener noreferrer">{tr(lang,"Source","资料")} · {source} ↗</a></figcaption></figure>'


def flow(items):
    return '<div class="viz-flow">' + ''.join(items) + '</div>'



def sequence(lang, actors, messages):
    """Three visible lifelines; arrows include an explicit sender/recipient label."""
    hint = '<p class="viz-scroll-hint">' + tr(lang, 'Read from top to bottom · Scroll horizontally on small screens', '从上到下阅读 · 小屏幕可左右滚动') + '</p>'
    body = hint + '<div class="viz-sequence-scroll" tabindex="0" role="region" aria-label="' + tr(lang, 'Message sequence diagram', '消息时序图') + '"><div class="viz-sequence"><div class="viz-actors">'
    body += ''.join(node(name, detail, tone) for name, detail, tone in actors) + '</div>'
    for i, (src, dst, text) in enumerate(messages, 1):
        if src == dst:
            item = f'<div class="viz-self" style="grid-column:{src+1}"><span class="viz-step">{i:02}</span>{text}</div>'
        else:
            start, end = sorted((src+1, dst+1))
            direction = ' reverse' if src > dst else ''
            margin = 50 / (end - start + 1)
            route = escape(actors[src][0]) + ' → ' + escape(actors[dst][0])
            item = f'<div class="viz-message{direction}" style="grid-column:{start}/{end+1};margin-left:{margin}%;margin-right:{margin}%"><span class="viz-step">{i:02}</span>{text}<small>{route}</small></div>'
        body += '<div class="viz-message-row">' + item + '</div>'
    return body + '</div></div>'
