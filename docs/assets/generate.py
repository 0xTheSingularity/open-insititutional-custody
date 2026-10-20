#!/usr/bin/env python3
"""Generate the README's standalone SVG assets with the Python standard library."""

from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PALETTES = {
    "light": {
        "bg": "#F6F5F2", "ink": "#202024", "muted": "#65636E",
        "line": "#D6D2DD", "accent": "#6951D5", "wash": "#EAE5F7",
    },
    "dark": {
        "bg": "#151518", "ink": "#F3F1ED", "muted": "#AAA6B2",
        "line": "#3A3642", "accent": "#B59AFB", "wash": "#282235",
    },
}


def text(x, y, value, size=24, color="ink", weight=400, extra=""):
    return (f'<text x="{x}" y="{y}" class="{color}" font-size="{size}" '
            f'font-weight="{weight}" {extra}>{escape(value)}</text>')


def svg(width, height, title, description, content, palette, motion=False):
    p = palette
    animation = """
    .signal { opacity: 0; }
    @media (prefers-reduced-motion: no-preference) {
      .signal { animation: transit 7.5s ease-in-out 1; }
      .gate-accent { animation: acknowledge 7.5s ease-in-out 1; }
    }
    @keyframes transit {
      0%, 8% { opacity: 0; stroke-dashoffset: 24; }
      14% { opacity: 1; stroke-dashoffset: 24; }
      46% { opacity: 1; stroke-dashoffset: -166; }
      60% { opacity: 1; stroke-dashoffset: -166; }
      88% { opacity: 1; stroke-dashoffset: -396; }
      96%, 100% { opacity: 0; stroke-dashoffset: -420; }
    }
    @keyframes acknowledge {
      0%, 35%, 78%, 100% { opacity: .10; }
      46%, 60% { opacity: .28; }
    }
    @media (prefers-reduced-motion: reduce) {
      .signal, .gate-accent { animation: none; }
    }
""" if motion else ""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" fill="none" role="img" aria-labelledby="title desc">
  <title id="title">{escape(title)}</title>
  <desc id="desc">{escape(description)}</desc>
  <style>
    text {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }}
    .ink {{ fill: {p['ink']}; }}
    .muted {{ fill: {p['muted']}; }}
    .accent {{ fill: {p['accent']}; }}
    .mono {{ font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace; }}
{animation}  </style>
  <rect width="{width}" height="{height}" fill="{p['bg']}"/>
  {content}
</svg>
'''


def mark(x, y, p):
    return f'''<g transform="translate({x} {y})" stroke="{p['accent']}" stroke-width="2.5" stroke-linecap="square">
    <path d="M8 0H0V24H8M24 0H32V24H24"/>
    <path d="M10 12H22"/>
  </g>'''


def boundary(x, y, p, scale=1):
    """An abstract native payload crosses a verified release boundary."""
    return f'''<g transform="translate({x} {y}) scale({scale})">
    <path d="M0 114H420" stroke="{p['line']}" stroke-width="2"/>
    <path class="signal" d="M0 114H420" stroke="{p['accent']}" stroke-width="3" stroke-dasharray="24 460"/>
    <path d="M22 64H77L96 83V164H22Z" fill="{p['bg']}" stroke="{p['ink']}" stroke-width="2"/>
    <path d="M77 64V83H96M39 99H65M39 114H77M39 129H69" stroke="{p['ink']}" stroke-width="2"/>
    <rect class="gate-accent" x="174" y="16" width="112" height="196" fill="{p['accent']}" opacity=".10"/>
    <path d="M198 16H174V212H198M262 16H286V212H262" stroke="{p['accent']}" stroke-width="3"/>
    <path d="M208 113L224 129L252 97" stroke="{p['accent']}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="389" cy="114" r="30" fill="{p['ink']}"/>
    <text x="389" y="126" fill="{p['bg']}" text-anchor="middle" font-size="44" style="font-family: Georgia, 'Times New Roman', serif">σ</text>
  </g>'''


def hero(p, mobile=False):
    if mobile:
        width, height = 640, 668
        content = mark(40, 34, p)
        content += text(88, 53, "OPEN INSTITUTIONAL CUSTODY", 16, "muted", 500,
                        'letter-spacing="1.15"')
        for y, line in [(157, "Your rules."), (239, "Before the"), (321, "signature.")]:
            content += text(36, y, line, 80, "ink", 500, 'letter-spacing="-3.8"')
        content += f'<path d="M40 370H600" stroke="{p["line"]}"/>'
        content += boundary(72, 404, p, 1.16)
    else:
        width, height = 1200, 492
        content = mark(56, 38, p)
        content += text(104, 57, "OPEN INSTITUTIONAL CUSTODY", 16, "muted", 500,
                        'letter-spacing="1.4"')
        for y, line in [(178, "Your rules."), (270, "Before the"), (362, "signature.")]:
            content += text(51, y, line, 94, "ink", 500, 'letter-spacing="-4.7"')
        content += boundary(726, 153, p)
        content += text(56, 440, "Payment controls, enforced at the signer.", 23, "muted")
        content += text(753, 440, "CHECK   /   RELEASE   /   SIGN", 17, "muted", 400,
                        'letter-spacing="1.1"')
    return svg(width, height, "Your rules. Before the signature.",
               "Open Institutional Custody. A native transaction passes through a verified release boundary before signature output. The brief animation stops automatically; reduced-motion preferences show the complete static illustration.",
               content, p, motion=True)


PHASES = [
    ("01", "Authorize", "Builder · approvers · authority", [
        "Build the transaction", "Review and approve", "Reserve shared exposure",
    ]),
    ("02", "Sign", "Signers · authority", [
        "Verify at each signer", "Commit release", "Produce the signature",
    ]),
    ("03", "Resolve", "Broadcaster · authority", [
        "Broadcast and observe", "Establish chain finality", "Settle the reservation",
    ]),
]


def flow(p, mobile=False):
    width, height = (640, 910) if mobile else (1200, 382)
    content = ""
    for i, (number, name, owner, steps) in enumerate(PHASES):
        if mobile:
            x, top = 40, 48 + i * 296
            content += text(x, top + 3, number, 22, "accent", 500,
                            'letter-spacing="1"')
            content += text(x + 66, top + 5, name, 37, "ink", 500,
                            'letter-spacing="-.8"')
            content += text(x + 66, top + 43, owner, 23, "muted")
            for j, step in enumerate(steps):
                y = top + 100 + j * 46
                content += text(x + 66, y, step, 27)
                content += f'<circle cx="{x + 22}" cy="{y - 9}" r="3" fill="{p["accent"]}"/>'
            content += f'<path d="M{x + 22} {top + 91}V{top + 183}" stroke="{p["line"]}"/>'
            if i < 2:
                content += f'<path d="M40 {top + 243}H600" stroke="{p["line"]}"/>'
        else:
            x, top = 40 + i * 396, 52
            content += text(x, top, number, 18, "accent", 500, 'letter-spacing="1"')
            if i < 2:
                content += f'<path d="M{x + 266} {top - 7}H{x + 344}M{x + 336} {top - 13}L{x + 344} {top - 7}L{x + 336} {top - 1}" stroke="{p["line"]}" stroke-width="1.5"/>'
            content += text(x, top + 64, name, 39, "ink", 500,
                            'letter-spacing="-1.1"')
            content += text(x, top + 99, owner, 20, "muted")
            for j, step in enumerate(steps):
                y = top + 160 + j * 44
                content += text(x + 22, y, step, 23)
                content += f'<circle cx="{x + 2}" cy="{y - 7}" r="2.5" fill="{p["accent"]}"/>'
            content += f'<path d="M{x + 2} {top + 153}V{top + 241}" stroke="{p["line"]}"/>'
    return svg(width, height, "Authorize. Sign. Resolve.",
               "First: build the transaction, independently review and approve, reserve shared exposure. Second: verify at each signer, commit the authority release, produce the native signature. Third: broadcast and observe, establish chain finality, settle the reservation. Approval, signature issuance, and settlement are separate decisions.",
               content, p)


def main():
    for theme, palette in PALETTES.items():
        for mobile in (False, True):
            suffix = f'{"mobile-" if mobile else ""}{theme}.svg'
            for name, render in (("banner", hero), ("flow", flow)):
                path = ROOT / f"custody-{name}-{suffix}"
                path.write_text(render(palette, mobile), encoding="utf-8")
                print(path.name)


if __name__ == "__main__":
    main()
