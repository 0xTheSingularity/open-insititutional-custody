#!/usr/bin/env python3
"""Build the GitHub wiki pages from docs/ and openwiki/.

The wiki is a generated mirror of those folders: every run replaces all pages,
so edit the source files in the repository, not the wiki. Links between mirrored
pages become wiki links. Links to any other repository file become GitHub URLs
pinned to the source commit, so file:line citations stay accurate.

    python3 scripts/wiki/build_wiki.py --out DIR [--commit SHA] [--repo OWNER/NAME]

Exits 1 and lists every broken link when a source link points at a missing file.
"""

import argparse
import pathlib
import posixpath
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_REPO = "0xTheSingularity/open-insititutional-custody"

# Guides appear in this order; docs pages missing from the list follow by name.
GUIDE_ORDER = [
    "docs/getting-started.md",
    "docs/payment-flow.md",
    "docs/concepts.md",
    "docs/local-stack.md",
    "docs/approval-client.md",
    "docs/signer-network.md",
    "docs/development.md",
    "docs/custody-check.md",
]

IMAGE_SUFFIXES = {".svg", ".png", ".gif", ".jpg", ".jpeg", ".webp"}
# Link text may wrap onto the next line, so links are matched across whole prose blocks.
LINK = re.compile(r'(!?)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?((?:\s+"[^"]*")?)\s*\)')
HTML_ATTR = re.compile(r'\b(src|href)="([^"]+)"')
FENCED_BLOCK = re.compile(r"^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$", re.M | re.S)


class Page:
    def __init__(self, source, name, title, description, body):
        self.source = source
        self.name = name
        self.title = title
        self.description = description
        self.body = body


def split_front_matter(text):
    """Return (top-level scalar fields, body) for a page with YAML front matter."""
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text
    fields = {}
    for line in text[4:end].splitlines():
        match = re.match(r"^([A-Za-z_]+):\s*(.+)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip().strip("\"'")
    return fields, text[end + 5 :]


def split_title(body):
    """Split off a leading '# Title': the wiki prints the page name as the title."""
    lines = body.lstrip("\n").splitlines()
    if lines and lines[0].startswith("# "):
        return lines[0][2:].strip(), "\n".join(lines[1:]).lstrip("\n")
    return None, body


def page_name(title):
    return "-".join(re.sub(r"[^A-Za-z0-9 -]+", "", title).split())


def collect():
    sources = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "docs").glob("*.md"))
    sources += sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "openwiki").rglob("*.md"))
    pages = {}
    for source in sources:
        fields, body = split_front_matter((ROOT / source).read_text(encoding="utf-8"))
        heading, body = split_title(body)
        if source == "docs/README.md":
            name = title = "Home"
        elif source == "openwiki/index.md":
            name = title = "Reference"
        elif source.startswith("openwiki/") and source.endswith("/index.md"):
            name = title = posixpath.basename(posixpath.dirname(source)).capitalize()
        else:
            title = fields.get("title") or heading or posixpath.basename(source)[:-3]
            name = page_name(title)
        pages[source] = Page(source, name, title, fields.get("description"), body)
    names = [page.name for page in pages.values()]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SystemExit(f"two source pages map to the same wiki page: {duplicates}")
    return pages


class Rewriter:
    def __init__(self, pages, repo, commit):
        self.pages = pages
        self.repo = repo
        self.commit = commit
        self.errors = []

    def target(self, link, source):
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", link) or link.startswith(("#", "//")):
            return link
        path, _, fragment = link.partition("#")
        anchor = f"#{fragment}" if fragment else ""
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
        if resolved == ".." or resolved.startswith("../"):
            self.errors.append(f"{source}: link leaves the repository: {link}")
            return link
        if (ROOT / resolved).is_dir() and f"{resolved}/index.md" in self.pages:
            resolved = f"{resolved}/index.md"
        if resolved in self.pages:
            return self.pages[resolved].name + anchor
        if not (ROOT / resolved).exists():
            self.errors.append(f"{source}: broken link: {link}")
            return link
        base = f"https://github.com/{self.repo}"
        if pathlib.PurePosixPath(resolved).suffix.lower() in IMAGE_SUFFIXES:
            return f"{base}/raw/{self.commit}/{resolved}"
        kind = "tree" if (ROOT / resolved).is_dir() else "blob"
        return f"{base}/{kind}/{self.commit}/{resolved}{anchor}"

    def render(self, page):
        parts, last = [], 0
        for block in FENCED_BLOCK.finditer(page.body):
            parts.append(self.prose(page.body[last : block.start()], page.source))
            parts.append(block.group(0))
            last = block.end()
        parts.append(self.prose(page.body[last:], page.source))
        return "".join(parts).rstrip() + "\n"

    def prose(self, text, source):
        text = re.sub(r"(?m)^# ", "## ", text)
        text = LINK.sub(
            lambda m: f"{m.group(1)}[{m.group(2)}]({self.target(m.group(3), source)}{m.group(4)})",
            text,
        )
        return HTML_ATTR.sub(lambda m: f'{m.group(1)}="{self.target(m.group(2), source)}"', text)


def home_intro(repo, pages):
    walkthrough = pages["docs/payment-flow.md"]
    return (
        "**Open Institutional Custody** is a set of Rust components for institutional\n"
        "payment authorization and signing. Approvers review each payment independently,\n"
        "and signers check the bytes, rules, and receipts before they produce a signature.\n"
        "\n"
        f"New here? Run the [5-minute quickstart](https://github.com/{repo}#5-minute-quickstart),\n"
        f"then [{walkthrough.title.lower()}]({walkthrough.name}).\n"
        "\n"
    )


def sidebar(pages):
    guides = [s for s in GUIDE_ORDER if s in pages]
    guides += sorted(
        s for s in pages if s.startswith("docs/") and s not in GUIDE_ORDER and s != "docs/README.md"
    )
    lines = ["**[Home](Home)**", "", "**Guides**", ""]
    lines += [f"- [{pages[s].title}]({pages[s].name})" for s in guides]
    lines += ["", "**Reference**", "", f"- [Overview]({pages['openwiki/index.md'].name})"]
    top = sorted(s for s in pages if s.count("/") == 1 and s.startswith("openwiki/") and s != "openwiki/index.md")
    lines += [f"- [{pages[s].title}]({pages[s].name})" for s in top]
    for section in sorted({s.split("/")[1] for s in pages if s.startswith("openwiki/") and s.count("/") == 2}):
        index = f"openwiki/{section}/index.md"
        lines.append(f"- [{pages[index].title}]({pages[index].name})" if index in pages else f"- {section.capitalize()}")
        children = sorted(
            (s for s in pages if s.startswith(f"openwiki/{section}/") and s != index),
            key=lambda s: pages[s].title,
        )
        lines += [f"  - [{pages[s].title}]({pages[s].name})" for s in children]
    return "\n".join(lines) + "\n"


def footer(repo, commit):
    base = f"https://github.com/{repo}"
    return (
        f"Generated from [`docs/`]({base}/tree/{commit}/docs) and "
        f"[`openwiki/`]({base}/tree/{commit}/openwiki) at "
        f"[`{commit[:7]}`]({base}/commit/{commit}). Edit those files in the repository: "
        "each sync replaces the wiki pages.\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Build the GitHub wiki from docs/ and openwiki/.")
    parser.add_argument("--out", required=True, type=pathlib.Path, help="wiki checkout to write into")
    parser.add_argument("--commit", help="source commit for pinned links (default: HEAD)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/NAME on GitHub")
    args = parser.parse_args()

    out = args.out.resolve()
    # Every run deletes the *.md files in --out, so never point it at the sources.
    if out in {ROOT, ROOT / "docs", ROOT / "openwiki"}:
        raise SystemExit(f"--out must be a wiki checkout, not {out}")

    commit = args.commit or subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()

    pages = collect()
    rewriter = Rewriter(pages, args.repo, commit)
    rendered = {}
    for page in pages.values():
        body = rewriter.render(page)
        if page.description:
            body = f"_{page.description}_\n\n{body}"
        if page.name == "Home":
            body = home_intro(args.repo, pages) + body
        rendered[f"{page.name}.md"] = body
    if rewriter.errors:
        print("\n".join(rewriter.errors), file=sys.stderr)
        return 1
    rendered["_Sidebar.md"] = sidebar(pages)
    rendered["_Footer.md"] = footer(args.repo, commit)

    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.md"):
        old.unlink()
    for name, text in rendered.items():
        (out / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(rendered)} wiki pages to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
