#!/usr/bin/env python3
"""Validate maintained documentation and render an immutable-linked public wiki."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAINTAINED = [
    'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'packaging/README.md',
    'docs/index.md', 'docs/ARCHITECTURE.md', 'docs/WIKI.md',
    'docs/REFERENCE.md', 'docs/CAPABILITIES.md', 'docs/THREAT-MODEL.md',
    'docs/attribution.md', 'docs/doctor.md', 'docs/INSIGHTS.md',
    'docs/PERFORMANCE.md', 'docs/DIAGNOSE.md', 'docs/diagnostic-coverage.md',
    'docs/runtime-lifecycle.md', 'docs/recovery-store.md', 'docs/resolver-adapter.md',
    'docs/observability-export.md', 'docs/PACKAGING.md', 'docs/wiki-maintenance.md',
]
BASE = 'https://github.com/matthart1983/netwatch'
LINK = re.compile(r'(?<!!)\[[^\]\n]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)')
WIKI = re.compile(r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True, stderr=subprocess.PIPE).strip()


def prose(text):
    # Fenced examples are not Markdown links or headings.
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^\s*(`{3,}|~{3,})', line)
        if match:
            token = match[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return '\n'.join(lines)


def anchors(text):
    found, counts = set(), {}
    for line in prose(text).splitlines():
        match = re.match(r'^#{1,6}\s+(.+?)(?:\s+#+)?$', line)
        if not match:
            continue
        title = re.sub(r'<[^>]+>', '', match[1]).lower()
        title = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', title)
        slug = ''.join(c for c in title if c.isalnum() or c in '_- ')
        slug = slug.replace(' ', '-')
        n = counts.get(slug, 0)
        counts[slug] = n + 1
        found.add(slug if n == 0 else f'{slug}-{n}')
    found.update(re.findall(r'(?:id|name)=["\']([^"\']+)', text))
    return found


INCLUDE = re.compile(r'^<!-- include: ([\w./-]+\.md)(?:#([\w-]+))? -->$', re.MULTILINE)


def expand_source(path):
    """Embed maintained sections, preserving examples and rebasing their links."""
    def include(match):
        name, section = match.groups()
        source = (ROOT / name).resolve()
        if name not in MAINTAINED or not source.is_relative_to(ROOT):
            raise ValueError(f'Include must name a maintained document: {name}')
        text = source.read_text()
        lines = text.splitlines(keepends=True)
        headings, counts, fence = [], {}, None
        for i, line in enumerate(lines):
            marker = re.match(r'^\s*(`{3,}|~{3,})', line)
            if marker:
                token = marker[1]
                if fence is None:
                    fence = token
                elif token[0] == fence[0] and len(token) >= len(fence):
                    fence = None
                continue
            heading = re.match(r'^(#{1,6})\s+', line) if fence is None else None
            if heading:
                slug = next(iter(anchors(line)))
                n = counts.get(slug, 0)
                counts[slug] = n + 1
                headings.append((i, len(heading[1]), slug if n == 0 else f'{slug}-{n}'))
        if section:
            selected = next((h for h in headings if h[2] == section), None)
            if selected is None:
                raise ValueError(f'Missing include section: {name}#{section}')
            start, level, _ = selected
            end = next((i for i, depth, _ in headings if i > start and depth <= level), len(lines))
        else:
            start, end, level = 0, len(lines), 1
        selected_headings = {i: depth for i, depth, _ in headings if start <= i < end}
        for i, depth in selected_headings.items():
            lines[i] = re.sub(r'^#{1,6}', '#' * min(6, depth + 2 - level), lines[i])
        text = ''.join(lines[start:end]).strip()
        def rebase(link):
            raw = link[1]
            url = urlsplit(raw)
            if url.scheme or url.netloc or raw.startswith('@repo@/'):
                return link[0]
            dest = (source.parent / unquote(url.path)).resolve() if url.path else source
            if not dest.is_relative_to(ROOT):
                raise ValueError(f'Included link escapes repository: {raw}')
            target = '@repo@/' + dest.relative_to(ROOT).as_posix()
            if url.fragment:
                target += '#' + url.fragment
            offset = link.start(1) - link.start()
            return link[0][:offset] + target + link[0][offset + len(raw):]
        text = LINK.sub(rebase, text)
        target = name + ('#' + section if section else '')
        return text + f'\n\n_Shared with the [maintained reference](@repo@/{target})._\n'
    return INCLUDE.sub(include, path.read_text())


def validate():
    manifest = json.loads((ROOT / 'docs/wiki-manifest.json').read_text())
    pages = manifest['pages']
    if len(pages) != len(set(pages)) or any(not re.fullmatch(r'[\w-]+', p) for p in pages):
        raise ValueError('Duplicate or invalid wiki slug')
    if set(pages) != {p.stem for p in (ROOT / 'docs/wiki').glob('*.md')}:
        raise ValueError('Wiki manifest and source inventory differ')
    if not re.fullmatch(r'v\d+\.\d+\.\d+', manifest['release']):
        raise ValueError('Invalid release baseline')
    if not re.fullmatch(r'[0-9a-f]{40}', manifest['release_commit']):
        raise ValueError('Release commit must be a full SHA')
    # Shallow PR checkouts need not contain tags; verify the binding when available.
    try:
        tagged = git('rev-parse', '--verify', f"refs/tags/{manifest['release']}^{{commit}}")
    except subprocess.CalledProcessError:
        tagged = None
    if tagged and tagged != manifest['release_commit']:
        raise ValueError('Release tag and manifest commit differ')
    errors = []
    files = MAINTAINED + [f'docs/wiki/{p}.md' for p in pages]
    for name in files:
        path = ROOT / name
        text = prose(expand_source(path))
        for match in WIKI.finditer(re.sub(r"`+[^`]*`+", "", text)):
            slug = (match[2] or match[1]).replace(' ', '-')
            if slug not in pages:
                errors.append(f'{name}: missing wiki page {slug}')
        for raw in LINK.findall(text):
            url = urlsplit(raw)
            if url.scheme or url.netloc:
                continue
            target = unquote(url.path)
            dest = ROOT / target[7:] if target.startswith('@repo@/') else path.parent / target if target else path
            dest = dest.resolve()
            if not dest.is_relative_to(ROOT):
                errors.append(f'{name}: link escapes repository: {raw}')
            elif not dest.exists():
                errors.append(f'{name}: missing target {raw}')
            elif url.fragment and dest.suffix == '.md' and unquote(url.fragment) not in anchors(dest.read_text()):
                errors.append(f'{name}: missing heading {raw}')
            elif url.fragment and dest.suffix != '.md' and re.fullmatch(r'L\d+(?:-L\d+)?', url.fragment):
                if int(url.fragment.split('-')[-1][1:]) > len(dest.read_text().splitlines()):
                    errors.append(f'{name}: source line out of range {raw}')
    if errors:
        raise ValueError('\n'.join(errors))
    return manifest, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--ref', default='HEAD', help='pushed documentation commit for immutable links')
    args = parser.parse_args()
    manifest, files = validate()
    if args.output:
        ref = git('rev-parse', '--verify', f'{args.ref}^{{commit}}')
        # A pinned link must describe the exact source being rendered.
        for name in files + ['docs/wiki-manifest.json', 'scripts/wiki.py']:
            committed = subprocess.check_output(['git', '-C', str(ROOT), 'show', f'{ref}:{name}'])
            if committed != (ROOT / name).read_bytes():
                raise ValueError(f'{name} differs from {ref}; commit sources before rendering')
        args.output.mkdir(parents=True, exist_ok=False)
        for page in manifest['pages']:
            text = expand_source(ROOT / f'docs/wiki/{page}.md')
            title, _, body = text.partition('\n')
            header = (f"> Release baseline: [{manifest['release']}]({BASE}/releases/tag/{manifest['release']}). "
                      f"Reviewed {manifest['reviewed']}. "
                      f"[Page source]({BASE}/blob/{ref}/docs/wiki/{page}.md). "
                      "Development-only behavior is labeled unreleased.\n")
            text = title + '\n\n' + header + body
            text = text.replace('@repo@', f'{BASE}/blob/{ref}')
            (args.output / f'{page}.md').write_text(text.rstrip() + '\n')
        print(f'Rendered {len(manifest["pages"])} pages into {args.output}')
    print(f'Validated {len(files)} maintained documents and {len(manifest["pages"])} wiki pages')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f'documentation check failed: {exc}', file=sys.stderr)
        sys.exit(1)
