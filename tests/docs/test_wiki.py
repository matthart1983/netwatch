"""Regression checks for real documentation failure modes; no network access."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('wiki', Path(__file__).resolve().parents[2] / 'scripts/wiki.py')
wiki = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wiki)


class DocumentationChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'docs/wiki').mkdir(parents=True)
        (self.root / 'docs/wiki-manifest.json').write_text(json.dumps({
            'release': 'v0.39.0', 'release_commit': 'a' * 40,
            'reviewed': '2026-11-01', 'pages': ['Home', 'Some-Page']}))
        (self.root / 'docs/wiki/Home.md').write_text('# Home\n\n[[Some Page]]\n')
        (self.root / 'docs/wiki/Some-Page.md').write_text('# Some page\n')
        (self.root / 'reference.md').write_text('# Reference\n\n## CLI `--help`\n\n## CLI `--help`\n')
        for name, value in [('ROOT', self.root), ('MAINTAINED', ['reference.md'])]:
            p = patch.object(wiki, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(wiki, 'git', return_value='a' * 40)
        p.start()
        self.addCleanup(p.stop)

    def test_wiki_spaces_and_duplicate_heading_slugs(self):
        (self.root / 'docs/wiki/Some-Page.md').write_text(
            '# Page\n\n[help](@repo@/reference.md#cli---help-1)\n')
        wiki.validate()

    def test_broken_file_and_heading_are_reported(self):
        (self.root / 'docs/wiki/Home.md').write_text(
            '# Home\n\n[bad](@repo@/missing.md)\n[bad](@repo@/reference.md#missing)\n')
        with self.assertRaises(ValueError) as error:
            wiki.validate()
        self.assertIn('missing target', str(error.exception))
        self.assertIn('missing heading', str(error.exception))

    def test_missing_wiki_page_is_reported(self):
        (self.root / 'docs/wiki/Home.md').write_text('# Home\n\n[[Missing Page]]\n')
        with self.assertRaisesRegex(ValueError, 'missing wiki page Missing-Page'):
            wiki.validate()

    def test_examples_are_not_links(self):
        (self.root / 'docs/wiki/Home.md').write_text(
            '# Home\n\n`[[diagnose_targets]]`\n\n```md\n[[Missing]]\n[bad](missing.md)\n```\n')
        wiki.validate()

    def test_manifest_cannot_silently_drop_existing_page(self):
        (self.root / 'docs/wiki/Unlisted.md').write_text('# Unlisted\n')
        with self.assertRaisesRegex(ValueError, 'inventory differ'):
            wiki.validate()

    def test_include_section_preserves_code_and_rebases_link_target_only(self):
        (self.root / 'reference.md').write_text(
            '# Reference\n\n## Setup\n\n[reference.md](reference.md#setup)\n'
            '```sh\n## Not a section\necho example\n```\n'
            '### Detail\nkeep this\n## Next\ndo not include\n')
        page = self.root / 'docs/wiki/Home.md'
        page.write_text('# Home\n\n<!-- include: reference.md#setup -->\n')
        expanded = wiki.expand_source(page)
        self.assertIn('[reference.md](@repo@/reference.md#setup)', expanded)
        self.assertIn('## Not a section\necho example', expanded)
        self.assertIn('### Detail\nkeep this', expanded)
        self.assertNotIn('do not include', expanded)
        wiki.validate()

    def test_include_missing_section_fails(self):
        (self.root / 'docs/wiki/Home.md').write_text(
            '# Home\n\n<!-- include: reference.md#missing -->\n')
        with self.assertRaisesRegex(ValueError, 'Missing include section'):
            wiki.validate()

    def test_include_requires_maintained_source(self):
        (self.root / 'docs/wiki/Home.md').write_text(
            '# Home\n\n<!-- include: ../outside.md -->\n')
        with self.assertRaisesRegex(ValueError, 'maintained document'):
            wiki.validate()

    def test_include_nested_heading_is_promoted(self):
        (self.root / 'reference.md').write_text(
            '# Reference\n## Parent\n### Child\ntext\n#### Nested\nmore\n')
        page = self.root / 'docs/wiki/Home.md'
        page.write_text('# Home\n\n<!-- include: reference.md#child -->\n')
        expanded = wiki.expand_source(page)
        self.assertIn('## Child\n', expanded)
        self.assertIn('### Nested\n', expanded)
        self.assertNotIn('## Parent', expanded)


    def test_release_tag_mismatch_is_reported(self):
        with patch.object(wiki, 'git', return_value='b' * 40):
            with self.assertRaisesRegex(ValueError, 'tag and manifest commit differ'):
                wiki.validate()


if __name__ == '__main__':
    unittest.main()
