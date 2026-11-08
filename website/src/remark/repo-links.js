// Remark plugin: relative links in ../docs that point at repository files
// outside docs/ (../SECURITY.md, ../integrations/x/README.md, source files)
// work on GitHub but not on the site. Rewrite them to the file on GitHub.

const path = require('path');

const DOCS_DIR = path.resolve(__dirname, '../../../docs');
const REPO_ROOT = path.resolve(DOCS_DIR, '..');
const BLOB = 'https://github.com/ardada2468/HaltSQL/blob/main/';
const TREE = 'https://github.com/ardada2468/HaltSQL/tree/main/';

function isRelative(url) {
  return url && !/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith('#') && !url.startsWith('/');
}

function rewrite(url, filePath) {
  const [target, hash = ''] = url.split('#');
  if (!target) return null;
  const abs = path.resolve(path.dirname(filePath), target);
  const insideDocs = abs === DOCS_DIR || abs.startsWith(DOCS_DIR + path.sep);
  if (insideDocs) {
    // Directory links inside docs (e.g. `adr/`) have no page on the site.
    if (target.endsWith('/')) return (abs === DOCS_DIR ? TREE + 'docs' : TREE + path.relative(REPO_ROOT, abs)) + (hash ? '#' + hash : '');
    // openapi.yaml is excluded from the site: link to GitHub.
    if (target.endsWith('.yaml') || target.endsWith('.yml') || target.endsWith('.json'))
      return BLOB + path.relative(REPO_ROOT, abs) + (hash ? '#' + hash : '');
    return null;
  }
  if (!abs.startsWith(REPO_ROOT + path.sep)) return null;
  const rel = path.relative(REPO_ROOT, abs).split(path.sep).join('/');
  const base = target.endsWith('/') ? TREE : BLOB;
  return base + rel + (hash ? '#' + hash : '');
}

function walk(node, fn) {
  fn(node);
  if (node.children) for (const c of node.children) walk(c, fn);
}

module.exports = function repoLinks() {
  return (tree, file) => {
    const filePath = file.path || (file.history && file.history[0]);
    if (!filePath) return;
    walk(tree, (node) => {
      if ((node.type === 'link' || node.type === 'definition') && isRelative(node.url)) {
        const out = rewrite(node.url, filePath);
        if (out) node.url = out;
      }
    });
  };
};
