# HaltSQL docs site

The [Docusaurus](https://docusaurus.io/) site published to GitHub Pages at
<https://haltsql.github.io/HaltSQL/>.

The pages themselves are the Markdown files in [`../docs`](../docs): this folder
holds only the site shell (config, sidebar, landing page, styles). Edit a doc in
`docs/` and it changes both on GitHub and on the site.

```bash
cd website
npm ci
npm start          # live preview at http://localhost:3000/HaltSQL/
npm run build      # static site in website/build
```

- `docusaurus.config.js`: site config. Docs are read from `../docs` as plain
  CommonMark (`markdown.format: detect`), so `.md` files must not use MDX/JSX.
  Diagrams are ` ```mermaid ` code blocks.
- `sidebars.js`: the sidebar. Add new pages here.
- `src/pages/index.js`: the landing page.
- `src/remark/repo-links.js`: rewrites links from `docs/` to repository files
  outside `docs/` (for example `../SECURITY.md`) into GitHub URLs.

`.github/workflows/pages.yml` builds the site on pull requests and deploys it on
pushes to `main`. GitHub Pages must be enabled with source "GitHub Actions"
(Settings, Pages).
