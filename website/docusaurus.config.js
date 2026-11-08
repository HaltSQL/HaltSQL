// @ts-check
// HaltSQL documentation site (Docusaurus). The Markdown lives in ../docs so the
// repository docs and the site never drift; this folder only holds the site
// shell (config, sidebar, landing page, styles).

import { themes as prismThemes } from 'prism-react-renderer';
import repoLinks from './src/remark/repo-links.js';

const repo = 'https://github.com/ardada2468/HaltSQL';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'HaltSQL',
  tagline: 'A policy firewall for LLM-generated PostgreSQL',
  favicon: 'img/favicon.svg',

  url: 'https://ardada2468.github.io',
  baseUrl: '/HaltSQL/',
  organizationName: 'ardada2468',
  projectName: 'HaltSQL',
  trailingSlash: false,

  // The docs folder is also read on GitHub, where some links point at repository
  // files outside docs/ (CONTRIBUTING.md, source files). Report, don't fail.
  onBrokenLinks: 'warn',

  i18n: { defaultLocale: 'en', locales: ['en'] },

  markdown: {
    // .md files are plain CommonMark (they must keep rendering on GitHub);
    // .mdx files get MDX.
    format: 'detect',
    mermaid: true,
    hooks: { onBrokenMarkdownLinks: 'warn' },
  },
  themes: ['@docusaurus/theme-mermaid'],
  clientModules: ['./src/clientModules/d3-transition.js'],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.js',
          // docPath is relative to ../docs
          editUrl: ({ docPath }) => `${repo}/edit/main/docs/${docPath}`,
          beforeDefaultRemarkPlugins: [repoLinks],
          exclude: ['**/openapi.yaml', 'adr/template.md'],
        },
        blog: false,
        theme: { customCss: './src/css/custom.css' },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: { respectPrefersColorScheme: true },
      announcementBar: {
        id: 'v0-1',
        content:
          'HaltSQL 0.1 is pre-1.0: the verdict format and reason codes are stable, everything else may still change.',
        isCloseable: true,
      },
      navbar: {
        title: 'HaltSQL',
        logo: { alt: 'HaltSQL', src: 'img/logo.svg' },
        items: [
          { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
          { to: '/docs/how-it-works/architecture', label: 'How it works', position: 'left' },
          { to: '/docs/integrations', label: 'Integrations', position: 'left' },
          { to: '/docs/policy-reference', label: 'Reference', position: 'left' },
          { href: `${repo}/blob/main/CHANGELOG.md`, label: 'Changelog', position: 'left' },
          { href: repo, label: 'GitHub', position: 'right' },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Learn',
            items: [
              { label: 'Quickstart', to: '/docs/quickstart' },
              { label: 'How it works', to: '/docs/how-it-works/architecture' },
              { label: 'Tenancy semantics', to: '/docs/tenancy' },
            ],
          },
          {
            title: 'Run it',
            items: [
              { label: 'Deployment', to: '/docs/deployment' },
              { label: 'haltsql-proxy', to: '/docs/proxy' },
              { label: 'Policy bundles', to: '/docs/policy-bundles' },
            ],
          },
          {
            title: 'Reference',
            items: [
              { label: 'Policy reference', to: '/docs/policy-reference' },
              { label: 'Reason codes', to: '/docs/reason-codes' },
              { label: 'HTTP API', to: '/docs/http-api' },
            ],
          },
          {
            title: 'Project',
            items: [
              { label: 'GitHub', href: repo },
              { label: 'Security policy', href: `${repo}/blob/main/SECURITY.md` },
              { label: 'Contributing', href: `${repo}/blob/main/CONTRIBUTING.md` },
            ],
          },
        ],
        copyright: `HaltSQL is licensed under MIT. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'json', 'yaml', 'sql', 'ocaml', 'python', 'go', 'java'],
      },
      mermaid: { theme: { light: 'neutral', dark: 'dark' } },
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 4 },
    }),
};

export default config;
