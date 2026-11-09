// @ts-check
// Sidebar for the docs site. Doc ids are file paths under ../docs without the
// extension. Labels are set here so long page titles stay readable in the nav.

const doc = (id, label) => ({ type: 'doc', id, label });

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    {
      type: 'category',
      label: 'Get started',
      collapsed: false,
      items: [
        doc('index', 'Overview'),
        doc('quickstart', 'Quickstart'),
        doc('mcp', 'Replace server-postgres (MCP)'),
        doc('faq', 'FAQ'),
        doc('glossary', 'Glossary'),
      ],
    },
    {
      type: 'category',
      label: 'Tutorials',
      collapsed: false,
      items: [
        doc('tutorials/secure-an-mcp-agent', 'Secure an MCP agent'),
        doc('tutorials/multi-tenant-analytics-agent', 'Multi-tenant analytics agent'),
        doc('tutorials/roll-out-a-policy-safely', 'Roll out a policy safely'),
      ],
    },
    {
      type: 'category',
      label: 'Integrations',
      link: { type: 'doc', id: 'integrations' },
      items: [
        doc('integrations/mcp-clients', 'MCP clients'),
        {
          type: 'category',
          label: 'Agent frameworks',
          link: { type: 'doc', id: 'agent-frameworks' },
          items: [
            doc('integrations/langchain', 'LangChain'),
            doc('integrations/langgraph', 'LangGraph'),
            doc('integrations/openai-agents', 'OpenAI Agents SDK'),
            doc('integrations/google-adk', 'Google ADK'),
            doc('integrations/llamaindex', 'LlamaIndex'),
            doc('integrations/crewai', 'CrewAI'),
            doc('integrations/semantic-kernel', 'Semantic Kernel'),
            doc('integrations/vanna', 'Vanna'),
          ],
        },
        {
          type: 'category',
          label: 'SDKs',
          items: [
            doc('sdk-python', 'Python'),
            doc('sdk-typescript', 'TypeScript'),
            doc('sdk-go', 'Go'),
            doc('sdk-java', 'Java'),
          ],
        },
        doc('integrations/data-catalogs', 'Data catalogs'),
        doc('integrations/identity-providers', 'Identity providers'),
        doc('integrations/secrets-managers', 'Secrets managers'),
        doc('integrations/audit-and-observability', 'Audit and observability'),
      ],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        doc('cli', 'CLI'),
        doc('http-api', 'HTTP API (sidecar)'),
        doc('proxy', 'Wire proxy'),
        doc('policy-bundles', 'Signed policy bundles'),
        doc('policy-ci', 'Policy CI'),
        doc('shadow-reports', 'Shadow mode reports'),
        doc('opa', 'Open Policy Agent'),
        doc('rls-generation', 'RLS generation'),
        doc('schema-and-pii', 'Schema and PII import'),
      ],
    },
    {
      type: 'category',
      label: 'Deploy',
      items: [
        doc('deployment', 'Deployment overview'),
        doc('deploy-aws', 'AWS'),
        doc('deploy-gcp', 'Google Cloud'),
        doc('deploy-azure', 'Azure'),
        doc('kubernetes-operator', 'Kubernetes operator'),
        doc('terraform', 'Terraform'),
      ],
    },
    {
      type: 'category',
      label: 'Operate',
      items: [
        doc('operations/production-checklist', 'Production checklist'),
        doc('operations/high-availability', 'High availability and scaling'),
        doc('operations/upgrades', 'Versioning and upgrades'),
        doc('operations/troubleshooting', 'Troubleshooting'),
        doc('operations/runbooks', 'Runbooks'),
        doc('authentication', 'Authentication and TLS'),
        doc('secrets', 'Secrets'),
        doc('audit-sinks', 'Audit sinks'),
        doc('audit-verify', 'Verifying audit chains'),
        doc('observability', 'Observability'),
        doc('performance', 'Performance'),
        doc('compatibility', 'Database compatibility'),
      ],
    },
    {
      type: 'category',
      label: 'Security and compliance',
      items: [
        doc('security/overview', 'Security overview'),
        doc('security/hardening', 'Hardening guide'),
        doc('security/compliance', 'Compliance mapping'),
        doc('security/supply-chain', 'Supply chain and releases'),
        doc('security/security-questionnaire', 'Security questionnaire'),
        doc('threat-model', 'Threat model'),
        doc('defense-in-depth', 'Defense in depth'),
        doc('testing', 'Testing and assurance'),
      ],
    },
    {
      type: 'category',
      label: 'How it works',
      link: { type: 'doc', id: 'how-it-works/architecture' },
      items: [
        'how-it-works/architecture',
        'how-it-works/verification-pipeline',
        'how-it-works/parser',
        'how-it-works/analyzer',
        'how-it-works/tenancy-proof',
        'how-it-works/policies-and-config',
        'how-it-works/deployment-modes',
        'how-it-works/proxy-internals',
        'how-it-works/server-internals',
        'how-it-works/policy-lifecycle',
        'how-it-works/assurance',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        doc('policy-reference', 'Policy reference'),
        doc('config-reference', 'Config reference'),
        doc('verdict', 'Verdict format'),
        doc('reason-codes', 'Reason codes'),
        doc('tenancy', 'Tenancy semantics'),
      ],
    },
    {
      type: 'category',
      label: 'Design decisions (ADRs)',
      items: [{ type: 'autogenerated', dirName: 'adr' }],
    },
  ],
};

export default sidebars;
