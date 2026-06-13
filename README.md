BugBountyScout

BugBountyScout is a local-first, modular CLI workbench for authorized web bug bounty testing. It helps security researchers stay in scope, analyze passive traffic, map frontend/API attack surface, identify exposed secrets and risky client-side patterns, organize authorization testing, preserve evidence, redact sensitive data, and generate clean report-ready findings.

The project is designed around a disciplined bug bounty workflow:

Scope → Capture → Analyze → Map → Triage → Evidence → Report

It is not an exploit runner, mass scanner, WAF bypass tool, or credential validation tool. The goal is to improve testing quality, reduce noise, prevent out-of-scope mistakes, and produce stronger bug bounty reports.

Core modules include:

ScopeGuard — stores program scope and blocks out-of-scope targets.
HAR Analyzer — analyzes HAR files for secrets, auth material, endpoints, cookies, headers, and third-party leakage.
Live JS Secret Scanner — scans frontend JavaScript, HTML, runtime config, and source maps for exposed secrets and sensitive configuration.
Source Map Hunter — analyzes exposed source maps for routes, comments, API clients, and sensitive source disclosure.
SPA Endpoint Mapper — extracts API endpoints, parameters, routes, object IDs, and GraphQL paths from frontend assets.
Passive API Mapper — creates API documentation and testing checklists from observed traffic.
ParamForge — builds target-specific parameter and wordlists from passive data.
JWT Risk Inspector — decodes and analyzes JWTs locally for claim, lifetime, scope, and role risks.
Header/Cookie Auditor — checks security headers, CSP, cookies, and cache policy.
CORS Auditor — analyzes CORS headers and helps avoid false-positive CORS reports.
GraphQL Risk Mapper — maps GraphQL operations, mutations, fields, variables, and authorization-relevant risks.
Client Storage Auditor — identifies sensitive data stored in browser-accessible storage.
Debug Leak Analyzer — detects stack traces, internal paths, debug flags, framework errors, and verbose API errors.
Source Sink Mapper — identifies client-side sources and dangerous sinks for manual DOM review.
PostMessage Analyzer — reviews postMessage usage, origin checks, and risky message handlers.
IDOR/BOLA Matrix — organizes manual authorization testing across users, roles, objects, and endpoints.
Evidence Locker — stores request/response proof, screenshots, notes, hashes, and reproduction steps.
ReportForge — generates professional Markdown/HTML bug bounty reports with redaction and quality checks.

The project should be CLI-first, passive-first, scope-aware, redacted-by-default, and report-focused.
