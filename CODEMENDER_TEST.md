# CodeMender Automated PR Security Scan Validation

This pull request validates the automated CodeMender security vulnerability scan pipeline:
- **Trigger**: GitHub Actions `pull_request` event (`opened`, `synchronize`, `reopened`)
- **Authentication**: GCP Workload Identity Federation (WIF) OIDC token exchange
- **Orchestration**: Cloud Run Job `codemender-pr-runner` (`us-central1`)
- **Analysis**: Sequential `cm init` & `cm find .` vulnerability scan via Vertex AI
- **Deliverables**: GCS report upload and automated PR markdown comment via GitHub App
