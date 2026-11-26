# DataLineage AI — Design Partner Pilot Runbook

## Pilot objective
Validate whether engineering teams can use DataLineage AI to understand SQL dependencies, assess schema/SQL changes and review downstream impact in their development workflow.

## Recommended pilot scope
- Start with 1–3 software/data engineering teams.
- Use synthetic, anonymized or explicitly approved non-sensitive SQL and schema samples.
- Keep the pilot time-boxed (for example, two weeks).
- Do not promise complete lineage for unsupported SQL dialects or dynamic SQL.

## Onboarding
1. Identify the team's SQL dialects, repositories and current review workflow.
2. Agree what data may be uploaded and how long it may be retained.
3. Create named test users and assign least-privilege roles.
4. Walk through SQL upload, lineage, schema comparison and PR impact analysis.
5. Record baseline review time and current failure modes.

## Success measures
- Time required to understand downstream impact.
- Percentage of expected dependencies found on a curated test set.
- False positives and missed dependencies reported by engineers.
- Usefulness of risk explanations and review comments.
- Setup friction and weekly active pilot users.

## Feedback cadence
- Collect issues after first use.
- Hold a short weekly review with each pilot team.
- Prioritize correctness and explainability over adding more integrations.
- Close the pilot with a written continue / revise / stop decision.

## Support boundaries
Document response times, supported dialects, known limitations, data handling and rollback steps before onboarding. Do not use real customer production data until security, privacy and operational controls have been reviewed.
