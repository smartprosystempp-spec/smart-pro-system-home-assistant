SMART PRO ACCESS PREFLIGHT QA 0.2.0 -- GITHUB CHANGED FILES ZIP
===============================================================
THIS IS NOT A COMPLETE REPOSITORY OR DIRECT HOME ASSISTANT INSTALL ZIP.
Extract first. Upload/replace the contents preserving paths in the current
Smart Pro System GitHub repo. Update ONLY the QA add-on and listed QA files.

IMPORTANT: stage 0.2.0 explicitly enables homeassistant_api=true for the
ISOLATED QA ADD-ON. This permits read-only authentication/role validation over
Core WebSocket; the QA code has NO create/delete/update account API commands.
Never install this temporary QA addon on production systems.

LIVE TEST: Smart Pro Access Preflight - QA from 0.1.0 to 0.2.0, then Open Web UI
as the administrator. Expect 'verified by Core' or a fail-closed code. Do not
modify user accounts. Check normal user smartpro_qa_user is denied afterwards.
Keep the QA user for future tests; DO NOT store or share password.

Production Smart Pro System 3.0.28, Managed Support 3.19.2 and Tunnel unchanged.
Full instructions: smart-pro-access-preflight/README.md
