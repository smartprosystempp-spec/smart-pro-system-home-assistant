# Managed Zero-Copy: MariaDB transaction invariant QA

**QA-only. No production/plugin installation, no real Managed credentials, no Portal or QA5 mutation.**

This harness runs against a **real MariaDB 11.4 InnoDB service** with four independent PHP mysqli worker processes. It covers the database invariants used in Broker 0.60.42's staged atomic-issuer design:

- All three tables must use InnoDB before START TRANSACTION.
- Installation-scoped MySQL GET_LOCK shared by candidate writers.
- SELECT ... FOR UPDATE of the one immutable approval ledger row.
- Zero preexisting nodes or pending manual pairings before creation.
- One candidate node INSERT, exact one-row conditional ledger UPDATE, single COMMIT.
- Rollback when a failure occurs between node INSERT and ledger UPDATE.
- Rollback on a **real SQL exception** raised by a MariaDB trigger.
- Lost-response retry returns no new node and leaves the original ciphertext unchanged.
- Rejection of duplicate approval by unique installation index.
- Fail closed if any table drifts to MyISAM.

**Scope qualification:** The PHP integration harness mirrors the critical SQL ordering and schema elements of Broker 0.60.42; it does **not** import the WordPress plugin or execute actual WPDB/Portal security gates. The full release still needs the real Broker source bound to a staging WordPress stack, a post-claim recipient authorization review and a coordinated QA5 test. A passing run is evidence for InnoDB/lock/rollback semantics, **not an end-to-end enrollment PASS**.

No user data is used; ID-00001 and generated nodes/credentials are synthetic. Credentials shown in the workflow exist solely in its temporary GitHub runner MariaDB service. The workflow does not deploy images or publish releases.