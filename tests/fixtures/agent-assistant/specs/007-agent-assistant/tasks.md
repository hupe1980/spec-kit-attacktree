# Tasks: Agent Assistant

## Phase 1: Setup

- [x] T001 Create project structure per implementation plan
- [x] T002 Initialize Python project with FastAPI dependencies

## Phase 2: User Story 1 - Ask a question

- [x] T010 [US1] Implement retriever in src/retrieval/retriever.py
- [x] T011 [US1] [CR-001] Delimit retrieved documents as untrusted data in src/agent/prompt_builder.py
- [x] T012 [US1] [CR-001] Add prompt-injection regression test in tests/agent/test_prompt_injection.py
- [ ] T013 [US1] [CR-002] Filter retrieval by document visibility in src/retrieval/retriever.py
- [ ] T014 [US1] [CR-005] Add per-user rate limiting on POST /ask in src/api/routes.py

## Phase 3: User Story 2 - Open a ticket

- [x] T020 [US2] Implement ticket tool in src/agent/tools.py
- [x] T021 [US2] [CR-003] Require explicit single-use confirmation before the ticket tool executes
- [ ] T022 [US2] [CR-004] Bind sessions to short-lived, audience-scoped tokens in src/api/auth.py
