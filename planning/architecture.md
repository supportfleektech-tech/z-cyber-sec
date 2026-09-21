# Architecture Summary

See `docs/02-architecture.md`, `docs/03-network-design.md`, and `docs/04-data-model.md`.

Start as a modular monolith with clear internal boundaries unless measured scale or team ownership justifies service extraction. Avoid premature microservices on a resource-constrained laptop. Keep adapters replaceable and external tool calls asynchronous where appropriate.
