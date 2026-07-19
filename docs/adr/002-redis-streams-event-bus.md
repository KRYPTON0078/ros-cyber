# ADR-002: Redis Streams for Event Pipeline

## Status

Accepted

## Context

Detection requires near-real-time processing of telemetry, auth events, and policy violations from multiple services.

## Decision

Use **Redis Streams** (`XADD`/`XREAD`) as the event bus between producers (ingestion, policy) and consumer (detection worker).

## Alternatives Considered

- **Kafka:** Over-engineered for v0.1 lab scale
- **Direct DB polling:** Too slow, poor decoupling
- **MQTT only:** Good for IoT but less durable consumer groups

## Consequences

- Simple Docker setup (Redis already needed for caching)
- Consumer can replay from stream offset
- Upgrade path to Kafka in v0.2 documented
