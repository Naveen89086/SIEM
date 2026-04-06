# Database Content Overview

## Tables
- security_logs
- sqlite_sequence
- events
- packets
- incidents
- risk_history
- security_events
- raw_packets

## Table: security_logs
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| src_ip | TEXT |
| dst_ip | TEXT |
| protocol | TEXT |
| port | TEXT |
| alert_type | TEXT |
| severity | TEXT |
| description | TEXT |
| details | TEXT |

### Sample Data (Last 5 records)
| id | timestamp | src_ip | dst_ip | protocol | port | alert_type | severity | description | details |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 25 | 1775124637.8481286 | 20.72.205.209 | 10.71.149.209 |  |  | RATE_LIMIT | HIGH | High packet rate from 20.72.205.209 → 10.71.149.209 (500 pkts/10s) | {"src_ip": "20.72.205.209", "dst_ip": "10.71.149.209", "count": 500, "enrichment": {"risk_score":... |
| 24 | 1775124139.9284146 | 10.71.149.24 |  |  |  | PORT_SCAN | MEDIUM | Port Scan detected from 10.71.149.24 (15 unique ports probed) | {"src_ip": "10.71.149.24", "ports_scanned": 15, "enrichment": {"risk_score": 45.17, "confidence":... |
| 23 | 1775124132.7239895 | 10.71.149.209 |  |  |  | DNS_TUNNEL | HIGH | Possible DNS Tunneling from 10.71.149.209 (avg payload 84B, 15 queries) | {"src_ip": "10.71.149.209", "avg_size": 84.06666666666666, "query_count": 15, "enrichment": {"ris... |
| 22 | 1775124124.405183 | 10.71.149.209 | 216.239.32.223 |  |  | RATE_LIMIT | HIGH | High packet rate from 10.71.149.209 → 216.239.32.223 (500 pkts/10s) | {"src_ip": "10.71.149.209", "dst_ip": "216.239.32.223", "count": 500, "enrichment": {"risk_score"... |
| 21 | 1775123573.4584112 | 10.71.149.24 |  |  |  | PORT_SCAN | MEDIUM | Port Scan detected from 10.71.149.24 (15 unique ports probed) | {"src_ip": "10.71.149.24", "ports_scanned": 15, "enrichment": {"risk_score": 7.65, "confidence": ... |

## Table: sqlite_sequence
### Schema
| Column | Type |
| --- | --- |
| name |  |
| seq |  |

### Sample Data (Last 5 records)
| name | seq |
| --- | --- |
| raw_packets | 5300 |
| incidents | 6 |
| security_logs | 25 |
| events | 25 |
| risk_history | 523 |

## Table: events
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| timestamp_str | TEXT |
| event_type | TEXT |
| severity | TEXT |
| message | TEXT |
| details | TEXT |
| mitre_id | TEXT |
| mitre_tactic | TEXT |
| confidence | REAL |
| src_ip | TEXT |
| dst_ip | TEXT |
| acknowledged | INTEGER |

### Sample Data (Last 5 records)
| id | timestamp | timestamp_str | event_type | severity | message | details | mitre_id | mitre_tactic | confidence | src_ip | dst_ip | acknowledged |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 25 | 1775124637.8481286 | 2026-04-02 15:40:37 | RATE_LIMIT | HIGH | High packet rate from 20.72.205.209 → 10.71.149.209 (500 pkts/10s) | {"src_ip": "20.72.205.209", "dst_ip": "10.71.149.209", "count": 500, "enrichment": {"risk_score":... | T1498 | Impact | 0.8 | 20.72.205.209 | 10.71.149.209 | 0 |
| 24 | 1775124139.9284146 | 2026-04-02 15:32:19 | PORT_SCAN | MEDIUM | Port Scan detected from 10.71.149.24 (15 unique ports probed) | {"src_ip": "10.71.149.24", "ports_scanned": 15, "enrichment": {"risk_score": 45.17, "confidence":... | T1046 | Discovery | 0.8 | 10.71.149.24 |  | 0 |
| 23 | 1775124132.7239895 | 2026-04-02 15:32:12 | DNS_TUNNEL | HIGH | Possible DNS Tunneling from 10.71.149.209 (avg payload 84B, 15 queries) | {"src_ip": "10.71.149.209", "avg_size": 84.06666666666666, "query_count": 15, "enrichment": {"ris... | T1071.004 | Command and Control | 0.8 | 10.71.149.209 |  | 0 |
| 22 | 1775124124.405183 | 2026-04-02 15:32:04 | RATE_LIMIT | HIGH | High packet rate from 10.71.149.209 → 216.239.32.223 (500 pkts/10s) | {"src_ip": "10.71.149.209", "dst_ip": "216.239.32.223", "count": 500, "enrichment": {"risk_score"... | T1498 | Impact | 0.8 | 10.71.149.209 | 216.239.32.223 | 0 |
| 21 | 1775123573.4584112 | 2026-04-02 15:22:53 | PORT_SCAN | MEDIUM | Port Scan detected from 10.71.149.24 (15 unique ports probed) | {"src_ip": "10.71.149.24", "ports_scanned": 15, "enrichment": {"risk_score": 7.65, "confidence": ... | T1046 | Discovery | 0.8 | 10.71.149.24 |  | 0 |

## Table: packets
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| src_ip | TEXT |
| dst_ip | TEXT |
| protocol | TEXT |
| src_port | TEXT |
| dst_port | TEXT |
| length | INTEGER |
| flags | TEXT |
| is_threat | INTEGER |
| threat_msg | TEXT |
| dns_query | TEXT |
| http_host | TEXT |
| tls_sni | TEXT |

### Sample Data (Last 5 records)
| id | timestamp | src_ip | dst_ip | protocol | src_port | dst_port | length | flags | is_threat | threat_msg | dns_query | http_host | tls_sni |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 454153 | 1775124828.6259217 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 454152 | 1775124828.624615 |  |  | PROTO- |  |  | 1329 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 454151 | 1775124828.6233544 |  |  | PROTO- |  |  | 1329 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 454150 | 1775124828.622057 |  |  | PROTO- |  |  | 86 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 454149 | 1775124828.6207201 |  |  | PROTO- |  |  | 148 | 0x0018 | 1 | Missing IP addresses |  |  |  |

## Table: incidents
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| created_at | REAL |
| updated_at | REAL |
| title | TEXT |
| severity | TEXT |
| status | TEXT |
| assigned_to | TEXT |
| event_ids | TEXT |
| notes | TEXT |
| src_ip | TEXT |
| kill_chain_phase | TEXT |

### Sample Data (Last 5 records)
| id | created_at | updated_at | title | severity | status | assigned_to | event_ids | notes | src_ip | kill_chain_phase |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 6 | 1775124137.8364375 | 1775124137.8364375 | Multi-Stage Attack from 10.71.149.209: Command & Control → Impact | CRITICAL | OPEN |  | [22, 23] | [] | 10.71.149.209 | Command & Control → Impact |
| 5 | 1775123573.4118767 | 1775123573.4118767 | Multi-Stage Attack from 10.71.149.209: Command & Control → Impact | CRITICAL | OPEN |  | [19, 20] | [] | 10.71.149.209 | Command & Control → Impact |
| 4 | 1774695173.4950364 | 1774695173.4950364 | Multi-Stage Attack from 172.18.195.209: Command & Control → Impact | CRITICAL | OPEN |  | [12, 14, 17] | [] | 172.18.195.209 | Command & Control → Impact |
| 3 | 1774694987.7977283 | 1774694987.7977283 | Multi-Stage Attack from 172.18.195.209: Command & Control → Impact | CRITICAL | OPEN |  | [12, 14] | [] | 172.18.195.209 | Command & Control → Impact |
| 2 | 1774010108.0026848 | 1774010108.0026848 | Multi-Stage Attack from 10.147.42.209: Command & Control → Impact | CRITICAL | OPEN |  | [1, 4, 5] | [] | 10.147.42.209 | Command & Control → Impact |

## Table: risk_history
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| risk_score | REAL |

### Sample Data (Last 5 records)
| id | timestamp | risk_score |
| --- | --- | --- |
| 523 | 1775124846.7337294 | 0.0 |
| 522 | 1775124826.4534242 | 3.2694950970327428 |
| 521 | 1775124816.4169376 | 3.4415737863502556 |
| 520 | 1775124806.3985171 | 3.622709248789743 |
| 519 | 1775124796.3937416 | 3.8133781566207823 |

## Table: security_events
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| src_ip | TEXT |
| dst_ip | TEXT |
| protocol | TEXT |
| src_port | INTEGER |
| dst_port | INTEGER |
| alert_type | TEXT |
| severity | TEXT |
| message | TEXT |
| details | TEXT |
| mitre_id | TEXT |
| mitre_tactic | TEXT |
| log_hash | TEXT |

### Sample Data (Last 5 records)
*No data found in this table.*

## Table: raw_packets
### Schema
| Column | Type |
| --- | --- |
| id | INTEGER |
| timestamp | REAL |
| src_ip | TEXT |
| dst_ip | TEXT |
| protocol | TEXT |
| src_port | TEXT |
| dst_port | TEXT |
| length | INTEGER |
| flags | TEXT |
| is_threat | INTEGER |
| threat_msg | TEXT |
| dns_query | TEXT |
| http_host | TEXT |
| tls_sni | TEXT |

### Sample Data (Last 5 records)
| id | timestamp | src_ip | dst_ip | protocol | src_port | dst_port | length | flags | is_threat | threat_msg | dns_query | http_host | tls_sni |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 5300 | 1775124852.4218493 |  |  | PROTO- |  |  | 816 |  | 1 | Missing IP addresses |  |  |  |
| 5299 | 1775124852.4218478 |  |  | PROTO- |  |  | 1292 |  | 1 | Missing IP addresses |  |  |  |
| 5298 | 1775124852.4218466 |  |  | PROTO- |  |  | 1292 |  | 1 | Missing IP addresses |  |  |  |
| 5297 | 1775124852.421845 |  |  | PROTO- |  |  | 1329 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 5296 | 1775124852.4218435 |  |  | PROTO- |  |  | 1329 | 0x0010 | 1 | Missing IP addresses |  |  |  |
