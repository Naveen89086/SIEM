# Database Content Overview

## Tables
- events
- sqlite_sequence
- packets
- incidents
- risk_history
- security_logs

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
| 1160 | 1773379812.1034515 | 2026-03-13 11:00:12 | RATE_LIMIT | HIGH | High packet rate from 10.147.42.143 → 10.147.42.209 (20 pkts/60s) | {"src_ip": "10.147.42.143", "dst_ip": "10.147.42.209", "count": 20, "enrichment": {"risk_score": ... | T1498 | Impact | 0.8 | 10.147.42.143 | 10.147.42.209 | 0 |
| 1159 | 1773379681.1978858 | 2026-03-13 10:58:01 | RATE_LIMIT | HIGH | High packet rate from 0.0.0.0 → 255.255.255.255 (20 pkts/60s) | {"src_ip": "0.0.0.0", "dst_ip": "255.255.255.255", "count": 20, "enrichment": {"risk_score": 7.95... | T1498 | Impact | 0.8 | 0.0.0.0 | 255.255.255.255 | 0 |
| 1158 | 1773379669.1170974 | 2026-03-13 10:57:49 | RATE_LIMIT | HIGH | High packet rate from 10.149.119.209 → 10.149.119.255 (20 pkts/60s) | {"src_ip": "10.149.119.209", "dst_ip": "10.149.119.255", "count": 20, "enrichment": {"risk_score"... | T1498 | Impact | 0.8 | 10.149.119.209 | 10.149.119.255 | 0 |
| 1157 | 1773378864.494883 | 2026-03-13 10:44:24 | PORT_SCAN | MEDIUM | Port Scan detected from 10.147.42.209 (5 unique ports probed) | {"src_ip": "10.147.42.209", "ports_scanned": 5, "enrichment": {"risk_score": 7.8, "confidence": 8... | T1046 | Discovery | 0.8 | 10.147.42.209 |  | 0 |
| 1156 | 1773378828.0419426 | 2026-03-13 10:43:48 | PORT_SCAN | MEDIUM | Port Scan detected from 10.147.42.143 (5 unique ports probed) | {"src_ip": "10.147.42.143", "ports_scanned": 5, "enrichment": {"risk_score": 11.83, "confidence":... | T1046 | Discovery | 0.8 | 10.147.42.143 |  | 0 |

## Table: sqlite_sequence
### Schema
| Column | Type |
| --- | --- |
| name |  |
| seq |  |

### Sample Data (Last 5 records)
| name | seq |
| --- | --- |
| security_logs | 1160 |
| risk_history | 784 |
| incidents | 296 |
| events | 1160 |
| packets | 2296908 |

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
| 2296908 | 1773379848.434977 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 2296907 | 1773379848.4346588 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 2296906 | 1773379848.4343455 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 2296905 | 1773379848.4340289 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |
| 2296904 | 1773379848.433701 |  |  | PROTO- |  |  | 74 | 0x0010 | 1 | Missing IP addresses |  |  |  |

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
| 296 | 1773379812.1413488 | 1773379812.1413488 | Multi-Stage Attack from 10.147.42.143: Reconnaissance → Impact | CRITICAL | OPEN |  | [1156, 1160] | [] | 10.147.42.143 | Reconnaissance → Impact |
| 295 | 1773378864.5461261 | 1773378864.5461261 | Multi-Stage Attack from 10.147.42.209: Reconnaissance → Impact | CRITICAL | OPEN |  | [1155, 1157] | [] | 10.147.42.209 | Reconnaissance → Impact |
| 294 | 1773334855.950776 | 1773334873.987398 | [CRITICAL] DATA_EXFIL — 74.224.107.140 | CRITICAL | RESOLVED |  | [1152] | [{"timestamp": "2026-03-12 22:31:13", "text": "Status changed to RESOLVED"}] | 74.224.107.140 | Exfiltration |
| 293 | 1773334767.0018878 | 1773334884.2226589 | Multi-Stage Attack from 74.224.107.140: Actions on Objectives → Impact | CRITICAL | INVESTIGATING |  | [1151, 1152] | [{"timestamp": "2026-03-12 22:31:24", "text": "Status changed to INVESTIGATING"}] | 74.224.107.140 | Actions on Objectives → Impact |
| 292 | 1773334746.4839368 | 1773334746.4839368 | Multi-Stage Attack from 10.196.44.209: Reconnaissance → Impact | CRITICAL | OPEN |  | [1148, 1150] | [] | 10.196.44.209 | Reconnaissance → Impact |

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
| 784 | 1773379844.834668 | 5.893061502126948 |
| 783 | 1773379834.8315272 | 6.203222633817841 |
| 782 | 1773379824.8253918 | 6.529708035597728 |
| 781 | 1773379814.8168545 | 6.873376879576556 |
| 780 | 1773379804.8160343 | 3.393047939212867 |

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
| 1160 | 1773379812.1034515 | 10.147.42.143 | 10.147.42.209 |  |  | RATE_LIMIT | HIGH | High packet rate from 10.147.42.143 → 10.147.42.209 (20 pkts/60s) | {"src_ip": "10.147.42.143", "dst_ip": "10.147.42.209", "count": 20, "enrichment": {"risk_score": ... |
| 1159 | 1773379681.1978858 | 0.0.0.0 | 255.255.255.255 |  |  | RATE_LIMIT | HIGH | High packet rate from 0.0.0.0 → 255.255.255.255 (20 pkts/60s) | {"src_ip": "0.0.0.0", "dst_ip": "255.255.255.255", "count": 20, "enrichment": {"risk_score": 7.95... |
| 1158 | 1773379669.1170974 | 10.149.119.209 | 10.149.119.255 |  |  | RATE_LIMIT | HIGH | High packet rate from 10.149.119.209 → 10.149.119.255 (20 pkts/60s) | {"src_ip": "10.149.119.209", "dst_ip": "10.149.119.255", "count": 20, "enrichment": {"risk_score"... |
| 1157 | 1773378864.494883 | 10.147.42.209 |  |  |  | PORT_SCAN | MEDIUM | Port Scan detected from 10.147.42.209 (5 unique ports probed) | {"src_ip": "10.147.42.209", "ports_scanned": 5, "enrichment": {"risk_score": 7.8, "confidence": 8... |
| 1156 | 1773378828.0419426 | 10.147.42.143 |  |  |  | PORT_SCAN | MEDIUM | Port Scan detected from 10.147.42.143 (5 unique ports probed) | {"src_ip": "10.147.42.143", "ports_scanned": 5, "enrichment": {"risk_score": 11.83, "confidence":... |
