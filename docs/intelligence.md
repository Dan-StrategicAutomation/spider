# Threat Intelligence

## Sources

1. **NVD API 2.0** (NIST National Vulnerability Database)
   - Rate limited: 0.6 req/sec (no key), 5 req/sec (with key)
   - Implementation: `src/spider/intelligence/cve_db.py`
   - Caching: 24h TTL in-memory cache

2. **CISA KEV** (Known Exploited Vulnerabilities)
   - Downloaded daily from CISA public feed
   - Implementation: `src/spider/intelligence/kev.py`
   - Identifies CVEs actively exploited in the wild

3. **EPSS** (Exploit Prediction Scoring System)
   - Predicts probability of exploitation in next 30 days
   - Implementation: `src/spider/intelligence/epss.py`
   - Rate limited client-side

4. **Exploit-DB** (OffSec Exploit Database)
   - searchsploit CLI integration
   - Implementation: `src/spider/intelligence/exploit_db.py`
   - Maps CVEs to actual exploit code

## Rate Limiting

NVD API is the primary bottleneck. Strategy:
- Batch requests when possible
- SQLite cache with 24h TTL
- Exponential backoff on 429 responses
- NVD API key recommended for 5x rate limit boost
