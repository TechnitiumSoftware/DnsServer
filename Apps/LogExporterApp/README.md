# Log Exporter for Technitium DNS Server

A plugin that exports DNS query logs to external sinks such as files, HTTP endpoints and Syslog servers. The plugin now supports enrichment stages before export, providing additional derived metadata.

It maintains an in-memory queue with bulk processing and supports EDNS and optional enrichment layers.

## Features

* Captures DNS queries and responses using the Technitium DNS `IDnsQueryLogger` interface.
* Performs enrichment before exporting (currently Public Suffix List resolution).
* Queues log entries asynchronously and flushes them in batches.
* Exports logs via pluggable output sinks: console, file, HTTP POST and Syslog.
* Includes nameserver, question, answer, protocol, RTT, EDNS details and additional enrichment data.
* Prevents unbounded memory usage through bounded log pipelines.
* Flushes pending logs on shutdown.

## Configuration

Provide JSON configuration similar to:

```json
{
  "maxQueueSize": 50000,
  "enableEdnsLogging": true,
  "enablePslResolution": {
    "enabled": true
  },
  "console": {
    "enabled": true
  },
  "file": {
    "enabled": false,
    "path": "/var/log/technitium/dns.log"
  },
  "http": {
    "enabled": true,
    "endpoint": "https://collector.example.com/dns",
    "headers": { "Authorization": "Bearer token" }
  },
  "syslog": {
    "enabled": false,
    "address": "10.0.0.5",
    "port": 6514,
    "protocol": "tls"
  }
}
```

## Sample dig result for technitium.com query

```bash
dig '@127.0.0.1' technitium.com

; <<>> DiG 9.16.25 <<>> @127.0.0.1 technitium.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62685
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;technitium.com.                        IN      A

;; ANSWER SECTION:
technitium.com.         8218    IN      A       206.189.140.177

;; Query time: 24 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Mon Dec 08 22:50:37 FLE Standard Time 2025
;; MSG SIZE  rcvd: 59

```

## Sample log fot technitium.com query

Otiginal log:

```json
{"answers":[{"dnssecStatus":"Disabled","name":"technitium.com","recordClass":"IN","recordData":"206.189.140.177","recordTtl":8218,"recordType":"A"}],"clientIp":"127.0.0.1","edns":[],"nameServer":"127.0.0.1","protocol":"Udp","question":{"questionClass":"IN","questionName":"technitium.com","questionType":"A"},"responseCode":"NoError","responseType":"Cached","timestamp":"2025-12-08T20:50:37.321Z","enrichment":{"domainInfo":{"domain":"technitium","topLevelDomain":"com","registrableDomain":"technitium.com","fullyQualifiedDomainName":"technitium.com","topLevelDomainRule":{"name":"com","type":"Normal","labelCount":1,"division":"ICANN"}}}}
```

Formatted for easier review.

```json
{
  "answers": [
    {
      "dnssecStatus": "Disabled",
      "name": "technitium.com",
      "recordClass": "IN",
      "recordData": "206.189.140.177",
      "recordTtl": 8218,
      "recordType": "A"
    }
  ],
  "clientIp": "127.0.0.1",
  "edns": [],
  "nameServer": "127.0.0.1",
  "protocol": "Udp",
  "question": {
    "questionClass": "IN",
    "questionName": "technitium.com",
    "questionType": "A"
  },
  "responseCode": "NoError",
  "responseType": "Cached",
  "timestamp": "2025-12-08T20:50:37.321Z",
  "enrichment": {
    "domainInfo": {
      "domain": "technitium",
      "topLevelDomain": "com",
      "registrableDomain": "technitium.com",
      "fullyQualifiedDomainName": "technitium.com",
      "topLevelDomainRule": {
        "name": "com",
        "type": "Normal",
        "labelCount": 1,
        "division": "ICANN"
      }
    }
  }
}
```
## Key notes

* `enablePslResolution` controls Public Suffix List enrichment.
* Enrichment adds fields under the `enrichment` dictionary inside each log.
* EDNS extended error information is included when enabled.
* `maxQueueSize` applies backpressure across the pipeline.
