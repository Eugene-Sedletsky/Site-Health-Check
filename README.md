[![Lint Status](https://github.com/Eugene-Sedletsky/Site-Health-Check/actions/workflows/pylint.yml/badge.svg)](https://github.com/Eugene-Sedletsky/Site-Health-Check/actions)

<p align="center">
  <img src="img/logo_mini.png" alt="Project Logo"/>
</p>

# Web site Health Check Tool

This Python tool performs a few health checks on a web page, including:
- **SSL certificate validation**,
- **DNS resolution time**,
- **time to first byte**,
- **and total download time of the static content**.

It also generates a health check report for a specific URL.


## Motivation

A portfolio of websites needed to be tested to ensure their continuous availability and security.
Automated SSL certificate renewals can sometimes fail without immediate notice, potentially
exposing your sites to security risks, downtime, and reputation breaches. While few outstanding
SSL testing tools are available; I wanted something more crafted for my simple needs.

 1. Is SSL valid
 2. EOL for SSL certificate
 3. Measure the time for DNS to respond
 4. Measure the time for the server to respond after the request has been sent (time to the first byte)
 5. Measure the time for whole static content to be served (ignoring images, CSS, JS, and images)
 6. Preferably multiple ways of delivering test results (like ELK, DataDog, Slack, telegram, or anything else); while I like those tools, I want to keep them the same whenever I need to pass messages to different clients.


By all means, this tool is intended to be something other than a replacement for available well-known SSL validators. 

---

## Precautions

This package is currently in its early development stages. At this time, a few changes may be made directly to the master branch without pull requests.

Please wait for further updates.

## Table of Contents

- [Web site Health Check Tool](#web-site-health-check-tool)
  - [Motivation](#motivation)
  - [Precautions](#precautions)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Dependencies](#dependencies)
  - [Usage](#usage)
    - [Running the Health Check](#running-the-health-check)
    - [Output](#output)
    - [Customizing Parameters](#customizing-parameters)
  - [Error Handling](#error-handling)
  - [Extending the Tool](#extending-the-tool)
  - [ToDo](#todo)
  - [Refactoring into an Elastic Beat](#refactoring-into-an-elastic-beat)

---

## Features

- **SSL Certificate Validation**
  - Checks if the SSL certificate is valid and matches the hostname.
  - Verifies that the SSL certificate has at least a minimum of days before expiration (default is 10 days).

- **DNS Resolution Time**
  - Measures the time it takes to resolve a domain to an IP address via DNS.
  - Retrieves all resolved IP addresses.

- **Time to First Byte (TTFB)**
  - Calculates the time it takes to receive the first data byte after requesting the server.

- **Total Download Time**
  - Measures the total time taken to download the entire static content of the web page.

- **Health Check Report**
  - Generates a detailed report for a specific URL, summarizing all the above metrics.

- **Configurable output receivers**

## Installation

### Prerequisites

- Python 3.11 or higher
- poetry dependency manager

### Dependencies

Install the required Python packages using the following command:

```bash
make install
```

## Usage

### Running the Health Check

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/web-health-check.git
   cd site-health-check
   ```

2. **Run the Script**

   **Option 1: create sites.ini, use sites.ini.example as an example**

   ```bash
   make run
   ```

   **Option 2: Pass URL as Command-Line Argument**


   Run the script:

   ```bash
   python main.py https://yourwebsite.com
   ```

### Output

The script will output a detailed health check report for the specified URL, including the following:

- **SSL Certificate**
  - Validity status
  - Days until expiration

- **DNS Resolution**
  - Resolution time
  - Resolved IP addresses

- **Performance Metrics**
  - Time to first byte
  - Total download time

- **Summary**
```
{
  "url": "https://example.com",
  "domain": "example.com",
  "ssl_check": {
    "valid": true,
    "days_until_expiration": 96,
    "expiry_date": "2025-03-01 23:59:59"
  },
  "dns_check": {
    "resolution_time_ms": 3.998994827270508,
    "resolved_ips": [
      "93.184.215.14"
    ]
  },
  "performance": {
    "ttfb_ms": 480.556,
    "total_download_time_ms": 361.16957664489746
  },
  "timestamp": "2024-11-25 21:15:08",
  "dns": {
    "domain": "example.com",
    "resolved_ips": [
      "93.184.215.14"
    ],
    "error": null,
    "dns_records": {
      "TYPE0": [],
      "A": [
        "93.184.215.14"
      ],
      "NS": [
        "a.iana-servers.net.",
        "b.iana-servers.net."
      ],
      "MD": [],
      "MF": [],
      "CNAME": [],
      "SOA": [
        "ns.icann.org. noc.dns.icann.org. 2024081457 7200 3600 1209600 3600"
      ],
      "MB": [],
      "MG": [],
      "MR": [],
      "NULL": [],
      "WKS": [],
      "PTR": [],
      "HINFO": [],
      "MINFO": [],
      "MX": [
        "0 ."
      ],
      "TXT": [
        "\"v=spf1 -all\"",
        "\"wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn\""
      ],
      "RP": [],
      "AFSDB": [],
      "X25": [],
      "ISDN": [],
      "RT": [],
      "NSAP": [],
      "NSAP-PTR": [],
      "SIG": [],
      "KEY": [],
      "PX": [],
      "GPOS": [],
      "AAAA": [
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
      ],
      "LOC": [],
      "NXT": [],
      "SRV": [],
      "NAPTR": [],
      "KX": [],
      "CERT": [],
      "A6": [],
      "DNAME": [],
      "OPT": [
        "Not supported for querying"
      ],
      "APL": [],
      "DS": [
        "370 13 2 be74359954660069d5c63d200c39f5603827d7dd02b56f120ee9f3a86764247c"
      ],
      "SSHFP": [],
      "IPSECKEY": [],
      "RRSIG": [],
      "NSEC": [],
      "DNSKEY": [
        "256 3 13 OtuN/SL9sE+SDQ0tOLeezr1KzUNi77Ff lTjxQylUhm3V7m13Vz9tYQucSGK0pyxI So9CQsszubAwJSypq3li3g==",
        "256 3 13 ai2pvpijJjeNTpBu4yg6T375JqIStPtL ABDTAILb+f4J7XpofUNXGQn6FpQvZ6CA RWn2xQapbjGtDRjTf4qYxg==",
        "257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7Y tkCJxD2d+t7KXqwahww5IgJtxJT2yFIt lggazyfXqJEVOmMJ3qT0tQ=="
      ],
      "DHCID": [],
      "NSEC3": [],
      "NSEC3PARAM": [
        "1 0 5 6a603f21393e8811"
      ],
      "TLSA": [],
      "SMIMEA": [],
      "HIP": [],
      "NINFO": [],
      "CDS": [],
      "CDNSKEY": [],
      "OPENPGPKEY": [],
      "CSYNC": [],
      "ZONEMD": [],
      "SVCB": [],
      "HTTPS": [],
      "SPF": [],
      "UNSPEC": [],
      "NID": [],
      "L32": [],
      "L64": [],
      "LP": [],
      "EUI48": [],
      "EUI64": [],
      "TKEY": [
        "Not supported for querying"
      ],
      "TSIG": [
        "Not supported for querying"
      ],
      "IXFR": [
        "Not supported for querying"
      ],
      "AXFR": [
        "Not supported for querying"
      ],
      "MAILB": [
        "Not supported for querying"
      ],
      "MAILA": [
        "Not supported for querying"
      ],
      "ANY": [
        "Not supported for querying"
      ],
      "URI": [],
      "CAA": [],
      "AVC": [],
      "AMTRELAY": [],
      "TA": [],
      "DLV": []
    },
    "domain_registration_info": {
      "domain": "EXAMPLE.COM",
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "registration_date": "1995-08-14T04:00:00",
      "expiration_date": "2025-08-13T04:00:00",
      "updated_date": "2024-08-14T07:01:34",
      "error": null
    }
  }
}

```

### Customizing Parameters

- **Minimum SSL Days**

  By default, the script checks if the SSL certificate has at least 10 days before expiration. You can change this value by passing the `min_ssl_days` parameter to the `health_check` function.

- **Timeouts**

  Adjust network timeouts by modifying the timeout parameters in the respective functions.

## Error Handling

For production use, consider adding robust error handling to manage exceptions such as:

- **Network Errors**: Handle connectivity issues and timeouts.
- **Invalid Inputs**: Validate URLs and handle cases where the domain cannot be resolved.
- **SSL Errors**: Manage exceptions related to SSL certificate retrieval and validation.

## Extending the Tool

- **Logging**: Integrate logging to record health checks over time.
- **Alerts**: Set up alerts to notify when SSL certificates are about to expire or when performance metrics exceed thresholds.
- **Concurrency**: Modify the script to handle multiple URLs concurrently using threading or asynchronous programming.
- **Reporting**: Export the health check report to a file (e.g., JSON, CSV) for further analysis.

## ToDo
Consider refactoring it into Elastic Beat or a data provider for Prometheus and Grafana. 


