<p align="center">
  <img src="img/logo_mini.png" alt="Project Logo"/>
</p>

# Web site Health Check Tool

This Python tool performs a few health checks on a web page, including:
- SSL certificate validation,
- DNS resolution time,
- time to first byte,
- and total download time of the static content.

It also generates a health check report for a specific URL.


## Motivation

A portfolio of websites needed to be tested to ensure their continuous availability and security.
Automated SSL certificate renewals can sometimes fail without immediate notice, potentially
exposing your sites to security risks, downtime, and reputation breaches. While few outstanding
SSL testing tools are available, I was looking for something more crafted for my simple needs.

 1. Is SSL valid
 2. EOL for SSL certificate
 3. Measure the time for DNS to respond
 4. Measure time for server to respond after request been sent (time to first byte)
 5. Measure the time for whole static content to be served (ignoring images, css, js, images)
 6. Preferably multiple ways of delivering test results (like ELK, DataDog, Slack, telegram, or anything else); while I like those tools, I don't want to change them every time I need to pass messages to different clients.


By all means, this tool is not intended to be a replacement for well-known SSL validators that are available. 

---

### Table of Contents

- [Web site Health Check Tool](#web-site-health-check-tool)
  - [Motivation](#motivation)
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
  - Verifies that the SSL certificate has at least a minimum number of days before expiration (default is 10 days).

- **DNS Resolution Time**
  - Measures the time it takes to resolve a domain to an IP address via DNS.
  - Retrieves all resolved IP addresses.

- **Time to First Byte (TTFB)**
  - Calculates the time it takes to receive the first byte of data after making a request to the server.

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

The script will output a detailed health check report for the specified URL, including:

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
    "url": "https://www.example.com",
    "domain": "www.example.com",
    "ssl_check": {
        "valid": true,
        "days_until_expiration": 154,
        "expiry_date": "2025-03-01 23:59:59"
    },
    "dns_check": {
        "resolution_time_ms": 2.5107860565185547,
        "resolved_ips": [
            "93.184.215.14"
        ]
    },
    "performance": {
        "ttfb_ms": 430.05100000000004,
        "total_download_time_ms": 397.6855278015137
    },
    "timestamp": "2024-09-28 21:34:14"
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
Consider refactor it into Elastic Beat or data provider for Prometheus and Grafana 

## Refactoring into an Elastic Beat

To integrate this tool into the Elastic Stack (ELK Stack) as a custom Beat, you can consider the following approaches:
