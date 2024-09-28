# README

## Web Health Check Tool

This Python tool performs vital health checks on a web page, including SSL certificate validation, DNS resolution time, time to first byte, and total download time of the static content. It also provides an option to generate a comprehensive health check report for a specific URL.

---

### Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Code Overview](#code-overview)
- [Error Handling](#error-handling)
- [Extending the Tool](#extending-the-tool)
- [Refactoring into an Elastic Beat](#refactoring-into-an-elastic-beat)
- [License](#license)

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
   cd web-health-check
   ```

2. **Run the Script**

   Modify the `health_check.py` script with your desired URL or pass the URL as an argument.

   **Option 1: Modify the Script**

   ```python
   if __name__ == "__main__":
       health_check('https://example.com')
   ```

   **Option 2: Pass URL as Command-Line Argument**

   Update the script to accept command-line arguments:

   ```python
   import sys

   if __name__ == "__main__":
       url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
       health_check(url)
   ```

   Run the script:

   ```bash
   python health_check.py https://yourwebsite.com
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

### Customizing Parameters

- **Minimum SSL Days**

  By default, the script checks if the SSL certificate has at least 10 days before expiration. You can change this value by passing the `min_ssl_days` parameter to the `health_check` function.

  ```python
  health_check('https://example.com', min_ssl_days=15)
  ```

- **Timeouts**

  Adjust network timeouts by modifying the timeout parameters in the respective functions.

## Code Overview

The script consists of the following main functions:

- `check_ssl_expiry(hostname, min_days)`
  - Checks SSL certificate validity and days until expiration.

- `measure_dns_time(domain)`
  - Measures DNS resolution time and retrieves resolved IPs.

- `measure_ttfb(url)`
  - Measures time to first byte for the given URL.

- `measure_total_download_time(url)`
  - Measures the total time to download the entire content of the web page.

- `health_check(url, min_ssl_days)`
  - Combines all the above functions to generate a comprehensive health check report.

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

## Refactoring into an Elastic Beat

To integrate this tool into the Elastic Stack (ELK Stack) as a custom Beat, you can consider the following approaches:

### Option 1: Use Heartbeat (Recommended)

[Heartbeat](https://www.elastic.co/guide/en/beats/heartbeat/current/index.html) is an existing Beat designed for uptime monitoring, which can perform many of the checks you need.

#### Steps:

1. **Install Heartbeat**

   ```bash
   sudo apt-get install heartbeat-elastic
   ```

2. **Configure Heartbeat**

   Edit the `heartbeat.yml` configuration file to include your targets.

   ```yaml
   heartbeat.monitors:
   - type: http
     id: my-monitor
     name: My Monitor
     schedule: '@every 1m'
     urls: ["https://example.com"]
     check.request:
       method: GET
     check.response:
       status: 200
   ```

3. **Enable SSL Checks**

   Heartbeat can perform SSL certificate checks.

   ```yaml
   ssl:
     certificate_authorities: ["/etc/ssl/certs/ca-certificates.crt"]
     supported_protocols: ["TLSv1.2", "TLSv1.3"]
     verification_mode: full
   ```

4. **Configure Output**

   Set up the output to Elasticsearch or Logstash.

   ```yaml
   output.elasticsearch:
     hosts: ["localhost:9200"]
   ```

5. **Run Heartbeat**

   ```bash
   sudo service heartbeat-elastic start
   ```

6. **Visualize in Kibana**

   Use the pre-built dashboards or create custom ones to visualize the health check data.

### Option 2: Create a Custom Beat

If Heartbeat does not meet all your requirements, you can create a custom Beat.

#### Prerequisites:

- **Go Programming Language**: Beats are written in Go.

#### Steps:

1. **Set Up Development Environment**

   Install Go and set up your `GOPATH`.

2. **Use Beat Generator**

   Use Elastic's Beat generator to create a new Beat.

   ```bash
   go get github.com/elastic/beats/v7
   cd ${GOPATH}/src/github.com/elastic/beats
   make create-beat NAME=mybeat
   ```

3. **Implement Your Logic**

   - Rewrite the health check functionalities in Go.
   - Utilize Go's libraries for SSL checks, DNS resolution, and HTTP requests.

4. **Build and Test**

   ```bash
   cd mybeat
   make
   ./mybeat test config
   ./mybeat setup
   ./mybeat -e
   ```

5. **Configure Output**

   Similar to Heartbeat, set up the output to Elasticsearch or Logstash in the `mybeat.yml` file.

6. **Create Dashboards**

   - Define index patterns in Kibana.
   - Create visualizations and dashboards to monitor the data.

#### Considerations:

- **Development Effort**: Creating a custom Beat requires significant development and testing.
- **Maintenance**: You'll need to maintain and update your custom Beat as Elastic Stack versions evolve.

### Option 3: Use Logstash with Custom Scripts

If rewriting the tool in Go is not feasible, you can integrate your Python script with Logstash.

#### Steps:

1. **Modify the Python Script**

   - Adjust the script to output data in a structured format (e.g., JSON).

2. **Set Up Logstash**

   - Install Logstash and configure an input to read from a file or receive data via TCP/HTTP.

   ```yaml
   input {
     file {
       path => "/path/to/health_check_output.json"
       start_position => "beginning"
       sincedb_path => "/dev/null"
     }
   }
   ```

3. **Configure Logstash Filters**

   - Parse the JSON data and enrich it as needed.

4. **Set Up Output**

   - Output the data to Elasticsearch.

   ```yaml
   output {
     elasticsearch {
       hosts => ["localhost:9200"]
       index => "web-health-check-%{+YYYY.MM.dd}"
     }
   }
   ```

5. **Automate the Process**

   - Schedule the Python script to run at regular intervals (e.g., using `cron`).
   - Ensure the script writes output to the location monitored by Logstash.

6. **Visualize in Kibana**

   - Create index patterns and dashboards based on the data ingested.

#### Advantages:

- **Leverages Existing Code**: You don't need to rewrite your script.
- **Flexibility**: Logstash offers powerful data processing capabilities.

#### Disadvantages:

- **Complexity**: Involves configuring multiple components.
- **Performance**: May not be as efficient as a Beat for high-volume data.

## License

This project is licensed under the [MIT License](LICENSE).

---

**Note**: For a production-ready solution, consider using existing tools like Heartbeat, which are optimized for performance and scalability within the Elastic Stack. Custom development should be weighed against the benefits and maintenance overhead.

---

Let me know if you need further assistance or specific guidance on any of the steps!