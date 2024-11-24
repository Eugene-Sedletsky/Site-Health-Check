"""Web Health Check Tool

Test SSL and response
"""
import ssl
import socket
import datetime
from typing import List
import sys
import json
import time
import os
import configparser
from dataclasses import dataclass
from urllib.parse import urlparse
import dns.resolver
import requests
from core.logger import LoggerConfigurator
import whois


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):  # Correct: datetime.datetime is a type
            return obj.isoformat()
        return super().default(obj)

@dataclass
class SiteConfig:
    "Site configuration data class"
    url: str
    min_ssl_days: int = 10

# Get the loggers
logger_main = LoggerConfigurator.get_logger('main-app-logger')
logger_health = LoggerConfigurator.get_logger('healthCheck')

def check_ssl_expiry(hostname, min_days=10):
    """
    Checks the SSL certificate expiry date for the specified hostname and determines if it is valid
    and not expiring within a given number of days.

    Args:
        hostname (str): The hostname or domain to check the SSL certificate for.
        min_days (int, optional): The minimum number of days the SSL certificate should remain
        valid.
            Defaults to 10.

    Returns:
        Dict[str, Any]: A dictionary containing the results of the SSL certificate check with the
        following keys:
            - 'valid' (bool): Indicates whether the SSL certificate is valid and matches the
                hostname.
            - 'days_until_expiration' (int, optional): Number of days remaining until the SSL
                certificate expires. Present only if the certificate is valid.
            - 'expiry_date' (str, optional): The expiration date of the SSL certificate in
                'YYYY-MM-DD HH:MM:SS' format. Present only if the certificate is valid.
            - 'error' (str, optional): An error message if the SSL check failed.

    Notes:
        - The function creates an SSL context with hostname verification enabled and certificate
            verification mode set to required.
        - It attempts to establish an SSL connection to the specified hostname on port 443.
        - If the SSL certificate is valid and not expiring within the specified `min_days`,
            it returns details about the certificate.
        - If the certificate is invalid, expired, or an error occurs during the connection,
        the function logs the error and returns 'valid' as False.

    Logging:
        - Logs informational messages about the SSL certificate validity and days until expiration.
        - Logs a warning if the SSL certificate is expiring in less than `min_days`.
        - Logs errors if the SSL certificate is invalid or if an SSL error occurs.

    Example:
        >>> ssl_result = check_ssl_expiry('example.com', min_days=15)
        >>> if ssl_result['valid']:
        ...     due_date = ssl_result['days_until_expiration']
        ...     print(
        ...        f"SSL certificate is valid, expires in {due_date} days."
        ...     )
        ... else:
        ...     print(
        ...        f"SSL certificate check failed: {ssl_result.get('error', 'Unknown error')}"
        ...     )
    """
    context = ssl.create_default_context()
    context.check_hostname = True  # Enable hostname verification
    context.verify_mode = ssl.CERT_REQUIRED  # Ensure certificate is verified

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # If the certificate is invalid, an exception will be raised above
                cert = ssock.getpeercert()
                # Extract expiration date
                expire_date_str = cert['notAfter']
                expire_date = datetime.datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.datetime.utcnow()).days
                logger_main.info("SSL Certificate is valid for %s: True", hostname)
                logger_main.info("Days until expiration: %s", days_left)

                if days_left < min_days:
                    message = "Warning: SSL certificate for %s expires in less than %s days!"

                    logger_main.warning(
                        message,
                        hostname,
                        min_days,
                    )
                return {
                    'valid': True,
                    'days_until_expiration': days_left,
                    'expiry_date': expire_date.strftime('%Y-%m-%d %H:%M:%S')
                }
    except ssl.CertificateError as ce:
        logger_main.error("SSL Certificate is valid for %s: False", hostname)
        logger_main.error("CertificateError: %s", str(ce))

        return {
            'valid': False,
            'error': str(ce)
        }
    except ssl.SSLError as se:
        logger_main.error("SSL Error for %s: %s", hostname, str(se))

        return {
            'valid': False,
            'error': str(se)
        }
    except Exception as e: # pylint: disable=broad-exception-caught
        logger_main.error(
            "An error occurred while checking SSL for %s: %s", hostname, str(e))

        return {
            'valid': False,
            'error': str(e)
        }

def measure_dns_time(domain):
    """
    Measures the DNS resolution time for the specified domain.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        Dict[str, Any]: A dictionary containing the DNS resolution results with the following keys:
            - 'resolution_time_ms' (float, optional): The time taken to resolve the domain
                in milliseconds.
            - 'resolved_ips' (List[str]): A list of IP addresses that the domain resolves to.
            - 'error' (str, optional): An error message if DNS resolution failed.

    Notes:
        - The function uses the `dns.resolver` module to perform DNS resolution.
        - It measures the time taken from the initiation of the DNS query to receiving the response
        - If the resolution is successful, it returns the resolution time and the list of resolved
            IP addresses.
        - In case of an exception (e.g., timeout, NXDOMAIN), it logs the error and returns
            an 'error' key in the result.

    Logging:
        - Logs informational messages about the DNS resolution time and resolved IPs.
        - Logs errors if DNS resolution fails.

    Example:
        >>> dns_result = measure_dns_time('example.com')
        >>> if dns_result.get('error'):
        ...     print(f"DNS resolution failed: {dns_result['error']}")
        ... else:
        ...     print(f"Resolution time: {dns_result['resolution_time_ms']:.2f} ms")
        ...     print(f"Resolved IPs: {dns_result['resolved_ips']}")
    """
    resolver = dns.resolver.Resolver()
    start_time = time.time()
    try:
        answers = resolver.resolve(domain)
        end_time = time.time()
        duration = (end_time - start_time) * 1000
        ips = [rdata.address for rdata in answers]
        logger_main.info(
            "DNS resolution time for %s: %.2f ms", domain, duration
        )
        logger_main.debug("Resolved IPs for %s: %s", domain, ips)

        return {
            'resolution_time_ms': duration,
            'resolved_ips': ips
        }
    except Exception as e: # pylint: disable=broad-exception-caught
        logger_main.error("Error resolving DNS for %s: %s", domain, str(e))

        return {
            'resolution_time_ms': None,
            'resolved_ips': [],
            'error': str(e)
        }

def measure_time_to_first_byte(url):
    """
    Measures the Time to First Byte (TTFB) for the specified URL.

    Args:
        url (str): The URL of the website to measure the TTFB for.

    Returns:
        Optional[float]: The time to first byte in milliseconds, or None if the measurement fails.

    Notes:
        - The function sends an HTTP GET request to the specified URL using the `requests` library.
        - It measures the time elapsed from the request initiation until the first byte of
            the response is received.
        - If the request encounters an exception (e.g., timeout, connection error), the function
            logs the error and returns None.
        - The function utilizes a session with a retry strategy to handle transient network issues.

    Logging:
        - Logs informational messages about the TTFB measurement.
        - Logs errors if the request fails.

    Example:
        >>> ttfb = measure_time_to_first_byte('https://example.com')
        >>> if ttfb is not None:
        ...     print(f"Time to First Byte: {ttfb:.2f} ms")
        ... else:
        ...     print("Failed to measure Time to First Byte.")
    """

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=3)
    session.mount('https://', adapter)
    try:
        response = session.get(url, stream=True, timeout=10)
        time_to_first_byte = response.elapsed.total_seconds() * 1000
        logger_main.info(
            "Time to First Byte for %s: %.2f ms",
            url,
            time_to_first_byte,
        )

        return time_to_first_byte
    except requests.exceptions.RequestException as e:
        logger_main.error(
            "Error fetching %s: %s",
            url,
            str(e)
        )
        return None

def measure_total_download_time(url):
    "Total download time for URL"
    start_time = time.time()
    try:
        _ = requests.get(url, timeout=10)
        end_time = time.time()
        duration = (end_time - start_time) * 1000
        logger_main.info(
            "Total download time for %s: %.2f ms",
            url,
            duration,
        )

        return duration
    except requests.exceptions.RequestException as e:
        logger_main.error("Error downloading %s: %s", url, str(e))

        return None

def health_check(url, dns_record={}, min_ssl_days=10):
    """
    Performs a comprehensive health check on the given URL, including SSL certificate validation,
    DNS resolution time measurement, Time to First Byte (TTFB), and total download time of
    the webpage.

    Args:
        url (str): The URL of the website to perform the health check on.
        min_ssl_days (int, optional): The minimum number of days the SSL certificate should
        be valid. Defaults to 10.

    Returns:
        Dict[str, Any]: A dictionary containing the results of the health check with
        the following keys:
            - 'url' (str): The URL that was checked.
            - 'domain' (str): The domain extracted from the URL.
            - 'ssl_check' (Dict[str, Any]): Results of the SSL certificate check, containing:
                - 'valid' (bool): Whether the SSL certificate is valid and matches the hostname.
                - 'days_until_expiration' (int, optional): Days remaining until the
                    SSL certificate expires.
                - 'expiry_date' (str, optional): The expiration date of the SSL certificate
                    in 'YYYY-MM-DD HH:MM:SS' format.
                - 'error' (str, optional): An error message if the SSL check failed.
            - 'dns_check' (Dict[str, Any]): Results of the DNS resolution time measurement,
                containing:
                - 'resolution_time_ms' (float, optional): Time taken to resolve the domain,
                    in milliseconds.
                - 'resolved_ips' (List[str]): A list of IP addresses resolved for the domain.
                - 'error' (str, optional): An error message if DNS resolution failed.
            - 'performance' (Dict[str, Any]): Performance metrics of the website, containing:
                - 'ttfb_ms' (float, optional): Time to First Byte, in milliseconds.
                - 'total_download_time_ms' (float, optional): Total time to download the webpage
                    content, in milliseconds.
                - 'ttfb_error' (str, optional): An error message if TTFB measurement failed.
                - 'download_error' (str, optional): An error message if download time measurement
                    failed.
            - 'timestamp' (str): The UTC timestamp when the health check was performed,
            in 'YYYY-MM-DD HH:MM:SS' format.

    Notes:
        - The function handles exceptions internally and records any errors in the corresponding
            sections of the return dictionary.
        - Logging is performed using the configured logger instances for informational
            and error messages.
        - The function integrates with a logging system to output JSON reports if configured.

    Example:
        >>> result = health_check('https://example.com', min_ssl_days=15)
        >>> print(result['ssl_check']['valid'])
        True
    """
    domain = urlparse(url).hostname

    logger_main.info(
        "\nHealth Check Report for %s\n%s",
        url,
        '-' * 40
    )

    # Initialize the report dictionary
    report = {
        'url': url,
        'domain': domain,
        'ssl_check': {},
        'dns_check': {},
        'performance': {},
        'timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'dns': dns_record
    }

    # SSL Check
    ssl_result = check_ssl_expiry(domain, min_days=min_ssl_days)
    report['ssl_check'] = ssl_result

    # DNS Resolution Time
    dns_result = measure_dns_time(domain)
    report['dns_check'] = dns_result

    # Time to First Byte
    ttfb = measure_time_to_first_byte(url)
    if ttfb is not None:
        report['performance']['ttfb_ms'] = ttfb
    else:
        report['performance']['ttfb_ms'] = None
        report['performance']['ttfb_error'] = 'Error fetching TTFB'

    # Total Download Time
    total_time = measure_total_download_time(url)
    if total_time is not None:
        report['performance']['total_download_time_ms'] = total_time
    else:
        report['performance']['total_download_time_ms'] = None
        report['performance']['download_error'] = 'Error downloading content'

    # Summary Logging
    logger_main.info("\nSummary for %s", url)
    logger_main.info("SSL Valid: %s", ssl_result.get('valid'))
    dns_time = dns_result.get('resolution_time_ms')
    if dns_time is not None:
        logger_main.info("DNS Resolution Time: %.2f ms", dns_time)
    else:
        logger_main.error("DNS Resolution Time: Error")
    if ttfb is not None:
        logger_main.info("Time to First Byte: %.2f ms", ttfb)
    else:
        logger_main.error("Time to First Byte: Error")
    if total_time is not None:
        logger_main.info("Total Download Time: %.2f ms", total_time)
    else:
        logger_main.error("Total Download Time: Error")

    # Log the JSON report using the healthCheck logger
    json_report = json.dumps(report, cls=DateTimeEncoder)
    logger_health.info(json_report)

    return report

def load_sites_from_config(config_file: str = 'sites.ini') -> List[SiteConfig]:
    """
    Loads site configurations from an INI-style configuration file and returns a list
    of `SiteConfig` instances.

    This function reads a configuration file specified by `config_file`, parses the
    sections representing individual site configurations, and creates `SiteConfig` data
    class instances for each site. Each section in the configuration file should represent
    a site, containing at least a `url` key. Optional keys such as `min_ssl_days` can also
    be included to override default values.

    Args:
        config_file (str): The path to the configuration file containing site information.
            Defaults to 'sites.ini'.

    Returns:
        List[SiteConfig]: A list of `SiteConfig` instances, each representing a site's
        configuration.

    Raises:
        FileNotFoundError: If the specified configuration file does not exist.

    Side Effects:
        - Logs errors if the configuration file is missing or if required keys are missing
            in a section.
        - Logs warnings for invalid values that are corrected to defaults.

    Notes:
        - The configuration file should be in INI format, where each section represents a site with
            configuration keys such as `url` and `min_ssl_days`.
        - The `url` key is required in each section. If a section lacks a `url`, it will be skipped.
        - The `min_ssl_days` key is optional. If not provided or invalid, it defaults to 10.
        - Additional optional keys can be added to the `SiteConfig` data class and parsed
            accordingly.

    Example Configuration File (`sites.ini`):
        [site1]
        url = https://www.example.com
        min_ssl_days = 15

        [site2]
        url = https://www.anotherexample.com
        # min_ssl_days not specified; defaults to 10

        [site3]
        url = https://www.invalidsite.com
        min_ssl_days = not_a_number  # Will default to 10 due to invalid value

    Example:
        >>> sites_to_check = load_sites_from_config()
        >>> for site in sites_to_check:
        ...     print(f"Checking site: {site.url} with min_ssl_days: {site.min_ssl_days}")
        ...
        Checking site: https://www.example.com with min_ssl_days: 15
        Checking site: https://www.anotherexample.com with min_ssl_days: 10
        Checking site: https://www.invalidsite.com with min_ssl_days: 10

    Implementation Details:
        - Uses Python's `configparser` module to read and parse the INI file.
        - Creates instances of the `SiteConfig` data class for type safety and convenient attribute
            access.
        - Strips any leading or trailing whitespace from the `url` value.
        - Converts the `min_ssl_days` value to an integer, defaulting to 10 if conversion fails.

    Dependencies:
        - Requires the `configparser` module from the standard library.
        - Depends on the `SiteConfig` data class being defined, typically using the `@dataclass`
            decorator.

    """
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        logger_main.error(
            "Configuration file %s not found.",
            config_file,
        )
        return []

    config.read(config_file)
    sites: List[SiteConfig] = []

    for section in config.sections():
        url = config.get(section, 'url', fallback=None)
        min_ssl_days_str = config.get(section, 'min_ssl_days', fallback=None)

        if url is None:
            logger_main.warning(
                "No URL found in section '%s'. Skipping.",
                section,
            )
            continue

        url = url.strip()

        if min_ssl_days_str is not None:
            try:
                min_ssl_days = int(min_ssl_days_str)
            except ValueError:
                logger_main.warning(
                    "Invalid 'min_ssl_days' value in section '%s'. Defaulting to 10.",
                    section,
                )
                min_ssl_days = 10
        else:
            min_ssl_days = 10  # Default value

        site_config = SiteConfig(url=url, min_ssl_days=min_ssl_days)
        sites.append(site_config)

    return sites

def extract_dns_info(url: str) -> dict[str, List[str]]:
    """
    Extracts basic DNS information (IP addresses) from the given URL.

    Args:
        url (str): The URL of the website.

    Returns:
        Dict[str, List[str]]: A dictionary containing DNS information with the following keys:
            - 'domain': The domain extracted from the URL.
            - 'resolved_ips': A list of resolved IP addresses.
            - 'error': An error message, if DNS resolution fails.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # Extract domain from the URL

    try:
        # Resolve the domain to its associated IP addresses
        resolved_ips = socket.gethostbyname_ex(domain)[2]
        return {
            'domain': domain,
            'resolved_ips': resolved_ips,
            'error': None
        }
    except socket.gaierror as e:
        # Handle DNS resolution failure
        return {
            'domain': domain,
            'resolved_ips': [],
            'error': str(e)
        }

def list_all_dns_records(domain: str) -> dict[str, List[str]]:
    """
    Lists all DNS records (A, MX, NS, CNAME, TXT, and other available records) associated with the domain.

    Args:
        domain (str): The domain to query DNS records for.

    Returns:
        Dict[str, List[str]]: A dictionary where the keys are the DNS record types (e.g., 'A', 'MX', 'TXT')
                              and the values are lists of corresponding records.
    """
    dns_records = {}

    # Loop through all DNS record types available in dnspython's rdatatype
    for record_type in dns.rdatatype.RdataType:
        try:
            # Get the name of the record type
            record_type_name = dns.rdatatype.to_text(record_type)
            
            # Try resolving this record type for the domain
            answers = dns.resolver.resolve(domain, record_type_name)
            dns_records[record_type_name] = [str(rdata) for rdata in answers]
        
        except dns.resolver.NoAnswer:
            # No records of this type found
            dns_records[record_type_name] = []
        
        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            return {'error': f"Domain {domain} does not exist"}
        
        except dns.resolver.NoMetaqueries:
            # Some record types like ANY, AXFR, etc., can't be queried.
            dns_records[record_type_name] = ["Not supported for querying"]
        
        except dns.exception.Timeout:
            # Timeout during the DNS query
            dns_records[record_type_name] = ["Timeout querying this record type"]
        
        except Exception as e:
            # Catch all other errors, including unsupported record types
            dns_records[record_type_name] = [f"Error: {str(e)}"]

    return dns_records

def get_domain_registration_info(domain: str) -> dict[str, any]:
    """
    Retrieves domain registration and expiration information using WHOIS lookup.

    Args:
        domain (str): The domain to query WHOIS information for.

    Returns:
        Dict[str, Any]: A dictionary containing the registration and expiration dates, including:
            - 'domain': The domain name.
            - 'registrar': The registrar of the domain.
            - 'registration_date': The date the domain was registered.
            - 'expiration_date': The date the domain is set to expire.
            - 'updated_date': The last date when the domain information was updated.
            - 'error': An error message, if WHOIS lookup fails.
    """
    try:
        w = whois.whois(domain)
        
        # Extract the relevant information
        registration_info = {
            'domain': w.domain_name,
            'registrar': w.registrar,
            'registration_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'updated_date': w.updated_date,
            'error': None
        }

        # Handle multiple dates (sometimes WHOIS returns a list of dates)
        if isinstance(registration_info['registration_date'], list):
            registration_info['registration_date'] = registration_info['registration_date'][0]
        if isinstance(registration_info['expiration_date'], list):
            registration_info['expiration_date'] = registration_info['expiration_date'][0]
        if isinstance(registration_info['updated_date'], list):
            registration_info['updated_date'] = registration_info['updated_date'][0]

        return registration_info

    except Exception as e:
        # Handle errors such as domain not found or whois query issues
        return {
            'domain': domain,
            'registrar': None,
            'registration_date': None,
            'expiration_date': None,
            'updated_date': None,
            'error': str(e)
        }

if __name__ == "__main__":
    # Configure logging
    # configure_logger()

    # Load URLs from configuration file
    sites_to_check = load_sites_from_config()

    # If URLs are provided via command-line arguments, use them instead
    if len(sys.argv) > 1:
        sites_to_check = sys.argv[1:]

    if not sites_to_check:
        logger_main.error("No URLs provided to check.")
        sys.exit(1)

    for site in sites_to_check:
        logger_main.info("\nProcessing URL %s", site.url)
        dns_info = extract_dns_info(site.url)
        domain = dns_info['domain']
        dns_records = list_all_dns_records(domain)
        domain_registration_info = get_domain_registration_info(domain)
        dns_info.update(
            {
                'dns_records' : dns_records,
                'domain_registration_info': domain_registration_info
            }
        )

        health_check_info = health_check(
            url=site.url,
            dns_record=dns_info,
            min_ssl_days=site.min_ssl_days
        )
