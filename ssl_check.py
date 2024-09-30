"SSL check experiment"
import socket
import datetime
import requests
import OpenSSL
import idna
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

def get_certificate(hostname, port=443):
    """
    Retrieves the server's SSL certificate using PyOpenSSL.
    """
    try:
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        conn = OpenSSL.SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.set_tlsext_host_name(hostname.encode())
        conn.connect((hostname, port))
        conn.do_handshake()
        cert = conn.get_peer_certificate()
        pem_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        conn.close()
        return pem_cert.decode()
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"Error retrieving certificate: {e}")
        return None

def ssl_certificate_expiry_check(cert_pem):
    """
    Checks if the SSL certificate is expired or nearing expiration.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    expire_date = cert.not_valid_after_utc  # Timezone-aware datetime
    now = datetime.datetime.now(datetime.timezone.utc)  # Timezone-aware datetime
    remaining = expire_date - now  # Valid subtraction
    print(f"Certificate expires on: {expire_date}")
    print(f"Days until expiry: {remaining.days}")
    if remaining.days < 30:
        print("Warning: Certificate will expire soon!")
    else:
        print("Certificate is valid.\n")

def ssl_certificate_chain_check(hostname, port=443):
    """
    Verifies the complete certificate chain.
    """
    try:
        hostname_idna = idna.encode(hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = OpenSSL.SSL.VERIFY_NONE
        ssl_conn = OpenSSL.SSL.Connection(ctx, sock)
        ssl_conn.set_tlsext_host_name(hostname_idna)
        ssl_conn.set_connect_state()
        ssl_conn.do_handshake()
        certs = ssl_conn.get_peer_cert_chain()
        ssl_conn.close()
        sock.close()

        print("Certificate Chain:")
        for idx, cert in enumerate(certs):
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            print(f"Certificate {idx + 1}:")
            print(f"  Subject: {subject.CN}")
            print(f"  Issuer: {issuer.CN}\n")
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"Error retrieving certificate chain: {e}")

def domain_name_match(cert_pem, hostname):
    """
    Ensures that the SSL certificate matches the domain name.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    san_list = san.get_values_for_type(x509.DNSName)

    print(f"Common Name (CN): {common_name}")
    print(f"Subject Alternative Names (SANs): {san_list}")
    if hostname == common_name or hostname in san_list:
        print("Domain name matches the certificate.\n")
    else:
        print("Warning: Domain name does not match the certificate!\n")

def wildcard_and_san_certificate_validation(cert_pem, hostname):
    """
    Validates wildcard and SAN certificates.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    san_list = san.get_values_for_type(x509.DNSName)
    match = False
    for name in san_list:
        if name.startswith("*"):
            if hostname.endswith(name.strip("*")):
                match = True

                break
        elif name == hostname:
            match = True

            break

    if match:
        print("Wildcard/SAN certificate covers the domain.\n")
    else:
        print("Wildcard/SAN certificate does NOT cover the domain!\n")

def self_signed_certificate_detection(cert_pem):
    """
    Detects if the certificate is self-signed.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    if issuer == subject:
        print("The certificate is self-signed!\n")
    else:
        print("The certificate is not self-signed.\n")

def supported_protocols(hostname, port=443):
    """
    Ensures that the web server supports modern SSL/TLS protocols.
    """
    protocols = {
        'SSLv2': OpenSSL.SSL.SSLv2_METHOD if hasattr(OpenSSL.SSL, 'SSLv2_METHOD') else None,
        'SSLv3': OpenSSL.SSL.SSLv3_METHOD if hasattr(OpenSSL.SSL, 'SSLv3_METHOD') else None,
        'TLSv1': OpenSSL.SSL.TLSv1_METHOD,
        'TLSv1_1': OpenSSL.SSL.TLSv1_1_METHOD,
        'TLSv1_2': OpenSSL.SSL.TLSv1_2_METHOD,
        'TLSv1_3': OpenSSL.SSL.TLSv1_3_METHOD if hasattr(OpenSSL.SSL, 'TLSv1_3_METHOD') else None,
    }

    for name, method in protocols.items():
        if method is None:
            continue
        try:
            context = OpenSSL.SSL.Context(method)
            conn = OpenSSL.SSL.Connection(
                context,
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            conn.set_tlsext_host_name(hostname.encode())
            conn.connect((hostname, port))
            conn.do_handshake()
            print(f"{name}: Supported")
            conn.close()
        except OpenSSL.SSL.Error:
            print(f"{name}: Not supported")
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"{name}: Error - {e}")
    print()

def hsts_check(hostname):
    """
    Checks if HSTS headers are configured.
    """
    try:
        response = requests.get(f'https://{hostname}', timeout=5)
        if 'strict-transport-security' in response.headers:
            print("HSTS is enabled.\n")
        else:
            print("HSTS is not enabled.\n")
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"Error checking HSTS: {e}\n")

def main():
    "Usage example"
    hostname = input("Enter the domain name (e.g., example.com): ").strip()

    cert_pem = get_certificate(hostname)
    if cert_pem:
        print("\n=== SSL Certificate Expiry Check ===")
        ssl_certificate_expiry_check(cert_pem)

        print("=== SSL Certificate Chain Check ===")
        ssl_certificate_chain_check(hostname)

        print("=== Domain Name Match (Hostname Validation) ===")
        domain_name_match(cert_pem, hostname)

        print("=== Wildcard and SAN Certificate Validation ===")
        wildcard_and_san_certificate_validation(cert_pem, hostname)

        print("=== Self-signed Certificate Detection ===")
        self_signed_certificate_detection(cert_pem)

        print("=== Supported Protocols ===")
        supported_protocols(hostname)

        print("=== HSTS (HTTP Strict Transport Security) Check ===")
        hsts_check(hostname)
    else:
        print("Failed to retrieve the certificate.")

if __name__ == "__main__":
    main()
