import os
import tempfile

from OpenSSL import crypto


def create_temp_self_signed_cert():
    """ Create a self signed SSL certificate in temporary files for host
        '127.0.0.1'

    Returns a tuple containing the certificate file name and the key
    file name.

    It is the caller's responsibility to delete the files after use
    """
    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "aioimaplib"
    cert.get_subject().OU = "aioimaplib"
    cert.get_subject().CN = '127.0.0.1'
    ext = crypto.X509Extension(b'subjectAltName', False, b'IP:127.0.0.1')
    cert.add_extensions([ext])
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    # Save certificate in temporary file
    (cert_file_fd, cert_file_name) = tempfile.mkstemp(suffix='.crt', prefix='cert')
    cert_file = os.fdopen(cert_file_fd, 'wb')
    cert_file.write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    )
    cert_file.close()

    # Save key in temporary file
    (key_file_fd, key_file_name) = tempfile.mkstemp(suffix='.key', prefix='cert')
    key_file = os.fdopen(key_file_fd, 'wb')
    key_file.write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    )
    key_file.close()

    # Return file names
    return (cert_file_name, key_file_name)
