from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
import ipaddress


ip_address = "172.30.10.184"  
key_file = "key.pem"  
cert_file = "cert.pem"  


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, ip_address),
])


ip = ipaddress.ip_address(ip_address)
alt_names = x509.SubjectAlternativeName([x509.IPAddress(ip)])


cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 год
    .add_extension(alt_names, critical=False)
    .sign(private_key, hashes.SHA256())
)


with open(key_file, "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )


with open(cert_file, "wb") as f:
    f.write(cert.public_bytes(Encoding.PEM))

print(f"Сертификат и ключ успешно созданы:\n - Ключ: {key_file}\n - Сертификат: {cert_file}")
