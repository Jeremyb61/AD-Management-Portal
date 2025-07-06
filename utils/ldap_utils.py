from ldap3 import Server, Connection, SIMPLE, Tls, NONE
import ssl
import re
import struct

# === CONFIG ===
BASE_DN = 'DC=Billecci,DC=com'
SERVICE_USER = 'ldap_service@billecci.com'
SERVICE_PASS = 'obtrusive-disarm5lunacy!bluish'
LDAP_SERVER = "BIL-DC01.billecci.com"
ALLOWED_GROUP = 'Domain Admins'

# configure cert validation
tls_config = Tls(
    ca_certs_file='C:/certs/billecci_selfsigned.cer',
    validate=ssl.CERT_REQUIRED,
    version=ssl.PROTOCOL_TLSv1_2
)

# configure ldap over SSL connection to DC 
server = Server(
    LDAP_SERVER, 
    port=636, 
    use_ssl=True, 
    tls=tls_config,
    get_info=NONE
)

# === CONFIG ===

def decode_sid(sid_bytes):
    # Decode Windows SID bytes to string like S-1-5-21-...

    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
    sub_authorities = struct.unpack('<' + 'I'*sub_authority_count, sid_bytes[8:8 + 4*sub_authority_count])

    sid_str = f'S-{revision}-{authority}'
    for sub_auth in sub_authorities:
        sid_str += f'-{sub_auth}'
    return sid_str


def authenticate(username, password):
    try:

        # bind with ldap_service account
        conn = Connection(
            server,
            user="CN=LDAP Service,OU=Service Accounts,DC=Billecci,DC=com",
            password=SERVICE_PASS,
            authentication=SIMPLE,
            auto_bind=True
        )

        # search for user and group info of user attempting to login
        conn.search(
            BASE_DN,
            f"(sAMAccountName={username})",
            attributes=["distinguishedName", "objectSid", "primaryGroupID", "memberOf"]
        )

        #username not found? authentication fails
        if not conn.entries:
            print("User not found")
            conn.unbind()
            return False

        
        entry = conn.entries[0]
        user_dn = entry.distinguishedName.value
        object_sid = entry.objectSid.value
        primary_group_id = entry.primaryGroupID.value



        full_sid = decode_sid(object_sid)
        sid_base = '-'.join(full_sid.split('-')[:-1])
        primary_group_sid = f"{sid_base}-{primary_group_id}"


        conn.search(BASE_DN, f"(objectSid={primary_group_sid})", attributes=["cn"])
        primary_group_cn = conn.entries[0].cn.value if conn.entries else None


        # Step 4: Collect all groups
        group_names = []
        if primary_group_cn:
            group_names.append(primary_group_cn)

        if 'memberOf' in entry:
            for group_dn in entry.memberOf.values:
                conn.search(group_dn, '(objectClass=*)', attributes=['cn'])
                if conn.entries:
                    group_names.append(conn.entries[0].cn.value)

        print("Groups for user:", group_names)

        if not any(name.lower() == ALLOWED_GROUP.lower() for name in group_names):

            print("User is not in Domain Admins")
            conn.unbind()
            return False

        # Step 5: Authenticate as user
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )
        

        conn.unbind()
        print("User authenticated successfully")
        return True

    except Exception as e:
        print("LDAP error:", e)
        return False

    finally:
        if conn:
            conn.unbind()
        if user_conn:
            user_conn.unbind()


def validate_user_payload(data):
    errors = []

    first = data.get('firstName', '').strip()
    last = data.get('lastName', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    jobtitle = data.get('jobtitle', '').strip()
    phone = data.get('phonenumber', '').strip()

    name_pattern = r"^[A-Za-z]{2,20}$"
    username_pattern = r"^[A-Za-z]+$"
    jobtitle_pattern = r"^(?=(?:[^0-9]*[0-9]?[^0-9]*$))[A-Za-z0-9 ]{3,}$"
    phone_pattern = r"^\d{10,11}$"

    if not re.match(name_pattern, first):
        errors.append("Invalid first name")
    if not re.match(name_pattern, last):
        errors.append("Invalid last name")
    
    if not re.match(username_pattern, username):
        errors.append("Username must contain only letters")
    elif not (len(username) >= 2 and username[0].lower() == first[0].lower() and username[1:].lower() == last.lower()):
        errors.append("Username must follow first-initial last-name format")

    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number")
    if not re.search(r"[^a-zA-Z0-9]", password):
        errors.append("Password must contain at least one special character")

    if not re.match(jobtitle_pattern, jobtitle):
        errors.append("Job title can contain no less than 3 letters, no more than 1 number")

    if not re.match(phone_pattern, phone):
        errors.append("Phone number must be 10–11 digits")

def get_service_connection():
    return Connection(
        server,
        user='BILLECCI\\ldap_service',
        password=SERVICE_PASS,
        authentication=SIMPLE,
        auto_bind=True
    )


    return errors
