from flask import Blueprint, render_template, request, redirect, session, flash, jsonify
from utils.ldap_utils import authenticate, validate_user_payload, get_service_connection, server, BASE_DN, SERVICE_PASS
from ldap3 import Connection, SIMPLE, MODIFY_REPLACE, MODIFY_ADD

users_bp = Blueprint('users', __name__)

@users_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')
    return render_template('index.html')


@users_bp.route('/create-user', methods=['POST'])
def create_user():
    if 'username' not in session:
        return redirect('/')
    
    data = request.json


    validation_errors = validate_user_payload(data)
    if validation_errors:
        return jsonify({'error': 'Validation failed', 'details': validation_errors}), 400

    first_name = data['firstName']
    last_name = data['lastName']
    username = data['username']
    password = data['password']
    groups = data.get('groups', [])
    job_title = data['jobtitle']
    phone = data['phonenumber']

    user_cn = f"{first_name} {last_name}"
    user_dn = f"CN={user_cn},OU=Managed Users,{BASE_DN}"
    user_principal_name = f"{username}@billecci.com"
    
    try:
        # Create LDAP connection over SSL
        conn = get_service_connection()

        # Check if user exists
        conn.search(BASE_DN, f'(sAMAccountName={username})', attributes=["*"])
        if conn.entries:
            return jsonify({'error': 'user_exists'}), 409

        # Create the user
        conn.add(user_dn, [
            'top',
            'person',
            'organizationalPerson',
            'user'
        ], {
            'cn': user_cn,
            'givenName': first_name,
            'sn': last_name,
            'displayName': user_cn,
            'userPrincipalName': user_principal_name,
            'sAMAccountName': username,
            'telephoneNumber': phone or '',
            'title': job_title or ''
        })

        if conn.result['result'] != 0:
            return jsonify({'error': 'User creation failed', 'details': conn.result}), 500

        # Set password securely
        conn.extend.microsoft.modify_password(user_dn, password)
        if conn.result['result'] != 0:
            return jsonify({'error': 'Failed to set password', 'details': conn.result}), 500

        # Enable account by setting userAccountControl
        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
        if conn.result['result'] != 0:
            return jsonify({'error': 'Failed to enable user account', 'details': conn.result}), 500


        for group in groups:
            group_dn = f"CN={group},OU=Managed Groups,DC=billecci,DC=com"
            print("Adding user to group:", group_dn)
            conn.modify(group_dn, {
                'member': [(MODIFY_ADD, [user_dn])]
            })
            if conn.result['result'] != 0:
                return jsonify({ 'error': f'Failed to add user to group: {group_dn}','details': conn.result }), 500

        return jsonify({'status': 'success', 'message': f"User {username} created successfully"}), 201

    except Exception as e:
        print("User creation error:", e)
        return jsonify({'error': 'LDAP error', 'details': str(e)}), 500   



@users_bp.route('/list-managed-users', methods=['GET'])
def list_managed_users():
    if 'username' not in session:
        return redirect('/')

    try:
        # Create LDAP connection over SSL
        conn = get_service_connection()

        ou_dn = f"OU=Managed Users,{BASE_DN}"

        conn.search(
            search_base=ou_dn,
            search_filter='(objectClass=user)',
            attributes=['cn', 'displayName', 'sAMAccountName', 'title', 'telephoneNumber', 'memberof', 'userAccountControl']
        )

        excluded_groups = {
            f'CN=Domain Admins,CN=Users,{BASE_DN}',
            f'CN=Enterprise Admins,CN=Users,{BASE_DN}',
            f'CN=Administrators,CN=Builtin,{BASE_DN}',
        }

        users = []
        for entry in conn.entries:

            # Skip if member of any excluded group
            member_of = set(str(group) for group in entry.memberOf) if hasattr(entry, 'memberOf') else set()
            if member_of & excluded_groups:
                continue

            # Get account enabled/disabled status
            uac = int(entry.userAccountControl.value) if hasattr(entry, 'userAccountControl') else 0
            is_enabled = not (uac & 2)

            users.append({
                'dn': str(entry.entry_dn),
                'username': str(entry.sAMAccountName),
                'displayName': str(entry.displayName) if hasattr(entry, 'displayName') else '',
                'jobTitle': str(entry.title) if hasattr(entry, 'title') else '',
                'phone': str(entry.telephoneNumber) if hasattr(entry, 'telephoneNumber') else '',
                'enabled': is_enabled

            })

        return jsonify(users), 200

    except Exception as e:
        print("LDAP list error:", e)
        return jsonify({'error': 'Failed to list users', 'details': str(e)}), 500

@users_bp.route('/toggle-user-status', methods=['POST'])
def toggle_user_status():
    if 'username' not in session:
        return redirect('/')

    data = request.get_json()
    dns = data.get('dns', [])
    target_enabled = data.get('enabled', True)



    if not dns or not isinstance(dns, list):
        return jsonify({'error': 'Missing or invalid "dns" field'}), 400

    results = []

    try:

        # Create LDAP connection over SSL
        conn = get_service_connection()

        for dn in dns:
            # Read the current userAccountControl
            conn.search(dn, '(objectClass=person)', attributes=['userAccountControl'])
            if not conn.entries:
                results.append({'dn': dn, 'status': 'not found'})
                continue

            current_uac = int(conn.entries[0].userAccountControl.value)

            if target_enabled:
                # Clear the "account disabled" bit (bit 2)
                new_uac = current_uac & ~2
            else:
                # Set the "account disabled" bit (bit 2)
                new_uac = current_uac | 2

            # Apply the update
            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
            if conn.result['result'] == 0:
                results.append({'dn': dn, 'status': 'success'})
            else:
                results.append({'dn': dn, 'status': 'failed', 'details': conn.result})

        success_count = sum(1 for r in results if r['status'] == 'success')
        if success_count == len(results):
            return jsonify({'status': 'success', 'results': results})
        else:
            return jsonify({'status': 'partial_success', 'results': results})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@users_bp.route('/delete-users', methods=['POST'])
def delete_users():
    if 'username' not in session:
        return redirect('/')

    data = request.get_json()
    dns = data.get('dns', [])

    if not dns or not isinstance(dns, list):
        return jsonify({'status': 'error', 'message': 'Invalid or missing "dns" list'}), 400

    try:

        # Create LDAP connection over SSL
        conn = get_service_connection()
        
        results = []
        for dn in dns:
            conn.delete(dn)
            if conn.result['result'] == 0:
                results.append({'dn': dn, 'status': 'success'})
            else:
                results.append({'dn': dn, 'status': 'failed', 'details': conn.result})

        if all(r['status'] == 'success' for r in results):
            return jsonify({'status': 'success', 'results': results})
        else:
            return jsonify({'status': 'partial_success', 'results': results}), 207  # 207 = Multi-Status

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
