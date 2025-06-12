from flask import Flask, jsonify, request
import os
import calendar
import logging
from flask_jwt_extended import create_access_token, JWTManager , jwt_required, get_jwt_identity
import mysql.connector
from mysql.connector import Error
import bcrypt
from encryption_utils import encrypt_data, decrypt_data
from datetime import datetime, timedelta
from urllib.parse import urlparse
#from base_meal_data import breakfast, lunch, dinner , breakfast_drink

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Ensure you have a secret key set for JWT to use
app.config['JWT_SECRET_KEY'] = 'fSdas23#%@adY'  # Change this!

jwt = JWTManager(app)  # Initialize Flask-JWT-Extended with your Flask app


# Internal admin check function
def is_user_admin(username):
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT user_role FROM users WHERE username = %s', (username,))
            user_role_result = cursor.fetchone()
            conn.close()
            if user_role_result and user_role_result[0].lower() == 'admin':
                return True
    except Error as e:
        print(f"Error checking user role: {e}")
    return False


# Internal function to get resident ID from resident name
def get_resident_id(resident_name):
    conn = None
    try:
        conn = get_db_connection()
        if conn is not None:
            with conn.cursor() as cursor:
                cursor.execute('SELECT id FROM residents WHERE name = %s', (resident_name,))
                result = cursor.fetchone()
                if result:
                    return result[0]  # Extract the ID from the tuple
    except Error as e:
        print(f"Error getting resident ID: {e}")
    finally:
        if conn:
            conn.close()
    return None


# --------------------------------- Database Connection --------------------------------- #

# TODO: Replace the hard-coded credentials with environment variables
def get_db_connection():
    connection = None
    try:
        # Heroku JawsDB MySQL connection using environment variable
        jawsdb_url = urlparse(os.environ['JAWSDB_URL'])
        # Heroku JawsDB MySQL connection
        connection = mysql.connector.connect(
            user=jawsdb_url.username,
            password=jawsdb_url.password,
            host=jawsdb_url.hostname,
            database=jawsdb_url.path[1:],
            port=jawsdb_url.port
        )
        
    except Error as err:
        print(f"Error: '{err}'")
    return connection

# -------------------------------- user_settings Table -------------------------------- #

@app.route('/save_user_preferences', methods=['POST'])
def save_user_preferences():
    data = request.json
    theme = data.get('theme')
    font = data.get('font')
    
    if not theme or not font:
        return jsonify({'error': 'Theme or Font not provided'}), 400

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Save theme setting
            cursor.execute('SELECT COUNT(*) FROM user_settings WHERE setting_name = "theme"')
            if cursor.fetchone()[0] > 0:
                cursor.execute('UPDATE user_settings SET setting_value = %s WHERE setting_name = "theme"', (theme,))
            else:
                cursor.execute('INSERT INTO user_settings (setting_name, setting_value) VALUES ("theme", %s)', (theme,))

            # Save font setting
            cursor.execute('SELECT COUNT(*) FROM user_settings WHERE setting_name = "font"')
            if cursor.fetchone()[0] > 0:
                cursor.execute('UPDATE user_settings SET setting_value = %s WHERE setting_name = "font"', (font,))
            else:
                cursor.execute('INSERT INTO user_settings (setting_name, setting_value) VALUES ("font", %s)', (font,))

            conn.commit()

        return jsonify({'message': 'User preferences saved successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/get_user_preferences', methods=['GET'])
def get_user_preferences():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        preferences = {'theme': 'Reddit', 'font': 'Helvetica'}  # Default values

        cursor.execute("SELECT setting_name, setting_value FROM user_settings WHERE setting_name IN ('theme', 'font')")
        results = cursor.fetchall()

        for setting_name, setting_value in results:
            if setting_name in preferences:
                preferences[setting_name] = setting_value

        return jsonify(preferences), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()



# ---------------------------------- users Table --------------------------------------- #

@app.route('/is_first_time_setup', methods=['GET'])
def is_first_time_setup():
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM users")
            user_count = cursor.fetchone()[0]
            conn.close()
            return jsonify({'first_time_setup': user_count == 0}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


# Endpoint used in the initial setup to create the first admin account TODO: Remove this endpoint after initial setup or secure it
@app.route('/create_admin_account', methods=['POST'])
def create_admin_account():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    initials = data.get('initials')
    
    # Hash the password for secure storage
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            # Use placeholders (%s) for inserting data safely to avoid SQL injection
            cursor.execute("INSERT INTO users (username, password_hash, user_role, initials, is_temp_password) VALUES (%s, %s, 'admin', %s, 0)", (username, hashed_password, initials))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Admin account created successfully!'}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    current_user_identity = get_jwt_identity()
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_role = data.get('role', 'user')  # Default to 'User' if not provided
    is_temp_password = data.get('is_temp_password', True)
    initials = data.get('initials', '')

    admin_check = is_user_admin(current_user_identity)
    if not admin_check:
        return jsonify({'error': 'Unauthorized - Admin role required'}), 403

    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()

            # Check for username uniqueness
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                conn.close()
                return jsonify({'error': 'Username already exists'}), 400
            
            # Create the new user
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('INSERT INTO users (username, password_hash, user_role, is_temp_password, initials) VALUES (%s, %s, %s, %s, %s)',
                           (username, hashed_password, user_role, is_temp_password, initials))
            conn.commit()
            conn.close()
            return jsonify({'message': 'User added successfully'}), 201
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/update_password', methods=['POST'])
@jwt_required()
def update_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')

    # Hash the new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users
                SET password_hash = %s, is_temp_password = 0
                WHERE username = %s
            ''', (hashed_password, username))
            conn.commit()
            conn.close()
            
            if cursor.rowcount == 0:
                # If no rows were updated, the user does not exist
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/is_admin', methods=['POST'])
def is_admin():
    data = request.json
    username = data.get('username')

    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            # Ensure the query is correctly parameterized to prevent SQL injection
            cursor.execute('SELECT user_role FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            conn.close()
            if result is None:
                return jsonify({'error': 'User not found'}), 404
            # Ensure case-insensitive comparison for 'admin' role
            is_admin = result[0].lower() == 'admin'
            return jsonify({'is_admin': is_admin}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        # Log the error for debugging purposes
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/validate_login', methods=['POST'])
def validate_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

            if user is None:
                return jsonify({'valid': False}), 200

            hashed_password = user[0]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                # Create a token to return upon successful authentication
                access_token = create_access_token(identity=username)
                return jsonify({'valid': True, 'token': access_token}), 200
            else:
                return jsonify({'valid': False}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/needs_password_reset', methods=['POST'])
def needs_password_reset():
    data = request.json
    username = data.get('username')
    
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT is_temp_password FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            conn.close()
            if result is None:
                return jsonify({'error': 'User not found'}), 404  # User not found
            is_temp_password = result[0]
            return jsonify({'needs_reset': bool(is_temp_password)}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_user_initials', methods=['GET'])
@jwt_required()
def get_user_initials():
    username = get_jwt_identity()
    conn = None
    try:
        conn = get_db_connection()
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute('SELECT initials FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            if result is None:
                return jsonify({'error': 'User not found'}), 404
            return jsonify({'initials': result[0]}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/get_all_users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM users")
        users = cursor.fetchall()

        # Extract usernames from the query result
        usernames = [user[0] for user in users]

        return jsonify(usernames), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/remove_user', methods=['POST'])
@jwt_required()
def remove_user():
    # Ensure only admins can remove users
    username = get_jwt_identity()
    if not is_user_admin(username):
        return jsonify({'error': 'Unauthorized: Only admins can remove users.'}), 403

    data = request.get_json()
    username_to_remove = data['username']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users WHERE username = %s", (username_to_remove,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'message': f'User {username_to_remove} has been removed successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# ------------------------------------------- audit_logs Table ----------------------------------- #

def log_action(username, activity, details):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            encrypted_details = encrypt_data(details)
            cursor.execute("INSERT INTO audit_logs (username, activity, details, log_time) VALUES (%s, %s, %s, %s)", 
                           (username, activity, encrypted_details, current_time))
            conn.commit()
            conn.close()
            return True
        else:
            return False
    except Error as e:
        print(f"Database error: {e}")
        return False


@app.route('/log_action', methods=['POST'])
def handle_log_action():
    data = request.json
    username = data.get('username')
    activity = data.get('activity')
    details = data.get('details')
    
    if log_action(username, activity, details):
        return jsonify({"message": "Action logged successfully"}), 200
    else:
        return jsonify({"error": "Failed to log action"}), 500


@app.route('/fetch_audit_logs', methods=['GET'])
@jwt_required()
def fetch_audit_logs():
    last_10_days = request.args.get('last_10_days', type=bool, default=False)
    username = request.args.get('username', default='')
    action = request.args.get('action', default='')
    date = request.args.get('date', default='')

    query = "SELECT log_time, username, activity, details FROM audit_logs WHERE 1=1"
    params = []

    if last_10_days:
        ten_days_ago = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
        query += " AND log_time >= %s"
        params.append(ten_days_ago)

    if username:
        query += " AND username LIKE %s"
        params.append(f"%{username}%")

    if action:
        query += " AND activity = %s"
        params.append(action)

    if date:
        query += " AND DATE(log_time) = %s"
        params.append(date)

    query += " ORDER BY log_time DESC"

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            logs = cursor.fetchall()
            decrypted_logs = [{'date': log[0].strftime('%Y-%m-%d %H:%M:%S'), 'username': log[1], 'action': log[2], 'description': decrypt_data(log[3])} for log in logs]
            return jsonify(decrypted_logs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()

# --------------------------------- residents Table --------------------------------- #

@app.route('/get_resident_count', methods=['GET'])
def get_resident_count():
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM residents')
            count = cursor.fetchone()[0]
            conn.close()
            return jsonify({'count': count}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        print(f"Database error: {e}") # Log the error for debugging purposes
        return jsonify({'error': str(e)}), 500


@app.route('/get_resident_names', methods=['GET'])
@jwt_required()
def get_resident_names():
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM residents')
            names = [row[0] for row in cursor.fetchall()]
            conn.close()
            return jsonify({'names': names}), 200
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_resident_care_level', methods=['GET'])
@jwt_required()
def get_resident_care_level():
    try:
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('SELECT name, level_of_care FROM residents')
            results = cursor.fetchall()
            decrypted_results = []
            for row in results:
                try:
                    decrypted_care_level = decrypt_data(row[1])
                except Exception as decrypt_error:
                    print(f"Error decrypting care level for {row[0]}: {decrypt_error}")
                    decrypted_care_level = "Error"  # or use a default value or skip
                decrypted_results.append({'name': row[0], 'level_of_care': decrypted_care_level})
            return jsonify({'residents': decrypted_results}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/insert_resident', methods=['POST'])
@jwt_required()
def insert_resident():
    data = request.json
    username = get_jwt_identity()
    name = data.get('name')
    date_of_birth = data.get('date_of_birth')
    level_of_care = data.get('level_of_care')

    admin_check = is_user_admin(username)
    if not admin_check:
        return jsonify({'error': 'Unauthorized - Admin role required'}), 403
    
    encrypted_dob = encrypt_data(date_of_birth)
    encrypted_level_of_care = encrypt_data(level_of_care)

    try :
        conn = get_db_connection()
        if conn is not None:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO residents (name, date_of_birth, level_of_care) VALUES (%s, %s, %s)', (name, encrypted_dob, encrypted_level_of_care))
            conn.commit()
            conn.close()
            log_action(username, 'Resident Added', f'Resident Added {name}')
            return jsonify({'message': 'Resident added successfully'}), 201
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/remove_resident', methods=['POST'])
@jwt_required()
def remove_resident():
    data = request.json
    resident_name = data['resident_name']
    username = get_jwt_identity()

    if not is_user_admin(username):
        return jsonify({'error': 'Unauthorized: Only admins can remove residents.'}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        resident_id = get_resident_id(resident_name)
        
        # Begin transaction
        conn.start_transaction()

        # Delete related ADL data
        cursor.execute("DELETE FROM adl_chart WHERE resident_id = %s", (resident_id,))
        
        # Delete related EMAR data
        cursor.execute("DELETE FROM emar_chart WHERE resident_id = %s", (resident_id,))

        # Delete related non-med order administrations
        cursor.execute("DELETE FROM non_med_order_administrations WHERE resident_id = %s", (resident_id,))

        # Delete related non-medication orders
        cursor.execute("DELETE FROM non_medication_orders WHERE resident_id = %s", (resident_id,))

        # Before deleting medications, delete entries from medication_time_slots
        cursor.execute("""
            DELETE mts FROM medication_time_slots mts
            JOIN medications m ON mts.medication_id = m.id
            WHERE m.resident_id = %s
        """, (resident_id,))

        # Delete related medications
        cursor.execute("DELETE FROM medications WHERE resident_id = %s", (resident_id,))

        # Finally, delete the resident
        cursor.execute("DELETE FROM residents WHERE id = %s", (resident_id,))
        
        # Commit transaction
        conn.commit()
        log_action(username, 'Resident Removed', f'Resident Removed {resident_name}')
        return jsonify({'message': f'Resident {resident_name} has been removed successfully'}), 200
    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/fetch_resident_information', methods=['POST'])
def fetch_resident_information():
    data = request.get_json()
    resident_name = data['resident_name']

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, date_of_birth FROM residents WHERE name = %s", (resident_name,))
            result = cursor.fetchone()
            if result:
                name, encrypted_date_of_birth = result
                decrypted_date_of_birth = decrypt_data(encrypted_date_of_birth) if encrypted_date_of_birth else None
                return jsonify({'name': name, 'date_of_birth': decrypted_date_of_birth}), 200
            else:
                return jsonify({'message': 'Resident not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/update_resident_info', methods=['POST'])
@jwt_required()
def update_resident_info():
    data = request.get_json()
    old_name = data['old_name']
    new_name = data['new_name']
    new_dob = data['new_dob']
    
    # Encrypt the new DOB before storing it
    encrypted_new_dob = encrypt_data(new_dob)

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE residents SET name = %s, date_of_birth = %s WHERE name = %s", (new_name, encrypted_new_dob, old_name))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({'error': 'No resident found or data is the same as existing'}), 404
            return jsonify({'message': 'Resident information updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_active_residents', methods=['GET'])
def fetch_active_residents():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM residents WHERE is_active = TRUE")
        active_residents = [row[0] for row in cursor.fetchall()]
        return jsonify(active_residents=active_residents), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/deactivate_resident', methods=['POST'])
@jwt_required()
def deactivate_resident():
    data = request.get_json()
    resident_name = data['resident_name']
    username = get_jwt_identity()

    if not is_user_admin(username):
        return jsonify({'error': 'Unauthorized: Only admins can deactivate residents.'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get resident_id
        resident_id = get_resident_id(resident_name)
        deactivation_date = datetime.now().strftime('%Y-%m-%d')

        # Update the resident's is_active status and set the deactivation_date
        cursor.execute("""
            UPDATE residents
            SET is_active = %s, deactivation_date = %s
            WHERE id = %s
        """, (False, deactivation_date, resident_id))

        conn.commit()
        log_action(username, 'Deactivate Resident', f'Resident {resident_name} deactivated.')
        return jsonify({'message': f'Resident {resident_name} has been successfully deactivated.'}), 200

    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/reactivate_resident', methods=['POST'])
@jwt_required()
def reactivate_resident():
    data = request.get_json()
    resident_name = data['resident_name']
    username = get_jwt_identity()

    if not is_user_admin(username):
        return jsonify({'error': 'Unauthorized: Only admins can reactivate residents.'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get resident_id
        resident_id = get_resident_id(resident_name)

        # Update the resident's is_active status and clear the deactivation_date
        cursor.execute("""
            UPDATE residents
            SET is_active = %s, deactivation_date = NULL
            WHERE id = %s
        """, (True, resident_id))

        conn.commit()
        log_action(username, 'Reactivate Resident', f'Resident {resident_name} reactivated.')
        return jsonify({'message': f'Resident {resident_name} has been successfully reactivated.'}), 200

    except Error as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# ------------------------------------ adl_chart Table ------------------------------------ #

@app.route('/fetch_adl_data_for_resident/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_adl_data_for_resident(resident_name):
    today = datetime.now().strftime("%Y-%m-%d")
    resident_id = get_resident_id(resident_name)

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT * FROM adl_chart
                WHERE resident_id = %s AND chart_date = %s
            ''', (resident_id, today))
            result = cursor.fetchone()
            if result:
                columns = [col[0] for col in cursor.description]
                adl_data = {columns[i]: result[i] for i in range(3, len(columns))}
                return jsonify(adl_data), 200
            else:
                # Instead of returning an error, return an empty dictionary
                return jsonify({}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/fetch_adl_chart_data_for_month/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_adl_chart_data_for_month(resident_name):
    # Extract 'year_month' from query parameters
    year_month = request.args.get('year_month', '')
    # Validate 'year_month' format
    try:
        datetime.strptime(year_month, "%Y-%m")
    except ValueError:
        return jsonify({'error': 'Invalid year_month format. Use YYYY-MM.'}), 400

    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    print('resident_id:', resident_id, 'year_month:', year_month)

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Adjust SQL query for MySQL and use LIKE for partial date matching
            cursor.execute('''
                SELECT * FROM adl_chart
                WHERE resident_id = %s AND DATE_FORMAT(chart_date, '%Y-%m') = %s
                ORDER BY chart_date
            ''', (resident_id, year_month))
            results = cursor.fetchall()
            if results:
                columns = [col[0] for col in cursor.description]
                # Convert each row into a dictionary
                adl_data = [{columns[i]: row[i] for i in range(len(columns))} for row in results]
                return jsonify(adl_data), 200
            else:
                return jsonify([]), 200  # Return an empty list if no data found
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/save_adl_data_from_management_window', methods=['POST'])
@jwt_required()
def save_adl_data_from_management_window():
    # Assuming you're receiving JSON data including the resident_name and adl_data
    request_data = request.get_json()
    resident_name = request_data['resident_name']
    adl_data = request_data['adl_data']
    audit_description = request_data['audit_description']
    
    # Convert empty strings to None (or a default value) for integer fields
    integer_fields = ['breakfast', 'lunch', 'dinner', 'snack_am', 'snack_pm', 'water_intake']
    for field in integer_fields:
        if adl_data.get(field, '') == '':
            adl_data[field] = None  # or use a default value like 0


    resident_id = get_resident_id(resident_name)
    today = datetime.now().strftime("%Y-%m-%d")

    if resident_id is None:
        return jsonify({'error': 'Resident not found'}), 404

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            
            sql = '''
                INSERT INTO adl_chart (resident_id, chart_date, first_shift_sp, second_shift_sp, 
                first_shift_activity1, first_shift_activity2, first_shift_activity3, second_shift_activity4, 
                first_shift_bm, second_shift_bm, shower, shampoo, sponge_bath, peri_care_am, 
                peri_care_pm, oral_care_am, oral_care_pm, nail_care, skin_care, shave, 
                breakfast, lunch, dinner, snack_am, snack_pm, water_intake)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                first_shift_sp = VALUES(first_shift_sp), second_shift_sp = VALUES(second_shift_sp), 
                first_shift_activity1 = VALUES(first_shift_activity1), first_shift_activity2 = VALUES(first_shift_activity2),
                first_shift_activity3 = VALUES(first_shift_activity3), second_shift_activity4 = VALUES(second_shift_activity4),
                first_shift_bm = VALUES(first_shift_bm), second_shift_bm = VALUES(second_shift_bm), shower = VALUES(shower),
                shampoo = VALUES(shampoo), sponge_bath = VALUES(sponge_bath), peri_care_am = VALUES(peri_care_am), 
                peri_care_pm = VALUES(peri_care_pm), oral_care_am = VALUES(oral_care_am), oral_care_pm = VALUES(oral_care_pm),
                nail_care = VALUES(nail_care), skin_care = VALUES(skin_care), shave = VALUES(shave), breakfast = VALUES(breakfast),
                lunch = VALUES(lunch), dinner = VALUES(dinner), snack_am = VALUES(snack_am), snack_pm = VALUES(snack_pm),
                water_intake = VALUES(water_intake)
            '''

            data_tuple = (
                resident_id, 
                today,
                adl_data.get('first_shift_sp', ''),
                adl_data.get('second_shift_sp', ''),
                adl_data.get('first_shift_activity1', ''),
                adl_data.get('first_shift_activity2', ''),
                adl_data.get('first_shift_activity3', ''),
                adl_data.get('second_shift_activity4', ''),
                adl_data.get('first_shift_bm', ''),
                adl_data.get('second_shift_bm', ''),
                adl_data.get('shower', ''),
                adl_data.get('shampoo', ''),
                adl_data.get('sponge_bath', ''),
                adl_data.get('peri_care_am', ''),
                adl_data.get('peri_care_pm', ''),
                adl_data.get('oral_care_am', ''),
                adl_data.get('oral_care_pm', ''),
                adl_data.get('nail_care', ''),
                adl_data.get('skin_care', ''),
                adl_data.get('shave', ''),
                adl_data.get('breakfast', ''),
                adl_data.get('lunch', ''),
                adl_data.get('dinner', ''),
                adl_data.get('snack_am', ''),
                adl_data.get('snack_pm', ''),
                adl_data.get('water_intake', '')
            )
            cursor.execute(sql, data_tuple)
            conn.commit()
            log_action(get_jwt_identity(), 'ADL Data Update', audit_description)
            return jsonify({'message': 'ADL data saved successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/does_adl_chart_exist/<resident_name>/<year_month>', methods=['GET'])
def does_adl_chart_data_exist(resident_name, year_month):
    resident_id = get_resident_id(resident_name)
    if resident_id is None:
        return jsonify({'error': f"Resident named {resident_name} not found"}), 404

    year, month = year_month.split('-')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = '''
            SELECT EXISTS(
                SELECT 1 FROM adl_chart ac
                WHERE ac.resident_id = %s 
                AND YEAR(ac.chart_date) = %s 
                AND MONTH(ac.chart_date) = %s
            )
        '''
        cursor.execute(query, (resident_id, year, month))
        exists = cursor.fetchone()[0]
        return jsonify({'exists': bool(exists)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/save_adl_data_from_chart', methods=['POST'])
@jwt_required()
def save_adl_data_from_chart():
    data = request.json
    resident_name = data['resident_name']
    adl_data_list = data['adl_data']  # List of dictionaries with 'chart_date' and 'data'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get resident ID
        resident_id = get_resident_id(resident_name)

        for adl_data in adl_data_list:
            chart_date = adl_data['chart_date']
            data_dict = adl_data['data']

            # Construct the SQL statement dynamically based on the data keys
            keys = data_dict.keys()
            values_placeholder = ', '.join(['%s'] * (len(keys) + 2))  # +2 for resident_id and chart_date
            columns = ', '.join(keys)
            update_clause = ', '.join([f"{key} = VALUES({key})" for key in keys])

            sql = f'''
                INSERT INTO adl_chart (resident_id, chart_date, {columns})
                VALUES ({values_placeholder})
                ON DUPLICATE KEY UPDATE {update_clause}
            '''

            values = [resident_id, chart_date] + list(data_dict.values())
            cursor.execute(sql, values)

        conn.commit()
        return jsonify({'message': 'ADL data saved successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()



# -------------------------------------- medications Table ----------------------------------- #

@app.route('/insert_medication', methods=['POST'])
@jwt_required()
def insert_medication():
    # Extract medication details from the request body
    data = request.get_json()
    resident_name = data.get('resident_name')
    medication_name = data.get('medication_name')
    dosage = data.get('dosage')
    instructions = data.get('instructions')
    medication_type = data.get('medication_type')
    selected_time_slots = data.get('selected_time_slots')
    medication_form = data.get('medication_form', None)
    count = data.get('count', None)
    current_user_identity = get_jwt_identity()

    admin_check = is_user_admin(current_user_identity)
    if not admin_check:
        return jsonify({'error': 'Unauthorized - Admin role required'}), 403

    resident_id = get_resident_id(resident_name)
    if resident_id is None:
        return jsonify({'error': 'Resident not found'}), 404

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Encrypt PHI fields
        encrypted_dosage = encrypt_data(dosage) 
        encrypted_instructions = encrypt_data(instructions)  

        # Insert medication details
        if medication_type == 'Controlled':
            cursor.execute('''
                INSERT INTO medications (resident_id, medication_name, dosage, instructions, medication_type, medication_form, count) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (resident_id, medication_name, encrypted_dosage, encrypted_instructions, medication_type, medication_form, count))
        else:
            cursor.execute('''
                INSERT INTO medications (resident_id, medication_name, dosage, instructions, medication_type) 
                VALUES (%s, %s, %s, %s, %s)
            ''', (resident_id, medication_name, encrypted_dosage, encrypted_instructions, medication_type))
        medication_id = cursor.lastrowid

        # Handle time slot relations for scheduled medications
        if medication_type == 'Scheduled':
            for slot in selected_time_slots:
                cursor.execute('SELECT id FROM time_slots WHERE slot_name = %s', (slot,))
                slot_id = cursor.fetchone()[0]
                cursor.execute('INSERT INTO medication_time_slots (medication_id, time_slot_id) VALUES (%s, %s)', (medication_id, slot_id))

        conn.commit()
        log_action(current_user_identity, 'Medication Added', f'Medication Added {medication_name} for {resident_name}')
        return jsonify({'message': 'Medication inserted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/fetch_discontinued_medications/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_discontinued_medications(resident_name):
    resident_id = get_resident_id(resident_name)
    
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Fetch discontinued medications
            cursor.execute('''
                SELECT medication_name, discontinued_date FROM medications 
                WHERE resident_id = %s AND discontinued_date IS NOT NULL
            ''', (resident_id,))
            results = cursor.fetchall()

        discontinued_medications = {row[0]: row[1] for row in results}

        return jsonify(discontinued_medications), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_medications_for_resident/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_medications_for_resident(resident_name):
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch Scheduled Medications
    cursor.execute("""
        SELECT m.medication_name, m.dosage, m.instructions, ts.slot_name
        FROM medications m
        JOIN medication_time_slots mts ON m.id = mts.medication_id
        JOIN time_slots ts ON mts.time_slot_id = ts.id
        WHERE m.resident_id = %s AND m.medication_type = 'Scheduled'
    """, (resident_id,))
    scheduled_results = cursor.fetchall()

    scheduled_medications = {}
    for med_name, dosage, instructions, time_slot in scheduled_results:
        # Assuming decrypt_data is a function that decrypts the data
        decrypted_dosage = decrypt_data(dosage)
        decrypted_instructions = decrypt_data(instructions)
        if time_slot not in scheduled_medications:
            scheduled_medications[time_slot] = {}
        scheduled_medications[time_slot][med_name] = {
            'dosage': decrypted_dosage, 'instructions': decrypted_instructions}

    # Fetch PRN Medications
    cursor.execute("""
        SELECT medication_name, dosage, instructions
        FROM medications 
        WHERE resident_id = %s AND medication_type = 'As Needed (PRN)'
    """, (resident_id,))
    prn_results = cursor.fetchall()

    prn_medications = {med_name: {'dosage': decrypt_data(dosage), 'instructions': decrypt_data(instructions)} 
        for med_name, dosage, instructions in prn_results}

    # Fetch Controlled Medications
    cursor.execute("""
        SELECT medication_name, dosage, instructions, count, medication_form
        FROM medications 
        WHERE resident_id = %s AND medication_type = 'Controlled'
    """, (resident_id,))
    controlled_results = cursor.fetchall()

    controlled_medications = {med_name: {'dosage': decrypt_data(dosage), 'instructions': decrypt_data(instructions), 'count': count, 'form': medication_form} 
        for med_name, dosage, instructions, count, medication_form in controlled_results}

    # Combine the data into a single structure
    medications_data = {'Scheduled': scheduled_medications, 'PRN': prn_medications, 'Controlled': controlled_medications}
    
    cursor.close()
    conn.close()
    
    return jsonify(medications_data)


# @app.route('/filter_active_medications', methods=['POST'])
# @jwt_required()
# def filter_active_medications():
#     # Assuming you're receiving a list of medication names and a resident name in the request JSON
#     data = request.get_json()
#     medication_names = data.get('medication_names', [])
#     resident_name = data.get('resident_name', '')
#     active_medications = []

#     try:
#         conn = get_db_connection()
#         if conn is not None:
#             with conn.cursor() as cursor:
#                 for med_name in medication_names:
#                     cursor.execute('''
#                         SELECT discontinued_date FROM medications
#                         JOIN residents ON medications.resident_id = residents.id
#                         WHERE residents.name = %s AND medications.medication_name = %s
#                     ''', (resident_name, med_name))
#                     result = cursor.fetchone()

#                     # Check if the medication is discontinued and if the discontinuation date is past the current date
#                     if result is None or (result[0] is None or datetime.now().date() < result[0]):
#                         active_medications.append(med_name)

#             return jsonify(active_medications=active_medications), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
#     finally:
#         if conn.is_connected():
#             conn.close()

@app.route('/filter_active_medications', methods=['POST'])
@jwt_required()
def filter_active_medications():
    data = request.get_json()
    medication_names = data.get('medication_names', [])
    resident_name = data.get('resident_name', '')
    active_medications = []

    if not medication_names:
        # If no medication names are provided, return an empty list immediately
        return jsonify(active_medications=[]), 200

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Build the IN clause dynamically based on the number of medication names
            in_placeholders = ', '.join(['%s'] * len(medication_names))
            query = '''
                SELECT medication_name, discontinued_date FROM medications
                JOIN residents ON medications.resident_id = residents.id
                WHERE residents.name = %s AND medications.medication_name IN ({})
            '''.format(in_placeholders)
            params = [resident_name] + medication_names
            cursor.execute(query, params)
            results = cursor.fetchall()

            # Check if the medication is discontinued and if the discontinuation date is past the current date
            for result in results:
                med_name, discontinued_date = result
                if discontinued_date is None or datetime.now().date() < discontinued_date:
                    active_medications.append(med_name)

        return jsonify(active_medications=active_medications), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()



@app.route('/fetch_all_non_medication_orders_for_resident/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_all_non_medication_orders_for_resident(resident_name):
    resident_id = get_resident_id(resident_name)
    if resident_id is None:
        return jsonify({'error': 'Resident not found'}), 404

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  # Use dictionary=True to get the results as dictionaries

        cursor.execute('''
            SELECT order_id, order_name, frequency, specific_days, special_instructions, discontinued_date, last_administered_date
            FROM non_medication_orders
            WHERE resident_id = %s
        ''', (resident_id,))
        orders = cursor.fetchall()

        if not orders:
            return jsonify({'message': 'No non-medication orders found for the specified resident'}), 200

        # The results are already dictionaries, so you can directly return them
        return jsonify({'non_medication_orders': orders}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/get_controlled_medication_details/<resident_name>/<medication_name>', methods=['GET'])
@jwt_required()
def get_controlled_medication_details(resident_name, medication_name):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        resident_id = get_resident_id(resident_name)

        # Fetch the count and form for the specified controlled medication
        cursor.execute('''
            SELECT count, medication_form FROM medications 
            WHERE resident_id = %s AND medication_name = %s AND medication_type = 'Controlled'
        ''', (resident_id, medication_name))
        result = cursor.fetchone()

        if result is None:
            return jsonify({'error': 'Medication not found or not a controlled type'}), 404

        medication_count, medication_form = result
        return jsonify({'count': medication_count, 'form': medication_form}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/discontinue_medication', methods=['POST'])
@jwt_required()
def discontinue_medication():
    data = request.get_json()
    resident_name = data['resident_name']
    medication_name = data['medication_name']
    discontinued_date = data['discontinued_date']
    print(f'Discontinuing medication {medication_name} for {resident_name} as of {discontinued_date}')

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Get the resident ID
            resident_id = get_resident_id(resident_name)

            # Update the medication record with the discontinued date
            sql = '''
                UPDATE medications 
                SET discontinued_date = %s
                WHERE resident_id = %s AND medication_name = %s
            '''
            #print(f'Executing SQL: {sql} with {discontinued_date}, {resident_id}, {medication_name}')
            cursor.execute(sql, (discontinued_date, resident_id, medication_name))
            conn.commit()

        return jsonify({'message': f"Medication '{medication_name}' has been discontinued as of {discontinued_date}."}), 200
    except Exception as e:
        conn.rollback()
        print(f"SQL Error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_medication_details/<resident_name>/<medication_name>', methods=['GET'])
@jwt_required()
def fetch_medication_details(resident_name, medication_name):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            resident_id = get_resident_id(resident_name)

            # Fetch medication details
            cursor.execute("SELECT medication_name, dosage, instructions FROM medications WHERE medication_name = %s AND resident_id = %s", (medication_name, resident_id))
            result = cursor.fetchone()
            if result:
                medication_details = {'medication_name': result[0], 'dosage': result[1], 'instructions': result[2]}
                return jsonify(medication_details), 200
            else:
                return jsonify({'error': 'Medication not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/update_medication_details/<resident_name>', methods=['POST'])
@jwt_required()
def update_medication_details(resident_name):
    data = request.get_json()
    old_name = data['old_name']
    new_name = data['new_name']
    new_dosage = encrypt_data(data['new_dosage'])
    new_instructions = encrypt_data(data['new_instructions'])

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            resident_id = get_resident_id(resident_name)
            if not resident_id:
                return jsonify({'error': 'Resident not found'}), 404

            sql = '''
                UPDATE medications
                SET medication_name = %s, dosage = %s, instructions = %s
                WHERE medication_name = %s AND resident_id = %s
            '''
            cursor.execute(sql, (new_name, new_dosage, new_instructions, old_name, resident_id))
            conn.commit()

        return jsonify({'message': 'Medication details updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


# -------------------------------------- non_medication_orders Table ------------------------------------- #

@app.route('/add_non_medication_order/<resident_name>', methods=['POST'])
@jwt_required()
def save_non_medication_order(resident_name):
    data = request.get_json()
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    # Required fields
    order_name     = data.get('order_name', '').strip()
    instructions   = data.get('instructions', '').strip()

    # Scheduling fields
    frequency      = data.get('frequency', '')         # can be '' if using specific_days
    specific_days  = data.get('specific_days', '')     # can be '' if using frequency
    times_per_day  = data.get('times_per_day', 1)      # new field

    # Validate
    if not order_name:
        return jsonify({'error': 'Order name is required'}), 400

    try:
        # Ensure times_per_day is a positive integer
        times_per_day = int(times_per_day)
        if times_per_day < 1:
            raise ValueError()
    except ValueError:
        return jsonify({'error': 'times_per_day must be a positive integer'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO non_medication_orders
              (resident_id, order_name, frequency, specific_days,
               times_per_day, special_instructions)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (
            resident_id,
            order_name,
            frequency,
            specific_days,
            times_per_day,
            instructions
        ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    # Audit log
    log_action(
        get_jwt_identity(),
        'Add Non-Medication Order',
        f'Order for {resident_name}: {order_name} ' +
        f'(every {frequency or "N/A"} days on {specific_days or "all days"}, ' +
        f'{times_per_day}×/day)'
    )

    return jsonify({'message': 'Non-medication order added successfully'}), 200


# @app.route('/fetch_non_medication_orders/<resident_name>', methods=['GET'])
# @jwt_required()
# def fetch_all_non_medication_orders(resident_name):
#     resident_id = get_resident_id(resident_name)
#     if not resident_id:
#         return jsonify({'error': f'Resident {resident_name} not found'}), 404

#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     try:
#         cursor.execute('''
#             SELECT
#                 order_id,
#                 order_name,
#                 frequency,
#                 specific_days,
#                 times_per_day,                   -- <-- include new column
#                 special_instructions,
#                 discontinued_date,
#                 last_administered_date
#             FROM non_medication_orders
#             WHERE resident_id = %s
#         ''', (resident_id,))
#         orders = cursor.fetchall()

#         non_medication_orders = []
#         for order in orders:
#             non_medication_orders.append({
#                 'order_id': order['order_id'],
#                 'order_name': order['order_name'],
#                 'frequency': order['frequency'],
#                 'specific_days': order['specific_days'],
#                 'times_per_day': order['times_per_day'],       # <-- new field here
#                 'special_instructions': order['special_instructions'],
#                 'discontinued_date': (order['discontinued_date']
#                                       if order['discontinued_date'] else None),
#                 'last_administered_date': (order['last_administered_date']
#                                            if order['last_administered_date'] else None),
#             })

#         return jsonify(non_medication_orders), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

#     finally:
#         cursor.close()
#         conn.close()
@app.route('/fetch_non_medication_orders/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_all_non_medication_orders(resident_name):
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT
              o.order_id,
              o.order_name,
              o.frequency,
              o.specific_days,
              o.times_per_day,
              o.special_instructions,
              o.discontinued_date,
              o.last_administered_date,
              -- subquery to count today’s runs
              COALESCE((
                SELECT COUNT(*) 
                FROM non_med_order_administrations a
                WHERE a.order_id = o.order_id
                  AND a.administration_date = CURDATE()
              ),0) AS done_today
            FROM non_medication_orders AS o
            WHERE o.resident_id = %s;
        ''', (resident_id,))

        orders = cursor.fetchall()
        return jsonify(orders), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------------------------------- non_med_order_administrations Table ------------------------------------- #

@app.route('/record_non_med_order_performance', methods=['POST'])
@jwt_required()
def record_non_med_order_performance():
    current_user = get_jwt_identity()
    data = request.get_json()
    order_name = data['order_name']
    resident_name = data['resident_name']
    notes = data['notes']
    initials = data['initials']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        resident_id = get_resident_id(resident_name)
        cursor.execute("SELECT order_id FROM non_medication_orders WHERE order_name = %s AND resident_id = %s", (order_name, resident_id))
        order_result = cursor.fetchone()
        if not order_result:
            return jsonify({"error": "Order not found"}), 404
        order_id = order_result[0]

        current_date = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("INSERT INTO non_med_order_administrations (order_id, resident_id, administration_date, notes, initials) VALUES (%s, %s, %s, %s, %s)", (order_id, resident_id, current_date, notes, initials))
        cursor.execute("UPDATE non_medication_orders SET last_administered_date = %s WHERE order_id = %s", (current_date, order_id))

        conn.commit()
        return jsonify({"message": "Non-medication order performance recorded successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/fetch_non_med_orders_for_resident', methods=['POST'])
@jwt_required()
def fetch_non_med_orders_for_resident():
    data = request.get_json()
    resident_name = data['resident_name']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch resident_id using the helper function
        resident_id = get_resident_id(resident_name)

        # Execute the query using the resident_id
        cursor.execute('''
            SELECT non_medication_orders.order_name, non_med_order_administrations.administration_date, non_med_order_administrations.notes, non_med_order_administrations.initials
            FROM non_medication_orders
            JOIN non_med_order_administrations ON non_medication_orders.order_id = non_med_order_administrations.order_id
            WHERE non_medication_orders.resident_id = %s
            ORDER BY non_med_order_administrations.administration_date DESC
        ''', (resident_id,))
        orders = cursor.fetchall()

        non_med_orders = {}
        for row in orders:
            order_name = row[0]
            if order_name not in non_med_orders:
                non_med_orders[order_name] = []
            non_med_orders[order_name].append([row[1], row[2], row[3]])

        non_med_orders_list = [{'order_name': order_name, 'details': details} for order_name, details in non_med_orders.items()]
        return jsonify(non_med_orders=non_med_orders_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# ------------------------------------------- emar_chart Table ---------------------------------------------------- #

@app.route('/fetch_emar_data_for_resident/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_emar_data_for_resident(resident_name):
    today = datetime.now().strftime("%Y-%m-%d")
    resident_id = get_resident_id(resident_name)
    
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Fetch eMAR data for the resident for today
            cursor.execute("""
                SELECT m.medication_name, e.time_slot, e.administered
                FROM emar_chart e
                JOIN medications m ON e.medication_id = m.id
                WHERE e.resident_id = %s AND e.chart_date = %s
            """, (resident_id, today))
            
            results = cursor.fetchall()

        # Organize eMAR data by medication name and time slot
        emar_data = {}
        for med_name, time_slot, administered in results:
            if med_name not in emar_data:
                emar_data[med_name] = {}
            emar_data[med_name][time_slot] = administered

        return jsonify(emar_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_emar_data_for_resident_audit_log/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_emar_data_for_resident_audit_log(resident_name):
    today = datetime.now().strftime("%Y-%m-%d")
    resident_id = get_resident_id(resident_name)
    
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT m.medication_name, e.time_slot, e.administered, e.chart_date
                FROM emar_chart e
                JOIN medications m ON e.medication_id = m.id
                WHERE e.resident_id = %s AND e.chart_date = %s
            """, (resident_id, today))
            
            results = cursor.fetchall()

        # Format the data similarly to the old SQLite function's output
        emar_data = [{'resident_name': resident_name, 
                      'medication_name': result[0], 
                      'time_slot': result[1], 
                      'administered': result[2], 
                      'date': result[3]} for result in results]

        return jsonify(emar_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/fetch_emar_data_for_month/<resident_name>/<year_month>', methods=['GET'])
@jwt_required()
def fetch_emar_data_for_month_simplified(resident_name, year_month):
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    year, month = year_month.split('-')

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = """
                SELECT m.medication_name, e.chart_date, e.time_slot, e.administered
                FROM emar_chart e
                JOIN medications m ON e.medication_id = m.id
                WHERE e.resident_id = %s AND YEAR(e.chart_date) = %s AND MONTH(e.chart_date) = %s
                ORDER BY e.chart_date, e.time_slot
            """
            cursor.execute(query, (resident_id, year, month))
            results = cursor.fetchall()

            emar_data = [{'medication_name': row[0], 'chart_date': row[1].strftime('%Y-%m-%d'), 'time_slot': row[2], 'administered': row[3]} for row in results]

            return jsonify(emar_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/save_emar_data', methods=['POST'])
@jwt_required()
def save_emar_data_from_management_window():
    request_data = request.json
    emar_data = request_data.get('emar_data', [])
    audit_description = request_data.get('audit_description', '')
    responses = []

    # Get the username from JWT
    username = get_jwt_identity()

    for entry in emar_data:
        resident_id = get_resident_id(entry['resident_name'])
        if not resident_id:
            responses.append({'status': 'error', 'message': f"Resident {entry['resident_name']} not found"})
            continue

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT id FROM medications WHERE resident_id = %s AND medication_name = %s", 
                           (resident_id, entry['medication_name']))
            medication_id_result = cursor.fetchone()
            
            if medication_id_result is None:
                responses.append({'status': 'error', 'message': f"Medication {entry['medication_name']} for resident {entry['resident_name']} not found"})
                continue

            medication_id = medication_id_result['id']

            sql = """
                INSERT INTO emar_chart (resident_id, medication_id, chart_date, time_slot, administered, current_count, notes)
                VALUES (%s, %s, %s, %s, %s, NULL, '')
                ON DUPLICATE KEY UPDATE administered = VALUES(administered)
            """
            cursor.execute(sql, (resident_id, medication_id, entry['date'], entry['time_slot'], entry['administered']))
            conn.commit()
            responses.append({'status': 'success', 'message': 'Data saved successfully'})
        except mysql.connector.Error as err:
            conn.rollback()
            responses.append({'status': 'error', 'message': str(err)})
        finally:
            cursor.close()
            conn.close()
    # Log the action with audit description
    if audit_description:
        log_action(username, "EMAR Data Update", audit_description)

    return jsonify(responses)


@app.route('/does_emars_chart_exist/<resident_name>/<year_month>', methods=['GET'])
def does_emars_chart_data_exist(resident_name, year_month):
    resident_id = get_resident_id(resident_name)
    if resident_id is None:
        return jsonify({'error': f"Resident named {resident_name} not found"}), 404

    year, month = year_month.split('-')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = '''
            SELECT EXISTS(
                SELECT 1 FROM emar_chart
                WHERE resident_id = %s 
                AND YEAR(chart_date) = %s 
                AND MONTH(chart_date) = %s
            )
        '''
        print(f"Executing eMARs existence check with resident_id: {resident_id}, year: {year}, month: {month}")
        cursor.execute(query, (resident_id, year, month))
        exists = cursor.fetchone()[0]
        return jsonify({'exists': bool(exists)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/save_prn_administration', methods=['POST'])
@jwt_required()
def save_prn_administration_data():
    data = request.json
    resident_name = data['resident_name']
    medication_name = data['medication_name']
    admin_data = data['admin_data']
    username = get_jwt_identity()

    # Extracting date and time from the 'datetime' string
    admin_date, admin_time = admin_data['datetime'].split(' ')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve resident ID and medication ID
        cursor.execute("SELECT id FROM residents WHERE name = %s", (resident_name,))
        resident_id_result = cursor.fetchone()
        if not resident_id_result:
            return jsonify({'error': 'Resident not found'}), 404

        resident_id = resident_id_result[0]

        cursor.execute("SELECT id FROM medications WHERE medication_name = %s AND resident_id = %s", (medication_name, resident_id))
        medication_id_result = cursor.fetchone()
        if not medication_id_result:
            return jsonify({'error': 'Medication not found'}), 404

        medication_id = medication_id_result[0]

        # Insert administration data into emar_chart, including chart_time
        cursor.execute('''
            INSERT INTO emar_chart (resident_id, medication_id, chart_date, chart_time, administered, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (resident_id, medication_id, admin_date, admin_time, admin_data['administered'], admin_data['notes']))

        conn.commit()

        # Formatting the date and time for the log message
        # Assuming 'admin_date' and 'admin_time' are in 'YYYY-MM-DD' and 'HH:MM' formats respectively
        datetime_str = f"{admin_date} {admin_time}" if admin_time else admin_date
        log_message = f"PRN Administered {medication_name} to {resident_name} at {datetime_str}"
        
        log_action(username, 'PRN Administration', log_message)
        
        return jsonify({'message': 'Administration data saved successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_prn_data_for_day/<resident_name>/<medication_name>/<year_month>/<day>', methods=['GET'])
@jwt_required()
def fetch_prn_data_for_day(resident_name, medication_name, year_month, day):
    day = day.zfill(2)  # Ensure day is two digits
    date_query = f'{year_month}-{day}'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Use TIME_FORMAT to convert chart_time to a string within the SQL query
        query = '''
            SELECT e.chart_date, TIME_FORMAT(e.chart_time, '%H:%i') AS formatted_time, e.administered, e.notes
            FROM emar_chart e
            JOIN residents r ON e.resident_id = r.id
            JOIN medications m ON e.medication_id = m.id
            WHERE r.name = %s AND m.medication_name = %s AND e.chart_date LIKE %s
        '''
        cursor.execute(query, (resident_name, medication_name, date_query + '%'))
        result = cursor.fetchall()

        # Now, formatted_time is directly usable as a string
        prn_data = [{'date': row[0].strftime('%Y-%m-%d') + ' ' + (row[1] if row[1] else ''), 'administered': row[2], 'notes': row[3]} for row in result]
        return jsonify(prn_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_monthly_medication_data/<resident_name>/<medication_name>/<year_month>/<medication_type>', methods=['GET'])
@jwt_required()
def fetch_monthly_medication_data(resident_name, medication_name, year_month, medication_type):
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch medication ID
        cursor.execute("SELECT id FROM medications WHERE medication_name = %s AND resident_id = %s", (medication_name, resident_id))
        medication_id_result = cursor.fetchone()
        if not medication_id_result:
            return jsonify({'error': 'Medication not found'}), 404
        medication_id = medication_id_result[0]

        # Query for the entire month
        year, month = year_month.split('-')
        start_date = f"{year}-{month}-01"
        end_date = f"{year}-{month}-{calendar.monthrange(int(year), int(month))[1]}"

        query = """
            SELECT e.chart_date, TIME_FORMAT(e.chart_time, '%H:%i') AS formatted_time, e.administered, e.notes
            FROM emar_chart e
            WHERE e.resident_id = %s AND e.medication_id = %s AND e.chart_date BETWEEN %s AND %s
            ORDER BY e.chart_date, e.chart_time
        """
        cursor.execute(query, (resident_id, medication_id, start_date, end_date))

        results = cursor.fetchall()
        medication_data = [{'date': row[0].strftime('%Y-%m-%d') + ' ' + row[1], 'administered': row[2], 'notes': row[3]} for row in results]

        return jsonify(medication_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/save_controlled_administration', methods=['POST'])
@jwt_required()
def save_controlled_administration():
    data = request.get_json()
    resident_name = data['resident_name']
    medication_name = data['medication_name']
    admin_data = data['admin_data']
    new_count = data['new_count']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Ensure autocommit is disabled to manage transactions manually
        conn.autocommit = False

        # Retrieve resident ID and medication ID
        resident_id = get_resident_id(resident_name)

        cursor.execute("SELECT id FROM medications WHERE medication_name = %s AND resident_id = %s", (medication_name, resident_id))
        medication_id_result = cursor.fetchone()
        if medication_id_result is None:
            return jsonify({'error': 'Medication not found'}), 404
        medication_id = medication_id_result[0]

        # Insert administration data into emar_chart, including the new count
        cursor.execute('''
            INSERT INTO emar_chart (resident_id, medication_id, chart_date, administered, notes, current_count)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (resident_id, medication_id, admin_data['datetime'], admin_data['administered'], admin_data['notes'], new_count))

        # Update medication count in medications table
        cursor.execute('''
            UPDATE medications
            SET count = %s
            WHERE id = %s
        ''', (new_count, medication_id))

        # Commit transaction
        conn.commit()
        return jsonify({'message': 'Controlled medication administration data saved successfully'}), 200

    except Exception as e:
        if conn.is_connected():
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/save_emar_data_from_chart', methods=['POST'])
@jwt_required()
def save_emar_data_from_chart():
    data = request.get_json()
    resident_name = data['resident_name']
    emar_data = data['emar_data']

    try:
        conn = get_db_connection()

        # Retrieve resident ID
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM residents WHERE name = %s", (resident_name,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Resident not found'}), 404
            resident_id = result[0]
            # Clear any remaining results to prevent "Unread result found" error
            while cursor.nextset():
                pass

        for entry in emar_data:
            if entry.get('administered') == 'ADM':  # Skip 'ADM' entries
                continue

            with conn.cursor() as cursor:
                medication_name = entry['medication_name']
                cursor.execute("SELECT id FROM medications WHERE medication_name = %s", (medication_name,))
                med_result = cursor.fetchone()
                # Clear any remaining results to prevent "Unread result found" error
                while cursor.nextset():
                    pass
                if not med_result:
                    continue  # Skip if medication not found
                medication_id = med_result[0]

                sql = '''
                    INSERT INTO emar_chart (resident_id, medication_id, chart_date, time_slot, administered)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE administered = VALUES(administered)
                '''
                cursor.execute(sql, (resident_id, medication_id, entry['chart_date'], entry['time_slot'], entry['administered']))
                conn.commit()

        return jsonify({'message': 'eMAR data saved successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()




# ----------------------------------- activities Table ------------------------------------ #

@app.route('/fetch_activities', methods=['GET'])
def fetch_activities():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT activity_name FROM activities')
        activities = [row[0] for row in cursor.fetchall()]
        return jsonify({'activities': activities}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/add_activity', methods=['POST'])
def add_activity():
    try:
        activity_name = request.json['activity_name']
        if not activity_name:
            return jsonify({'error': 'Activity name is required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO activities (activity_name) VALUES (%s)', (activity_name,))
        conn.commit()

        return jsonify({'message': 'Activity added successfully'}), 201
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/remove_activity', methods=['POST'])
def remove_activity():
    data = request.get_json()
    activity_name = data.get('activity_name')
    if not activity_name:
        return jsonify({'error': 'Activity name is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM activities WHERE activity_name = %s', (activity_name,))
        conn.commit()
        return jsonify({'message': f'Activity "{activity_name}" removed successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()

# --------------------------------- meals Table ------------------------------------ #

@app.route('/fetch_meal_data/<meal_type>', methods=['GET'])
def fetch_meal_data(meal_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Safely query the database with the provided meal_type
        query = 'SELECT meal_option, default_drink FROM meals WHERE meal_type = %s'
        cursor.execute(query, (meal_type,))
        meals = cursor.fetchall()
        
        processed_meals = []
        for meal_option, default_drink in meals:
            # Split the meal_option by '; ' to recreate the list
            options = [option.strip(' ;') for option in meal_option.split('; ')]
            # Append default_drink for breakfast meals, ensuring no trailing semicolon
            if meal_type == 'breakfast' and default_drink:
                options.append(default_drink.strip(' ;'))
            processed_meals.append(options)
        
        # Return the processed meals as a JSON response
        return jsonify({'meals': processed_meals})
    except Exception as e:
        # Handle exceptions and return an error message
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/fetch_raw_meal_data/<meal_type>', methods=['GET'])
def fetch_raw_meal_data(meal_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Fetch meal_option and, for breakfast, also default_drink
        query = 'SELECT meal_option, default_drink FROM meals WHERE meal_type = %s'
        cursor.execute(query, (meal_type,))
        meals = cursor.fetchall()
        
        # Process meals to include default_drink for breakfast
        raw_meals = []
        for meal_option, default_drink in meals:
            if meal_type == 'breakfast' and default_drink:
                # Concatenate default_drink with meal_option for breakfast
                raw_meal = f'{meal_option} {default_drink}'
            else:
                # Use meal_option as is for lunch and dinner
                raw_meal = meal_option
            raw_meals.append(raw_meal)
        
        # Return the raw meals as a JSON response
        return jsonify({'meals': raw_meals})
    except Exception as e:
        # Handle exceptions and return an error message
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()



@app.route('/add_meal', methods=['POST'])
def add_meal():
    data = request.json
    meal_type = data.get('meal_type')
    meal_option = data.get('meal_option')
    default_drink = data.get('default_drink', None)  # Optional, defaults to None

    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            query = "INSERT INTO meals (meal_type, meal_option, default_drink) VALUES (%s, %s, %s)"
            cursor.execute(query, (meal_type, meal_option, default_drink))
            conn.commit()
            return jsonify({'message': 'Meal added successfully'}), 201
        else:
            return jsonify({'error': 'Failed to connect to the database'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()


@app.route('/remove_meal/<meal_type>', methods=['POST'])
def remove_meal(meal_type):
    try:
        # Assuming the meal_option is sent in the request's JSON body
        data = request.get_json()
        meal_option = data['meal_option']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Deleting the meal from the database
        cursor.execute('DELETE FROM meals WHERE meal_type = %s AND meal_option = %s', (meal_type, meal_option))

        conn.commit()
        return jsonify({'message': 'Meal removed successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()

# -------------------------------------- documents Table ----------------------------------------------- #

@app.route('/fetch_employee_documents', methods=['GET'])
@jwt_required()
def fetch_employee_documents():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT document_name, expiration_interval FROM documents WHERE category = 'Employee'")
            documents = cursor.fetchall()
            document_details = {doc[0]: doc[1] if doc[1] is not None else '' for doc in documents}
        return jsonify(document_details=document_details), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_facility_documents', methods=['GET'])
@jwt_required()
def fetch_facility_documents():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT document_name, expiration_interval FROM documents WHERE category = 'Facility'")
            documents = cursor.fetchall()
            document_details = {doc[0]: doc[1] if doc[1] is not None else '' for doc in documents}
        return jsonify(document_details=document_details), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


# -------------------------------------- tracked_items Table ------------------------------------------- #

def calculate_expiration_date(certification_date, expiration_interval):
    """
    Calculate the expiration date based on the certification date and expiration interval.

    Args:
        certification_date (str): The date when the certification/document was issued, in 'YYYY-MM-DD' format.
        expiration_interval (int): The number of days until the document expires.

    Returns:
        str: The expiration date in 'YYYY-MM-DD' format.
    """
    if not expiration_interval:
        return None  # or some default date if expiration_interval is not provided

    certification_date_dt = datetime.strptime(certification_date, "%Y-%m-%d")
    expiration_date_dt = certification_date_dt + timedelta(days=int(expiration_interval))
    return expiration_date_dt.strftime("%Y-%m-%d")


@app.route('/dashboard_data', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    today = datetime.now().date()
    thirty_days_later = today + timedelta(days=30)
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Count items expiring within the next 30 days
            cursor.execute("""
                SELECT COUNT(*) FROM tracked_items 
                WHERE expiration_date BETWEEN %s AND %s
                """, (today, thirty_days_later))
            upcoming_renewals = cursor.fetchone()[0]

            # Count items due today or overdue
            cursor.execute("""
                SELECT COUNT(*) FROM tracked_items 
                WHERE expiration_date <= %s
                """, (today,))
            immediate_renewals = cursor.fetchone()[0]

        return jsonify(upcoming_renewals=upcoming_renewals, immediate_renewals=immediate_renewals), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/add_tracked_item_employee', methods=['POST'])
@jwt_required()
def add_tracked_item_employee():
    data = request.get_json()
    employee_name = data['employee_name']
    document_name = data['document_name']
    custom_document_name = data.get('custom_document_name')
    expiration_interval = data.get('expiration_interval')
    certification_date = data['certification_date']
    reminder_days_before_expiration = data['reminder_days_before_expiration']

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if custom_document_name:
                # Insert custom document into documents table
                cursor.execute(
                    "INSERT INTO documents (document_name, expiration_interval, is_custom, category) VALUES (%s, %s, TRUE, 'Employee')",
                    (custom_document_name, expiration_interval)
                )
                document_id = cursor.lastrowid
            else:
                # Fetch document_id for predefined documents
                cursor.execute("SELECT document_id FROM documents WHERE document_name = %s", (document_name,))
                result = cursor.fetchone()
                if result:
                    document_id = result[0]
                else:
                    return jsonify({'error': 'Document not found'}), 404

            expiration_date = calculate_expiration_date(certification_date, expiration_interval)
            
            # Insert into tracked_items table
            cursor.execute(
                "INSERT INTO tracked_items (document_id, document_date, expiration_date, reminder_days_before_expiration, document_status, pertains_to, category_type) VALUES (%s, %s, %s, %s, 'valid', %s, 'Employee')",
                (document_id, certification_date, expiration_date, reminder_days_before_expiration, employee_name)
            )
            conn.commit()

        return jsonify({'message': 'Tracked item added successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_employee_tracked_items', methods=['GET'])
@jwt_required()
def fetch_employee_tracked_items():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = '''
            SELECT ti.pertains_to, d.document_name, ti.document_date, ti.expiration_date, ti.document_status
            FROM tracked_items ti
            JOIN documents d ON ti.document_id = d.document_id
            WHERE ti.category_type = 'Employee'
        '''
        cursor.execute(sql)
        result = cursor.fetchall()

        employee_tracked_items = [{
            'employee_name': row[0],
            'document_name': row[1],
            'certification_date': row[2].strftime('%Y-%m-%d'),
            'expiration_date': row[3].strftime('%Y-%m-%d'),
            'status': row[4]
        } for row in result]

        return jsonify(employee_tracked_items), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/fetch_facility_tracked_items', methods=['GET'])
@jwt_required()
def fetch_facility_tracked_items():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = '''
            SELECT d.document_name, ti.document_date, ti.expiration_date, ti.document_status
            FROM tracked_items ti
            JOIN documents d ON ti.document_id = d.document_id
            WHERE ti.category_type = 'Facility'
        '''
        cursor.execute(sql)
        result = cursor.fetchall()

        facility_tracked_items = [{
            'document_name': row[0],
            'certification_date': row[1].strftime('%Y-%m-%d'),
            'expiration_date': row[2].strftime('%Y-%m-%d'),
            'status': row[3]
        } for row in result]

        return jsonify(facility_tracked_items), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


@app.route('/add_tracked_item_facility', methods=['POST'])
@jwt_required()
def add_tracked_item_facility():
    data = request.get_json()
    document_name = data['document_name']
    custom_document_name = data.get('custom_document_name')
    expiration_interval = data.get('expiration_interval')
    certification_date = data['certification_date']
    reminder_days_before_expiration = data['reminder_days_before_expiration']

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if custom_document_name:
                # Insert custom document into documents table if it doesn't already exist
                cursor.execute(
                    "INSERT INTO documents (document_name, expiration_interval, is_custom, category) VALUES (%s, %s, TRUE, 'Facility') ON DUPLICATE KEY UPDATE expiration_interval = VALUES(expiration_interval)",
                    (custom_document_name, expiration_interval)
                )
                document_id = cursor.lastrowid
            else:
                # Fetch document_id for predefined documents
                cursor.execute("SELECT document_id FROM documents WHERE document_name = %s AND category = 'Facility'", (document_name,))
                result = cursor.fetchone()
                if result:
                    document_id = result[0]
                else:
                    return jsonify({'error': 'Document not found'}), 404

            expiration_date = calculate_expiration_date(certification_date, expiration_interval)
            
            # Insert into tracked_items table
            cursor.execute(
                "INSERT INTO tracked_items (document_id, document_date, expiration_date, reminder_days_before_expiration, document_status, pertains_to, category_type) VALUES (%s, %s, %s, %s, 'valid', NULL, 'Facility')",
                (document_id, certification_date, expiration_date, reminder_days_before_expiration)
            )
            conn.commit()

        return jsonify({'message': 'Tracked item added successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn.is_connected():
            conn.close()


# ---------------------------------------- Data Insertion ---------------------------------------------- #

# def activities_list ():
#     activity_list = ["Movies", "Walk", "Exercise", "Bird Watching", "Puzzles", "Trivia", "Baking",
#               "Gardening", "Stretching", "Family Calls", "ROM Exercise", "Coloring", "Arts & Crafts", "Bingo",
#               "Card Games", "Music", "Board Games", "Dominoes", "Balloon Volleyball", "Tea Time Social", "Arts and Music", "Chair Zumba", "Virtual Museum Tours", "Indoor Bowling",
#               "Puzzle Quilts", "Ice-Cream Social", "Indoor Minigolf", "Brain Teasers", "Group Meditation", "DIY Craft Projects", "Group Painting", "Storytelling Circle"]

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         for activity in activity_list:
#             cursor.execute('INSERT INTO activities (activity_name) VALUES (%s)', (activity,))
#         conn.commit()
#         conn.close()
#         return jsonify({'message': 'Activities added successfully'}), 200
#     except Error as e:
#         return jsonify({'error': str(e)}), 500
#     finally:
#         if conn and conn.is_connected():
#             conn.close()


# def insert_meal_data():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         # Insert breakfast meals
#         for meal in breakfast:
#             meal_option = meal
#             cursor.execute('INSERT INTO meals (meal_type, meal_option, default_drink) VALUES (%s, %s, %s)',
#                            ('breakfast', meal_option, breakfast_drink))
#         # Insert lunch and dinner meals
#         for meal_type, meals in [('lunch', lunch), ('dinner', dinner)]:
#             for meal in meals:
#                 meal_option = meal
#                 cursor.execute('INSERT INTO meals (meal_type, meal_option) VALUES (%s, %s)',
#                                (meal_type, meal_option))
#         conn.commit()
#     except Error as e:
#         print(f"Error inserting meal data: {e}")
#     finally:
#         if conn and conn.is_connected():
#             conn.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
    
    
    
