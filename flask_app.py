from flask import Flask, jsonify, request
import logging
from flask_jwt_extended import create_access_token, JWTManager , jwt_required, get_jwt_identity
import mysql.connector
from mysql.connector import Error
import bcrypt
from encryption_utils import encrypt_data, decrypt_data
from datetime import datetime, timedelta

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
        # Heroku JawsDB MySQL connection
        connection = mysql.connector.connect(
            user='pozl9cpm2uqcwpua',
            password='rp0a76nf9cerxtb2',
            host='k9xdebw4k3zynl4u.cbetxkdyhwsb.us-east-1.rds.amazonaws.com',
            database='ci3kn5xmdkiffd0u'
        )
        # Google Cloud MySQL connection
        # connection = mysql.connector.connect(
        #     user='oscar',
        #     password='rir718hhzrthzr',
        #     host='34.94.226.95',
        #     database='resident_data'
        # )
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
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
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
        if conn.is_connected():
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

# --------------------------------- audit_logs Table --------------------------------- #

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


# --------------------------------- adl_chart Table --------------------------------- #

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
            log_action(get_jwt_identity(), 'ADL Data Saved', audit_description)
            return jsonify({'message': 'ADL data saved successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --------------------------------- medications Table --------------------------------- #

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


@app.route('/filter_active_medications', methods=['POST'])
@jwt_required()
def filter_active_medications():
    # Assuming you're receiving a list of medication names and a resident name in the request JSON
    data = request.get_json()
    medication_names = data.get('medication_names', [])
    resident_name = data.get('resident_name', '')
    active_medications = []

    try:
        conn = get_db_connection()
        if conn is not None:
            with conn.cursor() as cursor:
                for med_name in medication_names:
                    cursor.execute('''
                        SELECT discontinued_date FROM medications
                        JOIN residents ON medications.resident_id = residents.id
                        WHERE residents.name = %s AND medications.medication_name = %s
                    ''', (resident_name, med_name))
                    result = cursor.fetchone()

                    # Check if the medication is discontinued and if the discontinuation date is past the current date
                    if result is None or (result[0] is None or datetime.datetime.now().date() < result[0]):
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


# -------------------------------- non_medication_orders Table -------------------------------- #

@app.route('/add_non_medication_order/<resident_name>', methods=['POST'])
@jwt_required()
def save_non_medication_order(resident_name):
    data = request.get_json()
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    order_name = data.get('order_name')
    frequency = data.get('frequency', '')
    specific_days = data.get('specific_days', '')
    instructions = data.get('instructions')

    # Validate input
    if not order_name:
        return jsonify({'error': 'Order name is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO non_medication_orders (resident_id, order_name, frequency, specific_days, special_instructions)
            VALUES (%s, %s, %s, %s, %s)
        ''', (resident_id, order_name, frequency, specific_days, instructions))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    # Log the action 
    log_action(get_jwt_identity(), 'Add Non-Medication Order', f'Order for {resident_name}: {order_name}')

    return jsonify({'message': 'Non-medication order added successfully'}), 200


@app.route('/fetch_non_medication_orders/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_all_non_medication_orders(resident_name):
    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': f'Resident {resident_name} not found'}), 404

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT order_id, order_name, frequency, specific_days, special_instructions, discontinued_date, last_administered_date
            FROM non_medication_orders
            WHERE resident_id = %s
        ''', (resident_id,))
        orders = cursor.fetchall()

        # Prepare and return the list of orders
        non_medication_orders = [{
            'order_id': order['order_id'],
            'order_name': order['order_name'],
            'frequency': order['frequency'],
            'specific_days': order['specific_days'],
            'special_instructions': order['special_instructions'],
            'discontinued_date': order['discontinued_date'] if order['discontinued_date'] else None,
            'last_administered_date': order['last_administered_date'] if order['last_administered_date'] else None,
        } for order in orders]

        return jsonify(non_medication_orders), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# ----------------------------------- emar_chart Table ----------------------------------------- #

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


@app.route('/fetch_emar_data_for_month/<resident_name>', methods=['GET'])
@jwt_required()
def fetch_emar_data_for_month(resident_name):
    year_month = request.args.get('year_month', None)
    if not year_month:
        return jsonify({'error': 'Year and month parameter is required'}), 400

    resident_id = get_resident_id(resident_name)
    if not resident_id:
        return jsonify({'error': 'Resident not found'}), 404

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Fetch eMAR data for the resident for the specified month
            cursor.execute("""
                SELECT m.medication_name, DATE_FORMAT(e.chart_date, '%Y-%m-%d') as chart_date, e.time_slot, e.administered
                FROM emar_chart e
                JOIN medications m ON e.medication_id = m.id
                WHERE e.resident_id = %s AND DATE_FORMAT(e.chart_date, '%%Y-%%m') = %s
                ORDER BY e.chart_date, e.time_slot
            """, (resident_id, year_month))
            
            results = cursor.fetchall()

        # Organize eMAR data
        emar_data = [{'medication_name': row[0], 'date': row[1], 'time_slot': row[2], 'administered': row[3]} for row in results]

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
            
            # Log the action with audit description
            if audit_description:
                log_action(username, "EMAR Data Update", audit_description)

            responses.append({'status': 'success', 'message': 'Data saved successfully'})
        except mysql.connector.Error as err:
            conn.rollback()
            responses.append({'status': 'error', 'message': str(err)})
        finally:
            cursor.close()
            conn.close()

    return jsonify(responses)

# --------------------------------- Test Endpoints --------------------------------- #

@app.route('/test_fetch_adl_chart_data', methods=['GET'])
def test_fetch_adl_chart_data():
    try:
        conn = get_db_connection()  # Ensure this uses your existing DB connection function
        with conn.cursor(dictionary=True) as cursor:  # Using dictionary=True for convenience
            # Hard-coded query for testing
            query = '''
                SELECT * FROM adl_chart
                WHERE resident_id = 1 AND DATE_FORMAT(chart_date, '%Y-%m') = '2024-02'
                ORDER BY chart_date
            '''
            cursor.execute(query)
            results = cursor.fetchall()

            if results:
                return jsonify(results), 200
            else:
                return jsonify([]), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0')
