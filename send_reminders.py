import os
from datetime import date
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask_app import get_db_connection

def main():
    today = date.today()
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    sg = SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
    to_emails = [
        "oscarsoto@crossroadscarehomes.com",
        "rociosoto@crossroadscarehomes.com",
        "lupita_alvarez@crossroadscarehomes.com"
    ]
    from_email = "oscarsoto@crossroadscarehomes.com"

    # ——— 1) EXPIRED ITEMS ———
    cursor.execute("""
      SELECT item_id, pertains_to, d.document_name, expiration_date
        FROM tracked_items ti
        JOIN documents d ON ti.document_id = d.document_id
       WHERE ti.email_sent = 0
         AND ti.expiration_date < CURDATE()
    """)
    expired = cursor.fetchall()
    for row in expired:
        subject = f"⚠️ ALERT: {row['document_name']} expired on {row['expiration_date']}"
        body    = (
            f"{row['pertains_to']}'s {row['document_name']} "
            f"expired on {row['expiration_date']}. Please take action."
        )
        msg = Mail(from_email=from_email,
                   to_emails=to_emails,
                   subject=subject,
                   html_content=body)
        try:
            sg.send(msg)
            cursor.execute(
                "UPDATE tracked_items SET email_sent=1 WHERE item_id=%s",
                (row['item_id'],)
            )
            conn.commit()
            print(f"Sent EXPIRED alert for item {row['item_id']}")
        except Exception as e:
            print(f"Failed EXPIRED alert for {row['item_id']}: {e}")

    # ——— 2) UPCOMING REMINDERS ———
    cursor.execute("""
      SELECT item_id, pertains_to, d.document_name, expiration_date,
             reminder_days_before_expiration
        FROM tracked_items ti
        JOIN documents d ON ti.document_id = d.document_id
       WHERE ti.email_sent = 0
         AND ti.expiration_date = CURDATE() + INTERVAL ti.reminder_days_before_expiration DAY
    """)
    upcoming = cursor.fetchall()
    for row in upcoming:
        subject = f"📌 Reminder: {row['document_name']} expires on {row['expiration_date']}"
        body    = (
            f"{row['pertains_to']}'s {row['document_name']} "
            f"will expire on {row['expiration_date']} (in "
            f"{row['reminder_days_before_expiration']} days)."
        )
        msg = Mail(from_email=from_email,
                   to_emails=to_emails,
                   subject=subject,
                   html_content=body)
        try:
            sg.send(msg)
            cursor.execute(
                "UPDATE tracked_items SET email_sent=1 WHERE item_id=%s",
                (row['item_id'],)
            )
            conn.commit()
            print(f"Sent REMINDER for item {row['item_id']}")
        except Exception as e:
            print(f"Failed REMINDER for {row['item_id']}: {e}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()
