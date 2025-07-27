import os
from datetime import date
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask_app import get_db_connection

def main():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # 1) find items to remind
    cursor.execute("""
      SELECT item_id, pertains_to, d.document_name, expiration_date,
             reminder_days_before_expiration
        FROM tracked_items ti
        JOIN documents d ON ti.document_id = d.document_id
       WHERE ti.category_type IN ('Resident','Employee','Facility')
         AND ti.email_sent = 0
         AND ti.expiration_date = CURDATE() + INTERVAL ti.reminder_days_before_expiration DAY
    """)
    rows = cursor.fetchall()
    if not rows:
        print("No reminders to send today.")
        return

    sg = SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
    for row in rows:
        # 2) build and send the email
        to_emails = ["oscarsoto@crossroadscarehomes.com","rociosoto@crossroadscarehomes.com", "lupita_alvarez@crossroadscarehomes.com"]
        subject = f"📌 Reminder: {row['document_name']} expires on {row['expiration_date']}"
        body    = f"{row['pertains_to']}'s {row['document_name']} will expire on {row['expiration_date']}."
        message = Mail(from_email="oscarsoto@crossroadscarehomes.com",
                       to_emails=to_emails,
                       subject=subject,
                       html_content=body)
        try:
            sg.send(message)
            # 3) mark as sent
            cursor.execute("UPDATE tracked_items SET email_sent=1 WHERE item_id=%s", (row['item_id'],))
            conn.commit()
            print(f"Sent reminder for item {row['item_id']}")
        except Exception as e:
            print(f"Failed to send for {row['item_id']}: {e}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()