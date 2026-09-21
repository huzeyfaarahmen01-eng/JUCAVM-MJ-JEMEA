from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from database import create_database
from flask_mail import Mail, Message
from dotenv import load_dotenv
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import sqlite3
import os
import time
import re
import logging
from urllib.parse import urlparse
import shutil
from datetime import datetime


# ==================================================
# LOAD ENVIRONMENT VARIABLES
# ==================================================

load_dotenv()


# ==================================================
# FLASK APP
# ==================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "jemea-secret-key"
)


# ==================================================
# SECURITY #8 - SAFE ERROR HANDLING
# ==================================================

# Do not expose internal Python, database, email, or file-system errors
# to users. Technical details are written to the server log instead.
app.config["PROPAGATE_EXCEPTIONS"] = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ==================================================
# SECURITY #9 - CSRF PROTECTION
# ==================================================

# Protect state-changing POST requests from cross-site form submissions.
# This uses the browser-supplied Origin header when available, and falls
# back to Referer when Origin is not present. Existing Jemea forms continue
# to work without changing the templates.

def is_same_origin(value):

    if not value:
        return True

    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return False

    request_origin = request.host_url.rstrip("/")

    supplied_origin = (
        parsed.scheme
        + "://"
        + parsed.netloc
    ).rstrip("/")

    return supplied_origin == request_origin


@app.before_request
def protect_state_changing_requests():

    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    origin = request.headers.get("Origin")

    if origin and not is_same_origin(origin):

        app.logger.warning(
            "Blocked cross-origin request: origin=%s path=%s method=%s",
            origin,
            request.path,
            request.method
        )

        return (
            "Request blocked for security reasons.",
            403
        )

    if not origin:

        referer = request.headers.get("Referer")

        if referer and not is_same_origin(referer):

            app.logger.warning(
                "Blocked cross-site request: referer=%s path=%s method=%s",
                referer,
                request.path,
                request.method
            )

            return (
                "Request blocked for security reasons.",
                403
            )

    return None


# ==================================================
# SECURITY #11 - SESSION INTEGRITY & AUTHENTICATION CHECKS
# ==================================================

# Re-check active authentication sessions against the database.
# This helps prevent access if session values become stale, invalid,
# or inconsistent with the real admin/student account.

@app.before_request
def validate_active_sessions():

    # --------------------------------------------------
    # Validate the admin session when one exists.
    # --------------------------------------------------
    if session.get("admin"):

        admin_id = session.get("admin_id")
        admin_username = session.get("admin_username")

        if not admin_id or not admin_username:

            app.logger.warning(
                "Invalid admin session detected: missing session data."
            )

            session.clear()

            flash(
                "Your session is no longer valid. Please log in again.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        connection = None

        try:

            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id, username
                FROM admin_accounts
                WHERE id = ? AND username = ?
                """,
                (
                    admin_id,
                    admin_username
                )
            )

            admin_account = cursor.fetchone()

        except sqlite3.Error:

            app.logger.exception(
                "Could not validate the active admin session."
            )

            return (
                "Something went wrong. Please try again later.",
                500
            )

        finally:

            if connection is not None:
                connection.close()

        if admin_account is None:

            app.logger.warning(
                "Invalid admin session detected for username=%s.",
                admin_username
            )

            session.clear()

            flash(
                "Your session is no longer valid. Please log in again.",
                "error"
            )

            return redirect(
                url_for("login")
            )


    # --------------------------------------------------
    # Validate the student session when one exists.
    # --------------------------------------------------
    if session.get("student_id"):

        student_id = session.get("student_id")
        student_email = session.get("student_email")

        if not student_email:

            app.logger.warning(
                "Invalid student session detected: missing email."
            )

            session.clear()

            flash(
                "Your session is no longer valid. Please log in again.",
                "error"
            )

            return redirect(
                url_for("student_login")
            )

        connection = None

        try:

            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id, email
                FROM students
                WHERE id = ? AND email = ?
                """,
                (
                    student_id,
                    student_email
                )
            )

            student_account = cursor.fetchone()

        except sqlite3.Error:

            app.logger.exception(
                "Could not validate the active student session."
            )

            return (
                "Something went wrong. Please try again later.",
                500
            )

        finally:

            if connection is not None:
                connection.close()

        if student_account is None:

            app.logger.warning(
                "Invalid student session detected for email=%s.",
                student_email
            )

            session.clear()

            flash(
                "Your session is no longer valid. Please log in again.",
                "error"
            )

            return redirect(
                url_for("student_login")
            )

    return None


# ==================================================
# SECURITY #12 - AUTHORIZATION & ACCESS CONTROL
# ==================================================

# Defense-in-depth authorization for protected routes.
# Individual routes still perform their own checks, but this central
# guard prevents a future route from accidentally becoming public.

ADMIN_PROTECTED_ENDPOINTS = {
    "admin",
    "admin_settings",
    "view_message",
    "reply_message",
    "edit_message",
    "update_status",
    "delete_message",
    "admin_conversation",
    "admin_send_message",
    "admin_delete_conversation_messages",
    "admin_analytics",
    "admin_audit_logs",
}

STUDENT_PROTECTED_ENDPOINTS = {
    "student_dashboard",
    "student_notifications_page",
    "mark_notification_read",
    "mark_all_notifications_read",
    "student_conversation",
    "student_send_message",
    "student_profile",
    "student_change_password",
    "student_logout",
}


@app.before_request
def enforce_authorization():

    endpoint = request.endpoint

    if endpoint in ADMIN_PROTECTED_ENDPOINTS:

        if not session.get("admin"):

            return redirect(
                url_for("login")
            )

    if endpoint in STUDENT_PROTECTED_ENDPOINTS:

        if not session.get("student_id"):

            return redirect(
                url_for("student_login")
            )

    return None


# ==================================================
# SECURITY #15 - PRODUCTION / HTTPS CONFIGURATION
# ==================================================

JEMEA_ENV = os.getenv(
    "JEMEA_ENV",
    "development"
).lower()

IS_PRODUCTION = JEMEA_ENV == "production"

app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


app.secret_key = os.getenv(
    "SECRET_KEY",
    "jemea-secret-key"
)

# Your other security configurations...
# Security #9
# Security #11
# Security #12
# etc.


# ==================================================
# SECURITY #14 - SECURITY HEADERS
# ==================================================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=()"
    )

    return response


# ==================================================
# YOUR ROUTES START HERE
# ==================================================











# ==================================================
# SECURITY #5 - LOGIN RATE LIMITING
# ==================================================

# Track failed login attempts in memory.
# This helps slow down repeated password-guessing attempts.
login_attempts = {}

LOGIN_MAX_ATTEMPTS = 5
LOGIN_BLOCK_SECONDS = 300


# ==================================================
# SECURITY #6 - INPUT VALIDATION
# ==================================================

# Keep user-controlled text within safe, practical limits.
# Flask/Jinja will auto-escape HTML when values are rendered in templates,
# while these checks prevent oversized or malformed input from reaching
# the database and email system.
INPUT_LIMITS = {
    "name": 100,
    "email": 254,
    "department": 100,
    "year": 50,
    "message": 5000,
    "reply": 5000,
    "username": 50,
    "password": 128,
}

EMAIL_PATTERN = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)


def validate_input(value, field_name, max_length=None):

    if value is None:
        return field_name + " is required."

    if "\x00" in value:
        return field_name + " contains invalid characters."

    if max_length is not None and len(value) > max_length:
        return (
            field_name
            + " is too long. Maximum "
            + str(max_length)
            + " characters allowed."
        )

    return None


def validate_email(email):

    error = validate_input(
        email,
        "Email",
        INPUT_LIMITS["email"]
    )

    if error:
        return error

    if not EMAIL_PATTERN.fullmatch(email):
        return "Please enter a valid email address."

    return None


def validate_password(password):

    return validate_input(
        password,
        "Password",
        INPUT_LIMITS["password"]
    )


# ==================================================
# EMAIL CONFIGURATION
# ==================================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)


# ==================================================
# DATABASE
# ==================================================

create_database()


# ==================================================
# SECURITY #7 - DATABASE CONNECTION PROTECTION
# ==================================================

def get_connection():

    # Use a timeout so short database locks do not immediately
    # cause a request to fail.
    connection = sqlite3.connect(
        "jemea.db",
        timeout=10
    )

    # Enforce SQLite foreign-key rules for every connection.
    # This prevents orphaned notification/conversation records
    # when related records are deleted.
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection
# ==================================================
# SECURITY #17 - AUDIT LOGGING
# ==================================================

def audit_log(
    user_type,
    action,
    user_id=None,
    details=None
):
    """
    Record an important security or system action.
    """

    try:
        connection = get_connection()
        cursor = connection.cursor()

        ip_address = (
            request.remote_addr
            or "unknown"
        )

        cursor.execute(
            """
            INSERT INTO audit_logs (
                user_type,
                user_id,
                action,
                details,
                ip_address
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_type,
                str(user_id)
                if user_id is not None
                else None,
                action,
                details,
                ip_address
            )
        )

        connection.commit()
        connection.close()

    except Exception:
        app.logger.error(
            "Audit logging failed.",
            exc_info=True
        )


# ==================================================
# SECURITY #16 - DATABASE BACKUP
# ==================================================

BACKUP_FOLDER = "backups"


def create_database_backup():
    """
    Create a timestamped backup of the Jemea database.
    The original jemea.db is never modified.
    """

    os.makedirs(
        BACKUP_FOLDER,
        exist_ok=True
    )

    if not os.path.exists("jemea.db"):
        app.logger.warning(
            "Database backup skipped: jemea.db does not exist."
        )
        return None

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    backup_filename = (
        "jemea_backup_"
        + timestamp
        + ".db"
    )

    backup_path = os.path.join(
        BACKUP_FOLDER,
        backup_filename
    )

    shutil.copy2(
        "jemea.db",
        backup_path
    )

    app.logger.info(
        "Database backup created: %s",
        backup_path
    )

    return backup_path

# ==================================================
# SECURITY #16 - BACKUP TEST ROUTE
# ==================================================
@app.route("/create-backup")
def create_backup():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    try:

        backup_path = create_database_backup()

        if backup_path is None:

            flash(
                "Database backup could not be created.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # Make sure the backup file actually exists.
        if not os.path.isfile(backup_path):

            flash(
                "Backup was created but the file could not be found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # Make sure the backup is not empty.
        if os.path.getsize(backup_path) == 0:

            flash(
                "Backup file is empty.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        audit_log(
            user_type="admin",
            action="database_backup",
            user_id=session.get("admin_id"),
            details=(
                "Admin created a database backup: "
                + os.path.basename(backup_path)
            )
        )

        flash(
            "Database backup created successfully.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    except Exception:

        app.logger.exception(
            "Database backup failed."
        )

        flash(
            "Database backup failed.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    # ==================================================
# SECURITY #16 - BACKUP VERIFICATION
# ==================================================
# ==================================================
# VERIFY DATABASE BACKUP
# ==================================================

@app.route("/verify-backup")
def verify_backup():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    connection = None

    try:

        # ==================================================
        # CHECK BACKUP FOLDER
        # ==================================================

        if not os.path.isdir(BACKUP_FOLDER):

            flash(
                "Backup folder was not found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # FIND BACKUP FILES
        # ==================================================

        backup_files = [
            filename
            for filename in os.listdir(
                BACKUP_FOLDER
            )
            if filename.startswith(
                "jemea_backup_"
            )
            and filename.endswith(".db")
        ]

        if not backup_files:

            flash(
                "No database backup was found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        backup_files.sort(
            reverse=True
        )

        latest_backup = os.path.join(
            BACKUP_FOLDER,
            backup_files[0]
        )

        # ==================================================
        # CHECK FILE
        # ==================================================

        if not os.path.isfile(
            latest_backup
        ):

            flash(
                "Backup file was not found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        if os.path.getsize(
            latest_backup
        ) == 0:

            flash(
                "Backup verification failed: backup is empty.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # OPEN BACKUP DATABASE
        # ==================================================

        connection = sqlite3.connect(
            latest_backup,
            timeout=10
        )

        cursor = connection.cursor()

        # ==================================================
        # SQLITE INTEGRITY CHECK
        # ==================================================

        cursor.execute(
            """
            PRAGMA integrity_check
            """
        )

        integrity_result = cursor.fetchone()

        if (
            not integrity_result
            or integrity_result[0] != "ok"
        ):

            flash(
                "Backup verification failed: database integrity check failed.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # FOREIGN KEY CHECK
        # ==================================================

        cursor.execute(
            """
            PRAGMA foreign_key_check
            """
        )

        foreign_key_errors = cursor.fetchall()

        if foreign_key_errors:

            flash(
                "Backup verification failed: foreign-key errors were found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # CHECK REQUIRED TABLES
        # ==================================================

        cursor.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        )

        tables = {
            row[0]
            for row in cursor.fetchall()
        }

        required_tables = {
            "messages",
            "students",
            "conversation_messages",
            "notifications",
            "admin_accounts",
            "audit_logs"
        }

        missing_tables = (
            required_tables - tables
        )

        if missing_tables:

            flash(
                "Backup verification failed: required tables are missing.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # SUCCESS
        # ==================================================

        audit_log(
            user_type="admin",
            action="backup_verification",
            user_id=session.get("admin_id"),
            details=(
                "Admin verified database backup: "
                + backup_files[0]
            )
        )

        flash(
            "Database backup verified successfully.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    except Exception:

        app.logger.exception(
            "Database backup verification failed."
        )

        flash(
            "Database backup verification failed.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    finally:

        if connection is not None:

            connection.close()


# ==================================================
# RESTORE DATABASE BACKUP
# ==================================================

@app.route(
    "/restore-backup",
    methods=["POST"]
)
def restore_backup():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    backup_filename = request.form.get(
        "backup_filename",
        ""
    ).strip()

    # ==================================================
    # VALIDATE BACKUP NAME
    # ==================================================

    if not backup_filename:

        flash(
            "Please select a backup.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    # Prevent path traversal.
    if (
        os.path.basename(backup_filename)
        != backup_filename
    ):

        flash(
            "Invalid backup file.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    if not (
        backup_filename.startswith(
            "jemea_backup_"
        )
        and backup_filename.endswith(".db")
    ):

        flash(
            "Invalid backup file.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    backup_path = os.path.join(
        BACKUP_FOLDER,
        backup_filename
    )

    if not os.path.isfile(
        backup_path
    ):

        flash(
            "Backup file was not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    connection = None

    try:

        # ==================================================
        # CHECK BACKUP SIZE
        # ==================================================

        if os.path.getsize(
            backup_path
        ) == 0:

            flash(
                "Cannot restore an empty backup.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # VERIFY SELECTED BACKUP
        # ==================================================

        connection = sqlite3.connect(
            backup_path,
            timeout=10
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            PRAGMA integrity_check
            """
        )

        integrity_result = cursor.fetchone()

        if (
            not integrity_result
            or integrity_result[0] != "ok"
        ):

            flash(
                "Restore cancelled: backup integrity check failed.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        cursor.execute(
            """
            PRAGMA foreign_key_check
            """
        )

        foreign_key_errors = cursor.fetchall()

        if foreign_key_errors:

            flash(
                "Restore cancelled: backup contains foreign-key errors.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        # ==================================================
        # CHECK REQUIRED TABLES
        # ==================================================

        cursor.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        )

        tables = {
            row[0]
            for row in cursor.fetchall()
        }

        required_tables = {
            "messages",
            "students",
            "conversation_messages",
            "notifications",
            "admin_accounts",
            "audit_logs"
        }

        missing_tables = (
            required_tables - tables
        )

        if missing_tables:

            flash(
                "Restore cancelled: required database tables are missing.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        connection.close()
        connection = None

        # ==================================================
        # CREATE PRE-RESTORE SAFETY BACKUP
        # ==================================================

        current_database = "jemea.db"

        safety_path = None

        if os.path.isfile(
            current_database
        ):

            timestamp = datetime.now().strftime(
                "%Y-%m-%d_%H-%M-%S"
            )

            safety_filename = (
                "jemea_pre_restore_"
                + timestamp
                + ".db"
            )

            safety_path = os.path.join(
                BACKUP_FOLDER,
                safety_filename
            )

            shutil.copy2(
                current_database,
                safety_path
            )

        # ==================================================
        # RESTORE DATABASE
        # ==================================================

        shutil.copy2(
            backup_path,
            current_database
        )

        # ==================================================
        # VERIFY RESTORED DATABASE
        # ==================================================

        restored_connection = None

        try:

            restored_connection = sqlite3.connect(
                current_database,
                timeout=10
            )

            restored_cursor = (
                restored_connection.cursor()
            )

            restored_cursor.execute(
                """
                PRAGMA integrity_check
                """
            )

            restored_integrity = (
                restored_cursor.fetchone()
            )

            if (
                not restored_integrity
                or restored_integrity[0] != "ok"
            ):

                raise RuntimeError(
                    "Restored database failed integrity verification."
                )

            restored_cursor.execute(
                """
                PRAGMA foreign_key_check
                """
            )

            restored_foreign_key_errors = (
                restored_cursor.fetchall()
            )

            if restored_foreign_key_errors:

                raise RuntimeError(
                    "Restored database contains foreign-key errors."
                )

        finally:

            if restored_connection is not None:

                restored_connection.close()

        # ==================================================
        # AUDIT LOG
        # ==================================================

        audit_log(
            user_type="admin",
            action="database_restore",
            user_id=session.get("admin_id"),
            details=(
                "Admin restored database from backup: "
                + backup_filename
            )
        )

        flash(
            "Database restored successfully from backup.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    except Exception:

        app.logger.exception(
            "Database restore failed."
        )

        # ==================================================
        # ATTEMPT AUTOMATIC RECOVERY
        # ==================================================

        if (
            safety_path is not None
            and os.path.isfile(safety_path)
        ):

            try:

                shutil.copy2(
                    safety_path,
                    "jemea.db"
                )

                app.logger.info(
                    "Database automatically restored "
                    "from pre-restore safety backup."
                )

                flash(
                    "Database restore failed. The original database was automatically recovered.",
                    "error"
                )

            except Exception:

                app.logger.exception(
                    "Automatic database recovery failed."
                )

                flash(
                    "Database restore failed. Manual recovery may be required.",
                    "error"
                )

        else:

            flash(
                "Database restore failed.",
                "error"
            )

        return redirect(
            url_for("admin")
        )

    finally:

        if connection is not None:

            connection.close()
 # ==================================================
# DATABASE CLEANUP
# ==================================================

def cleanup_database():
    """
    Perform safe SQLite maintenance and integrity checks.

    Returns a dictionary compatible with the existing
    /database-cleanup route.
    """
    connection = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Check database integrity before maintenance.
        cursor.execute("PRAGMA integrity_check")
        integrity_result = cursor.fetchone()

        if not integrity_result or integrity_result[0] != "ok":
            app.logger.error(
                "Database cleanup stopped: integrity check failed: %s",
                integrity_result
            )
            return {
                "success": False,
                "message": "Database integrity check failed."
            }

        # Check for foreign-key violations.
        cursor.execute("PRAGMA foreign_key_check")
        foreign_key_errors = cursor.fetchall()

        if foreign_key_errors:
            app.logger.error(
                "Database cleanup stopped: foreign-key violations found: %s",
                len(foreign_key_errors)
            )
            return {
                "success": False,
                "message": "Foreign-key violations were found."
            }

        # Commit any pending work before VACUUM.
        connection.commit()

        # Ask SQLite to optimize query planning/statistics.
        cursor.execute("PRAGMA optimize")

        # Rebuild the database file to reclaim unused space.
        cursor.execute("VACUUM")

        connection.commit()

        # Verify the database again after maintenance.
        cursor.execute("PRAGMA integrity_check")
        final_integrity_result = cursor.fetchone()

        if (
            not final_integrity_result
            or final_integrity_result[0] != "ok"
        ):
            app.logger.error(
                "Database cleanup finished with failed final integrity check: %s",
                final_integrity_result
            )
            return {
                "success": False,
                "message": "Final database integrity check failed."
            }

        cursor.execute("PRAGMA foreign_key_check")
        final_foreign_key_errors = cursor.fetchall()

        if final_foreign_key_errors:
            app.logger.error(
                "Database cleanup finished with foreign-key violations: %s",
                len(final_foreign_key_errors)
            )
            return {
                "success": False,
                "message": "Final foreign-key check failed."
            }

        app.logger.info(
            "Database cleanup completed successfully."
        )

        return {
            "success": True,
            "message": "Database cleanup completed successfully."
        }

    except Exception:
        app.logger.exception(
            "Database cleanup operation failed."
        )

        return {
            "success": False,
            "message": "Database cleanup operation failed."
        }

    finally:
        if connection is not None:
            connection.close()


@app.route(
    "/database-cleanup",
    methods=["POST"]
)
def database_cleanup():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    connection = None

    try:

        # Remove orphaned conversation records.
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM conversation_messages
            WHERE submission_id NOT IN (
                SELECT id
                FROM messages
            )
            """
        )

        removed_conversations = cursor.rowcount

        connection.commit()
        connection.close()
        connection = None

        # Run the database cleanup/integrity checks.
        cleanup_result = cleanup_database()

        if not cleanup_result.get(
            "success",
            False
        ):

            app.logger.error(
                "Database cleanup reported failure: %s",
                cleanup_result
            )

            flash(
                "Database cleanup completed with errors.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        audit_log(
            user_type="admin",
            action="database_cleanup",
            user_id=session.get("admin_id"),
            details=(
                "Database cleanup completed. "
                "Removed "
                + str(removed_conversations)
                + " orphaned conversation record(s)."
            )
        )

        flash(
            "Database cleanup completed successfully. "
            + str(removed_conversations)
            + " orphaned conversation record(s) removed.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    except Exception:

        app.logger.exception(
            "Database cleanup failed."
        )

        flash(
            "Database cleanup failed.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    finally:

        if connection is not None:
            connection.close()
 # ==================================================
# CLEAN OLD DATABASE BACKUPS
# ==================================================

@app.route(
    "/cleanup-backups",
    methods=["POST"]
)
def cleanup_backups():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    try:

        if not os.path.isdir(
            BACKUP_FOLDER
        ):

            flash(
                "Backup folder was not found.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

        backup_files = [
            filename
            for filename in os.listdir(
                BACKUP_FOLDER
            )
            if (
                filename.startswith(
                    "jemea_backup_"
                )
                and filename.endswith(".db")
                and os.path.isfile(
                    os.path.join(
                        BACKUP_FOLDER,
                        filename
                    )
                )
            )
        ]

        backup_files.sort(
            reverse=True
        )

        # Keep the newest 10 regular backups.
        keep_count = 10

        files_to_delete = backup_files[
            keep_count:
        ]

        deleted_count = 0

        for filename in files_to_delete:

            backup_path = os.path.join(
                BACKUP_FOLDER,
                filename
            )

            try:

                os.remove(
                    backup_path
                )

                deleted_count += 1

            except OSError:

                app.logger.exception(
                    "Could not delete old backup: %s",
                    backup_path
                )

        audit_log(
            user_type="admin",
            action="backup_cleanup",
            user_id=session.get("admin_id"),
            details=(
                "Admin cleaned old database backups. "
                "Deleted "
                + str(deleted_count)
                + " old backup(s)."
            )
        )

        flash(
            "Backup cleanup completed. "
            + str(deleted_count)
            + " old backup(s) removed.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    except Exception:

        app.logger.exception(
            "Backup cleanup failed."
        )

        flash(
            "Backup cleanup failed.",
            "error"
        )

        return redirect(
            url_for("admin")
        )      





# ==================================================
# DATABASE MIGRATION
# ==================================================

def prepare_database():

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            ALTER TABLE messages
            ADD COLUMN conversation_cleared
            INTEGER NOT NULL DEFAULT 0
            """
        )

    except sqlite3.OperationalError:

        pass


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            student_id INTEGER NOT NULL,

            submission_id INTEGER,

            title TEXT NOT NULL,

            message TEXT NOT NULL,

            is_read INTEGER NOT NULL DEFAULT 0,

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (student_id)
                REFERENCES students(id)
                ON DELETE CASCADE,

            FOREIGN KEY (submission_id)
                REFERENCES messages(id)
                ON DELETE CASCADE

        )
        """
    )


    # ==================================================
    # ADMIN ACCOUNT TABLE
    # ==================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_accounts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL,

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            updated_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP

        )
        """
    )
    # ==================================================
    # SECURITY #17 - AUDIT LOG TABLE
    # ==================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL,
            user_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

  






    # ==================================================
    # CREATE INITIAL ADMIN ACCOUNT
    # ==================================================
    #
    # The first account uses ADMIN_USERNAME and
    # ADMIN_PASSWORD from .env.
    #
    # After that, Settings can change the account
    # without changing .env.
    #
    # ==================================================

    cursor.execute(
        """
        SELECT id
        FROM admin_accounts
        LIMIT 1
        """
    )

    existing_admin = cursor.fetchone()


    if existing_admin is None:

        initial_username = os.getenv(
            "ADMIN_USERNAME",
            "admin"
        )

        initial_password = os.getenv(
            "ADMIN_PASSWORD",
            "1234"
        )


        cursor.execute(
            """
            INSERT INTO admin_accounts
            (
                username,
                password
            )
            VALUES
            (
                ?,
                ?
            )
            """,
            (
                initial_username,
                generate_password_hash(
                    initial_password
                )
            )
        )
            # ==================================================
    # PHASE 4 - DATABASE INDEXES
    # ==================================================

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_messages_status
        ON messages(status)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_messages_email
        ON messages(email)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_messages_created_at
        ON messages(created_at)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_notifications_student_id
        ON notifications(student_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_notifications_submission_id
        ON notifications(submission_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_conversation_submission_id
        ON conversation_messages(submission_id)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_audit_logs_created_at
        ON audit_logs(created_at)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_audit_logs_action
        ON audit_logs(action)
        """
    )


    connection.commit()
    connection.close()

    


prepare_database()


# ==================================================
# MESSAGE COLUMNS
# ==================================================

MESSAGE_COLUMNS = """
    id,
    name,
    email,
    department,
    year,
    message,
    created_at,
    status,
    reply
"""


# ==================================================
# NOTIFICATION HELPER
# ==================================================

def create_student_notification(
    student_id,
    submission_id,
    title,
    message
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO notifications
        (
            student_id,
            submission_id,
            title,
            message,
            is_read
        )
        VALUES
        (
            ?,
            ?,
            ?,
            ?,
            0
        )
        """,
        (
            student_id,
            submission_id,
            title,
            message
        )
    )

    connection.commit()
    connection.close()


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    return render_template(
        "index.html",
        name="Huzeyfa",
        age=20,
        fruits=[
            "Apple",
            "Banana",
            "Mango"
        ]
    )


# ==================================================
# ABOUT
# ==================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# ==================================================
# CONTACT / SUBMIT IDEA
# ==================================================

@app.route(
    "/contact",
    methods=["GET", "POST"]
)
def contact():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        department = request.form.get(
            "department",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        message = request.form.get(
            "message",
            ""
        ).strip()


        if (
            not name
            or not email
            or not department
            or not year
            or not message
        ):

            flash(
                "Please complete all fields.",
                "error"
            )

            return redirect(
                url_for("contact")
            )


        validation_error = None

        for field_name, field_value in [
            ("Name", name),
            ("Department", department),
            ("Year", year),
            ("Message", message),
        ]:
            validation_error = validate_input(
                field_value,
                field_name,
                INPUT_LIMITS[field_name.lower()]
            )

            if validation_error:
                break

        if validation_error is None:
            validation_error = validate_email(email)

        if validation_error:

            flash(
                validation_error,
                "error"
            )

            return redirect(
                url_for("contact")
            )


        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO messages
            (
                name,
                message,
                created_at,
                status,
                email,
                department,
                year,
                reply
            )
            VALUES
            (
                ?,
                ?,
                datetime('now'),
                'New',
                ?,
                ?,
                ?,
                ''
            )
            """,
            (
                name,
                message,
                email,
                department,
                year
            )
        )

        connection.commit()
        connection.close()


        flash(
            "Your idea was submitted successfully! "
            "Thank you for contributing to Jemea.",
            "success"
        )

        return redirect(
            url_for("contact")
        )


    return render_template(
        "contact.html"
    )


# ==================================================
# SECURITY #5 - LOGIN RATE LIMITING HELPERS
# ==================================================

def is_login_blocked(identifier):

    now = time.time()

    record = login_attempts.get(identifier)

    if record is None:
        return False

    failed_attempts, blocked_until = record

    if blocked_until > now:
        return True

    if blocked_until:
        login_attempts.pop(identifier, None)

    return False


def record_failed_login(identifier):

    now = time.time()

    record = login_attempts.get(identifier)

    if record is None:
        failed_attempts = 0
    else:
        failed_attempts, blocked_until = record

        if blocked_until > now:
            return

        if blocked_until:
            failed_attempts = 0

    failed_attempts += 1

    if failed_attempts >= LOGIN_MAX_ATTEMPTS:

        login_attempts[identifier] = (
            failed_attempts,
            now + LOGIN_BLOCK_SECONDS
        )

    else:

        login_attempts[identifier] = (
            failed_attempts,
            0
        )


def clear_failed_logins(identifier):

    login_attempts.pop(identifier, None)


# ==================================================
# ADMIN LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        username_error = validate_input(
            username,
            "Username",
            INPUT_LIMITS["username"]
        )

        password_error = validate_password(password)

        if username_error or password_error:

            flash(
                username_error or password_error,
                "error"
            )

            return redirect(
                url_for("login")
            )

        login_identifier = (
            "admin:"
            + (
                request.remote_addr
                or "unknown"
            )
            + ":"
            + username.lower()
        )

        if is_login_blocked(login_identifier):

            flash(
                "Too many failed login attempts. "
                "Please try again in 5 minutes.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        connection = get_connection()
        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT
                id,
                username,
                password
            FROM admin_accounts
            WHERE username = ?
            """,
            (
                username,
            )
        )


        admin_account = cursor.fetchone()

        connection.close()


        if (
            admin_account
            and check_password_hash(
                admin_account[2],
                password
            )
        ):

            session.clear()

            session["admin"] = True
            session["admin_id"] = admin_account[0]
            session["admin_username"] = admin_account[1]

            audit_log(
                user_type="admin",
                action="login",
                user_id=admin_account[0],
                details="Admin logged in successfully."
            )

            clear_failed_logins(
                login_identifier
            )  

            

          


            

            return redirect(
                url_for("admin")
            )


        record_failed_login(
            login_identifier
        )

        flash(
            "Wrong username or password.",
            "error"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "login.html"
    )


# ==================================================
# ADMIN DASHBOARD
# ==================================================
@app.route("/admin")
def admin():

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )

    connection = get_connection()
    cursor = connection.cursor()

    search = request.args.get(
        "search",
        ""
    ).strip()

    status_filter = request.args.get(
        "status",
        "All"
    )

    per_page = 10

    try:

        page = int(
            request.args.get(
                "page",
                1
            )
        )

    except ValueError:

        page = 1

    if page < 1:

        page = 1

    where_parts = []
    params = []

    if search:

        where_parts.append(
            """
            (
                name LIKE ?
                OR email LIKE ?
                OR department LIKE ?
                OR year LIKE ?
                OR message LIKE ?
            )
            """
        )

        search_value = f"%{search}%"

        params.extend(
            [
                search_value,
                search_value,
                search_value,
                search_value,
                search_value
            ]
        )

    if status_filter != "All":

        where_parts.append(
            "status = ?"
        )

        params.append(
            status_filter
        )

    if where_parts:

        where_clause = (
            "WHERE "
            + " AND ".join(where_parts)
        )

    else:

        where_clause = ""

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM messages
        {where_clause}
        """,
        params
    )

    total_filtered = cursor.fetchone()[0]

    total_pages = max(
        1,
        (
            total_filtered
            + per_page
            - 1
        )
        // per_page
    )

    if page > total_pages:

        page = total_pages

    offset = (
        page - 1
    ) * per_page

    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
        OFFSET ?
        """,
        params + [
            per_page,
            offset
        ]
    )

    messages = cursor.fetchall()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        """
    )

    total_messages = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(DISTINCT email)
        FROM messages
        """
    )

    total_contacts = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE DATE(created_at)
            = DATE('now')
        """
    )

    messages_today = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'New'
        """
    )

    new_messages = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'Read'
        """
    )

    read_messages = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'Replied'
        """
    )

    replied_messages = cursor.fetchone()[0]

    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE status = 'New'
        ORDER BY id DESC
        LIMIT 8
        """
    )

    admin_notifications = cursor.fetchall()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'New'
        """
    )

    unread_admin_notifications = (
        cursor.fetchone()[0]
    )

    cursor.execute(
        """
        SELECT
            user_type,
            user_id,
            action,
            details,
            created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 8
        """
    )

    recent_activity = cursor.fetchall()

    connection.close()

    # ==================================================
    # BACKUP FILES
    # ==================================================

    backup_files = []

    if os.path.isdir(
        BACKUP_FOLDER
    ):

        backup_files = [
            filename
            for filename in os.listdir(
                BACKUP_FOLDER
            )
            if (
                filename.startswith(
                    "jemea_backup_"
                )
                and filename.endswith(".db")
                and os.path.isfile(
                    os.path.join(
                        BACKUP_FOLDER,
                        filename
                    )
                )
            )
        ]

        backup_files.sort(
            reverse=True
        )

    return render_template(
        "admin.html",

        messages=messages,

        total_messages=total_messages,

        total_contacts=total_contacts,

        messages_today=messages_today,

        new_messages=new_messages,

        read_messages=read_messages,

        replied_messages=replied_messages,

        search=search,

        status_filter=status_filter,

        page=page,

        per_page=per_page,

        total_filtered=total_filtered,

        total_pages=total_pages,

        admin_notifications=admin_notifications,

        unread_admin_notifications=(
            unread_admin_notifications
        ),

        recent_activity=recent_activity,

        backup_files=backup_files
    )



# ==================================================
# ADMIN ACCOUNT / SETTINGS
# ==================================================

@app.route(
    "/admin/settings",
    methods=["GET", "POST"]
)
def admin_settings():

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            id,
            username,
            created_at,
            updated_at
        FROM admin_accounts
        WHERE id = ?
        """,
        (
            session.get("admin_id"),
        )
    )


    admin_account = cursor.fetchone()


    if admin_account is None:

        connection.close()

        session.clear()

        flash(
            "Admin account could not be found.",
            "error"
        )

        return redirect(
            url_for("login")
        )


    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_username = request.form.get(
            "username",
            ""
        ).strip()

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        username_error = validate_input(
            new_username,
            "Username",
            INPUT_LIMITS["username"]
        )

        current_password_error = validate_password(
            current_password
        )

        new_password_error = validate_password(
            new_password
        ) if new_password else None

        confirm_password_error = validate_password(
            confirm_password
        ) if confirm_password else None

        if (
            username_error
            or current_password_error
            or new_password_error
            or confirm_password_error
        ):

            connection.close()

            flash(
                username_error
                or current_password_error
                or new_password_error
                or confirm_password_error,
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        if not current_password:

            connection.close()

            flash(
                "Please enter your current password.",
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        if not new_username:

            connection.close()

            flash(
                "Username cannot be empty.",
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        if len(new_username) < 3:

            connection.close()

            flash(
                "Username must be at least 3 characters.",
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        cursor.execute(
            """
            SELECT password
            FROM admin_accounts
            WHERE id = ?
            """,
            (session.get("admin_id"),)
        )

        stored_password = cursor.fetchone()[0]

        if not check_password_hash(
            stored_password,
            current_password
        ):

            connection.close()

            flash(
                "Current password is incorrect.",
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        if new_password:

            if len(new_password) < 8:

                connection.close()

                flash(
                    "New password must be at least 8 characters.",
                    "error"
                )

                return redirect(
                    url_for("admin_settings")
                )


            if new_password != confirm_password:

                connection.close()

                flash(
                    "New passwords do not match.",
                    "error"
                )

                return redirect(
                    url_for("admin_settings")
                )


        cursor.execute(
            """
            SELECT id
            FROM admin_accounts
            WHERE username = ?
            AND id != ?
            """,
            (
                new_username,
                session.get("admin_id")
            )
        )


        duplicate_username = cursor.fetchone()


        if duplicate_username:

            connection.close()

            flash(
                "That username is already in use.",
                "error"
            )

            return redirect(
                url_for("admin_settings")
            )


        if new_password:

            hashed_password = generate_password_hash(
                new_password
            )

            cursor.execute(
                """
                UPDATE admin_accounts
                SET
                    username = ?,
                    password = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    new_username,
                    hashed_password,
                    session.get("admin_id")
                )
            )

        else:

            cursor.execute(
                """
                UPDATE admin_accounts
                SET
                    username = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    new_username,
                    session.get("admin_id")
                )
            )
        connection.commit()
        connection.close()

        audit_log(
            user_type="admin",
            action="account_update",
            user_id=session.get("admin_id"),
            details="Admin account credentials were updated."
        )


        # Force a fresh login after changing credentials.
        session.clear()


       


        flash(
            "Admin account updated successfully. "
            "Please log in again with your new credentials.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    connection.close()


    return render_template(
        "admin_settings.html",
        admin_account=admin_account
    )


# ==================================================
# STUDENT STATUS
# ==================================================

@app.route(
    "/status",
    methods=["GET", "POST"]
)
def student_status():

    message = None
    error = None
    email = ""


    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        if not email:

            flash(
                "Please enter your email address.",
                "error"
            )

            return redirect(
                url_for("student_status")
            )


        connection = get_connection()
        cursor = connection.cursor()


        cursor.execute(
            f"""
            SELECT {MESSAGE_COLUMNS}
            FROM messages
            WHERE email = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                email,
            )
        )


        message = cursor.fetchone()

        connection.close()


        if message is None:

            flash(
                "No submission was found "
                "with this email address.",
                "error"
            )

            return redirect(
                url_for("student_status")
            )


    return render_template(
        "student_status.html",
        message=message,
        error=error,
        email=email
    )


# ==================================================
# VIEW MESSAGE
# ==================================================

@app.route(
    "/view_message/<int:message_id>"
)
def view_message(message_id):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    message = cursor.fetchone()


    if message is None:

        connection.close()

        flash(
            "Message not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )


    if message[7] == "New":

        cursor.execute(
            """
            UPDATE messages
            SET status = 'Read'
            WHERE id = ?
            """,
            (
                message_id,
            )
        )

        connection.commit()


        cursor.execute(
            f"""
            SELECT {MESSAGE_COLUMNS}
            FROM messages
            WHERE id = ?
            """,
            (
                message_id,
            )
        )


        message = cursor.fetchone()


    connection.close()


    return render_template(
        "view_message.html",
        message=message
    )


# ==================================================
# REPLY MESSAGE
# ==================================================

@app.route(
    "/reply_message/<int:message_id>",
    methods=["GET", "POST"]
)
def reply_message(message_id):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    message = cursor.fetchone()


    if message is None:

        connection.close()

        flash(
            "Message not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )


    if request.method == "POST":

        reply = request.form.get(
            "reply",
            ""
        ).strip()

        reply_error = validate_input(
            reply,
            "Reply",
            INPUT_LIMITS["reply"]
        )

        if reply_error:

            connection.close()

            flash(
                reply_error,
                "error"
            )

            return redirect(
                url_for(
                    "reply_message",
                    message_id=message_id
                )
            )


        if not reply:

            connection.close()

            flash(
                "Please write a reply.",
                "error"
            )

            return redirect(
                url_for(
                    "reply_message",
                    message_id=message_id
                )
            )


        student_email = message[2]
        student_name = message[1]


        try:

            email_message = Message(
                subject="Reply from Jemea",
                recipients=[
                    student_email
                ],
                sender=app.config[
                    "MAIL_USERNAME"
                ]
            )


            email_message.body = f"""
Hello {student_name},

Thank you for contacting Jemea.

Here is our reply to your idea:

{reply}

Best regards,
Jemea Team
"""


            mail.send(
                email_message
            )


            cursor.execute(
                """
                UPDATE messages
                SET
                    reply = ?,
                    status = 'Replied',
                    conversation_cleared = 0
                WHERE id = ?
                """,
                (
                    reply,
                    message_id
                )
            )


            cursor.execute(
                """
                INSERT INTO conversation_messages
                (
                    submission_id,
                    sender_type,
                    sender_name,
                    message
                )
                VALUES
                (
                    ?,
                    'admin',
                    'Jemea Team',
                    ?
                )
                """,
                (
                    message_id,
                    reply
                )
            )


            cursor.execute(
                """
                SELECT id
                FROM students
                WHERE email = ?
                """,
                (
                    student_email,
                )
            )


            student = cursor.fetchone()


            if student:

                cursor.execute(
                    """
                    INSERT INTO notifications
                    (
                        student_id,
                        submission_id,
                        title,
                        message,
                        is_read
                    )
                    VALUES
                    (
                        ?,
                        ?,
                        ?,
                        ?,
                        0
                    )
                    """,
                    (
                        student[0],
                        message_id,
                        "New reply from Jemea Team",
                        "The Jemea team has replied "
                        "to your conversation."
                    )
                )


            connection.commit()
            connection.close()


            flash(
                "Reply sent successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "view_message",
                    message_id=message_id
                )
            )


        except Exception as error:

            connection.close()

            app.logger.exception(
                "Admin reply email operation failed: %s",
                error
            )

            flash(
                "Email could not be sent. Please try again later.",
                "error"
            )

            return redirect(
                url_for(
                    "reply_message",
                    message_id=message_id
                )
            )


    connection.close()


    return render_template(
        "reply_message.html",
        message=message
    )


# ==================================================
# EDIT MESSAGE
# ==================================================

@app.route(
    "/edit_message/<int:message_id>",
    methods=["GET", "POST"]
)
def edit_message(message_id):

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    connection = get_connection()
    cursor = connection.cursor()

    # ==================================================
    # EDIT SUBMISSION
    # ==================================================

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        department = request.form.get(
            "department",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        message_text = request.form.get(
            "message",
            ""
        ).strip()

        validation_error = None

        for field_name, field_value, limit_key in [
            ("Name", name, "name"),
            ("Department", department, "department"),
            ("Year", year, "year"),
            ("Message", message_text, "message"),
        ]:

            validation_error = validate_input(
                field_value,
                field_name,
                INPUT_LIMITS[limit_key]
            )

            if validation_error:
                break

        if validation_error is None:

            validation_error = validate_email(
                email
            )

        if validation_error:

            connection.close()

            flash(
                validation_error,
                "error"
            )

            return redirect(
                url_for(
                    "edit_message",
                    message_id=message_id
                )
            )

        if (
            not name
            or not email
            or not department
            or not year
            or not message_text
        ):

            connection.close()

            flash(
                "Please complete all fields.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_message",
                    message_id=message_id
                )
            )

        cursor.execute(
            """
            UPDATE messages
            SET
                name = ?,
                email = ?,
                department = ?,
                year = ?,
                message = ?
            WHERE id = ?
            """,
            (
                name,
                email,
                department,
                year,
                message_text,
                message_id
            )
        )

        updated = cursor.rowcount

        connection.commit()
        connection.close()

        if updated > 0:

            audit_log(
                user_type="admin",
                action="edit_message",
                user_id=session.get("admin_id"),
                details=(
                    "Admin edited submission "
                    + str(message_id)
                )
            )

            flash(
                "Message updated successfully.",
                "success"
            )

        else:

            flash(
                "Message could not be updated.",
                "error"
            )

        return redirect(
            url_for("admin")
        )

    # ==================================================
    # LOAD EDIT PAGE
    # ==================================================

    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE id = ?
        """,
        (message_id,)
    )

    message = cursor.fetchone()

    connection.close()

    if message is None:

        flash(
            "Message not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    return render_template(
        "edit_message.html",
        message=message
    )

@app.route(
    "/bulk_update_status",
    methods=["POST"]
)
def bulk_update_status():

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    status = request.form.get(
        "status",
        ""
    )

    allowed_statuses = [
        "New",
        "Read",
        "Replied"
    ]

    if status not in allowed_statuses:

        flash(
            "Invalid status.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    message_ids = request.form.getlist(
        "message_ids"
    )

    clean_ids = []

    for message_id in message_ids:

        try:

            message_id = int(
                message_id
            )

            if message_id > 0:

                clean_ids.append(
                    message_id
                )

        except (
            TypeError,
            ValueError
        ):

            continue

    clean_ids = list(
        dict.fromkeys(
            clean_ids
        )
    )

    if not clean_ids:

        flash(
            "No messages selected.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    connection = get_connection()
    cursor = connection.cursor()

    updated_count = 0

    for message_id in clean_ids:

        cursor.execute(
            """
            SELECT
                email,
                name,
                status
            FROM messages
            WHERE id = ?
            """,
            (message_id,)
        )

        submission = cursor.fetchone()

        if not submission:
            continue

        old_status = submission[2]

        cursor.execute(
            """
            UPDATE messages
            SET status = ?
            WHERE id = ?
            """,
            (
                status,
                message_id
            )
        )

        if cursor.rowcount > 0:

            updated_count += 1

        if (
            old_status != status
            and status in [
                "Read",
                "Replied"
            ]
        ):

            cursor.execute(
                """
                SELECT id
                FROM students
                WHERE LOWER(email) = LOWER(?)
                """,
                (submission[0],)
            )

            student = cursor.fetchone()

            if student:

                if status == "Read":

                    title = (
                        "Your submission was read"
                    )

                    notification_message = (
                        "The Jemea team has read "
                        "your submission."
                    )

                else:

                    title = (
                        "Your submission was replied to"
                    )

                    notification_message = (
                        "The Jemea team has replied "
                        "to your submission."
                    )

                cursor.execute(
                    """
                    INSERT INTO notifications
                    (
                        student_id,
                        submission_id,
                        title,
                        message,
                        is_read
                    )
                    VALUES
                    (
                        ?,
                        ?,
                        ?,
                        ?,
                        0
                    )
                    """,
                    (
                        student[0],
                        message_id,
                        title,
                        notification_message
                    )
                )

    connection.commit()
    connection.close()

    audit_log(
        user_type="admin",
        action="bulk_status_change",
        user_id=session.get("admin_id"),
        details=(
            "Admin changed "
            + str(updated_count)
            + " submission(s) status to "
            + status
        )
    )

    flash(
        str(updated_count)
        + " message(s) changed to "
        + status
        + ".",
        "success"
    )

    return redirect(
        url_for("admin")
    )



# ==================================================
# UPDATE STATUS
# ==================================================

@app.route(
    "/update_status/<int:message_id>",
    methods=["POST"]
)
def update_status(message_id):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )

    status = request.form.get(
        "status",
        ""
    )

    allowed_statuses = [
        "New",
        "Read",
        "Replied"
    ]

    if status not in allowed_statuses:

        flash(
            "Invalid status.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            email,
            name,
            status
        FROM messages
        WHERE id = ?
        """,
        (message_id,)
    )

    submission = cursor.fetchone()

    if submission is None:

        connection.close()

        flash(
            "Submission not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    old_status = submission[2]

    cursor.execute(
        """
        UPDATE messages
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            message_id
        )
    )

    if (
        old_status != status
        and status in ["Read", "Replied"]
    ):

        cursor.execute(
            """
            SELECT id
            FROM students
            WHERE LOWER(email) = LOWER(?)
            """,
            (submission[0],)
        )

        student = cursor.fetchone()

        if student:

            if status == "Read":

                title = (
                    "Your submission was read"
                )

                notification_message = (
                    "The Jemea team has read "
                    "your submission."
                )

            else:

                title = (
                    "Your submission was replied to"
                )

                notification_message = (
                    "The Jemea team has replied "
                    "to your submission."
                )

            cursor.execute(
                """
                INSERT INTO notifications
                (
                    student_id,
                    submission_id,
                    title,
                    message,
                    is_read
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    0
                )
                """,
                (
                    student[0],
                    message_id,
                    title,
                    notification_message
                )
            )

    connection.commit()
    connection.close()

    audit_log(
        user_type="admin",
        action="status_change",
        user_id=session.get("admin_id"),
        details=(
            "Admin changed submission "
            + str(message_id)
            + " status from "
            + old_status
            + " to "
            + status
        )
    )

    flash(
        f"Status changed to {status}.",
        "success"
    )

    return redirect(
        url_for("admin")
    )









# ==================================================
# DELETE SUBMISSION
# ==================================================

@app.route(
    "/delete_message/<int:message_id>",
    methods=["POST"]
)
def delete_message(message_id):

    if not session.get("admin"):
        return redirect(
            url_for("login")
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, email
        FROM messages
        WHERE id = ?
        """,
        (message_id,)
    )

    submission = cursor.fetchone()

    if submission is None:

        connection.close()

        flash(
            "Submission not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    cursor.execute(
        """
        DELETE FROM notifications
        WHERE submission_id = ?
        """,
        (message_id,)
    )

    cursor.execute(
        """
        DELETE FROM conversation_messages
        WHERE submission_id = ?
        """,
        (message_id,)
    )

    cursor.execute(
        """
        DELETE FROM messages
        WHERE id = ?
        """,
        (message_id,)
    )

    deleted = cursor.rowcount

    connection.commit()
    connection.close()

    if deleted:

        audit_log(
            user_type="admin",
            action="delete_message",
            user_id=session.get("admin_id"),
            details=(
                "Admin deleted submission "
                + str(message_id)
                + " belonging to "
                + submission[1]
                + " ("
                + submission[2]
                + ")."
            )
        )

        flash(
            "Submission deleted successfully.",
            "success"
        )

    else:

        flash(
            "Submission could not be deleted.",
            "error"
        )

    return redirect(
        url_for("admin")
    )


# ==================================================
# ADMIN CONVERSATION
# ==================================================

@app.route(
    "/admin/conversation/<int:message_id>"
)
def admin_conversation(message_id):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    submission = cursor.fetchone()


    if submission is None:

        connection.close()

        flash(
            "Submission not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )


    if submission[7] == "New":

        cursor.execute(
            """
            UPDATE messages
            SET status = 'Read'
            WHERE id = ?
            """,
            (
                message_id,
            )
        )

        connection.commit()


        cursor.execute(
            f"""
            SELECT {MESSAGE_COLUMNS}
            FROM messages
            WHERE id = ?
            """,
            (
                message_id,
            )
        )


        submission = cursor.fetchone()


    cursor.execute(
        """
        SELECT
            id,
            submission_id,
            sender_type,
            sender_name,
            message,
            created_at
        FROM conversation_messages
        WHERE submission_id = ?
        ORDER BY id ASC
        """,
        (
            message_id,
        )
    )


    conversation = cursor.fetchall()


    cursor.execute(
        """
        SELECT conversation_cleared
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    cleared_result = cursor.fetchone()


    conversation_cleared = 0


    if cleared_result:

        conversation_cleared = cleared_result[0]


    if (
        not conversation
        and conversation_cleared == 0
    ):

        cursor.execute(
            """
            INSERT INTO conversation_messages
            (
                submission_id,
                sender_type,
                sender_name,
                message
            )
            VALUES
            (
                ?,
                'student',
                ?,
                ?
            )
            """,
            (
                message_id,
                submission[1],
                submission[5]
            )
        )


        if submission[8]:

            cursor.execute(
                """
                INSERT INTO conversation_messages
                (
                    submission_id,
                    sender_type,
                    sender_name,
                    message
                )
                VALUES
                (
                    ?,
                    'admin',
                    'Jemea Team',
                    ?
                )
                """,
                (
                    message_id,
                    submission[8]
                )
            )


        connection.commit()


        cursor.execute(
            """
            SELECT
                id,
                submission_id,
                sender_type,
                sender_name,
                message,
                created_at
            FROM conversation_messages
            WHERE submission_id = ?
            ORDER BY id ASC
            """,
            (
                message_id,
            )
        )


        conversation = cursor.fetchall()


    connection.close()


    return render_template(
        "admin_conversation.html",
        submission=submission,
        conversation=conversation
    )


# ==================================================
# ADMIN SEND CONVERSATION MESSAGE
# ==================================================

@app.route(
    "/admin/conversation/<int:message_id>/send",
    methods=["POST"]
)
def admin_send_message(message_id):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    message_text = request.form.get(
        "message",
        ""
    ).strip()

    message_error = validate_input(
        message_text,
        "Message",
        INPUT_LIMITS["message"]
    )

    if message_error:

        flash(
            message_error,
            "error"
        )
        return redirect(
    url_for(
        "admin_conversation",
        message_id=message_id
    )
)

    if not message_text:

        flash(
            "Please write a message.",
            "error"
        )

        return redirect(
            url_for(
                "admin_conversation",
                message_id=message_id
            )
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    submission = cursor.fetchone()


    if submission is None:

        connection.close()

        flash(
            "Submission not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )


    student_email = submission[2]
    student_name = submission[1]


    try:

        email_message = Message(
            subject="New message from Jemea",
            recipients=[
                student_email
            ],
            sender=app.config[
                "MAIL_USERNAME"
            ]
        )


        email_message.body = f"""
Hello {student_name},

You have received a new message from Jemea.

Message:

{message_text}

Best regards,
Jemea Team
"""


        mail.send(
            email_message
        )


        cursor.execute(
            """
            INSERT INTO conversation_messages
            (
                submission_id,
                sender_type,
                sender_name,
                message
            )
            VALUES
            (
                ?,
                'admin',
                'Jemea Team',
                ?
            )
            """,
            (
                message_id,
                message_text
            )
        )


        cursor.execute(
            """
            UPDATE messages
            SET
                reply = ?,
                status = 'Replied',
                conversation_cleared = 0
            WHERE id = ?
            """,
            (
                message_text,
                message_id
            )
        )


        cursor.execute(
            """
            SELECT id
            FROM students
            WHERE email = ?
            """,
            (
                student_email,
            )
        )


        student = cursor.fetchone()


        if student:

            cursor.execute(
                """
                INSERT INTO notifications
                (
                    student_id,
                    submission_id,
                    title,
                    message,
                    is_read
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    0
                )
                """,
                (
                    student[0],
                    message_id,
                    "New reply from Jemea Team",
                    "The Jemea team has sent "
                    "you a new message."
                )
            )
        connection.commit()
        connection.close()

        audit_log(
            user_type="admin",
            action="conversation_message",
            user_id=session.get("admin_id"),
            details=(
                "Admin sent a message in submission "
                + str(message_id)
            )
        )


        flash(
            "Message sent successfully.",
            "success"
        )


       


        return redirect(
            url_for(
                "admin_conversation",
                message_id=message_id
            )
        )


    except Exception as error:

        connection.close()

        app.logger.exception(
            "Admin conversation email operation failed: %s",
            error
        )

        flash(
            "Email could not be sent. Please try again later.",
            "error"
        )


        return redirect(
            url_for(
                "admin_conversation",
                message_id=message_id
            )
        )


# ==================================================
# ADMIN DELETE SELECTED CONVERSATION MESSAGES
# ==================================================

@app.route(
    "/admin/conversation/<int:message_id>/delete",
    methods=["POST"]
)
def admin_delete_conversation_messages(
    message_id
):

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    selected_ids = request.form.getlist(
        "message_ids"
    )


    if not selected_ids:

        flash(
            "Please select at least one message.",
            "warning"
        )

        return redirect(
            url_for(
                "admin_conversation",
                message_id=message_id
            )
        )
    valid_ids = []
    for message_id_value in selected_ids:
        try:
            message_id_value = int(
                message_id_value
            )
            if message_id_value>0:
                valid_ids.append(
                    message_id_value

                )
        except(TypeError,ValueError):
            continue
        valid_ids = list(
            dict.fromkeys(valid_ids)
        )



  


    if not valid_ids:

        flash(
            "No valid messages were selected.",
            "error"
        )

        return redirect(
            url_for(
                "admin_conversation",
                message_id=message_id
            )
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT id
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    submission_exists = cursor.fetchone()


    if submission_exists is None:

        connection.close()

        flash(
            "Submission not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM conversation_messages
        WHERE submission_id = ?
        """,
        (
            message_id,
        )
    )


    total_conversation_messages = (
        cursor.fetchone()[0]
    )


    placeholders = ",".join(
        "?"
        for _ in valid_ids
    )


    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM conversation_messages
        WHERE
            submission_id = ?
            AND id IN ({placeholders})
        """,
        [
            message_id,
            *valid_ids
        ]
    )


    selected_existing_count = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        f"""
        DELETE FROM conversation_messages
        WHERE
            submission_id = ?
            AND id IN ({placeholders})
        """,
        [
            message_id,
            *valid_ids
        ]
    )


    remaining_count = (
        total_conversation_messages
        - selected_existing_count
    )


    if remaining_count <= 0:

        cursor.execute(
            """
            UPDATE messages
            SET
                conversation_cleared = 1,
                reply = ''
            WHERE id = ?
            """,
            (
                message_id,
            )
        )

    connection.commit()
    connection.close()


    flash(
        "Selected conversation messages deleted.",
        "success"
    )


    return redirect(
        url_for(
            "admin_conversation",
            message_id=message_id
        )
    )


# ==================================================
# STUDENT REGISTER
# ==================================================

@app.route(
    "/student/register",
    methods=["GET", "POST"]
)
def student_register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        department = request.form.get(
            "department",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        validation_error = None

        for field_name, field_value, limit_key in [
            ("Name", name, "name"),
            ("Department", department, "department"),
            ("Year", year, "year"),
        ]:
            validation_error = validate_input(
                field_value,
                field_name,
                INPUT_LIMITS[limit_key]
            )

            if validation_error:
                break

        if validation_error is None:
            validation_error = validate_email(email)

        if validation_error is None:
            validation_error = validate_password(password)

        if validation_error:

            flash(
                validation_error,
                "error"
            )

            return redirect(
                url_for("student_register")
            )


        if (
            not name
            or not email
            or not password
            or not department
            or not year
        ):

            flash(
                "Please complete all fields.",
                "error"
            )

            return redirect(
                url_for("student_register")
            )


        if (
            "@"
            not in email
            or "."
            not in email
        ):

            flash(
                "Please enter a valid email.",
                "error"
            )

            return redirect(
                url_for("student_register")
            )


        if len(password) < 4:

            flash(
                "Password must be at least 4 characters.",
                "error"
            )

            return redirect(
                url_for("student_register")
            )


        password_hash = (
            generate_password_hash(password)
        )


        connection = get_connection()
        cursor = connection.cursor()


        try:

            cursor.execute(
                """
                INSERT INTO students
                (
                    name,
                    email,
                    password,
                    department,
                    year
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
                """,
                (
                    name,
                    email,
                    password_hash,
                    department,
                    year
                )
            )


            connection.commit()
            connection.close()


            flash(
                "Registration successful. "
                "You can now log in.",
                "success"
            )


            return redirect(
                url_for("student_login")
            )


        except sqlite3.IntegrityError:

            connection.close()


            flash(
                "An account with this email "
                "already exists.",
                "error"
            )


            return redirect(
                url_for("student_register")
            )


    return render_template(
        "student_register.html"
    )


# ==================================================
# STUDENT LOGIN
# ==================================================

@app.route(
    "/student/login",
    methods=["GET", "POST"]
)
def student_login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        email_error = validate_email(email)
        password_error = validate_password(password)

        if email_error or password_error:

            flash(
                email_error or password_error,
                "error"
            )

            return redirect(
                url_for("student_login")
            )

        login_identifier = (
            "student:"
            + (
                request.remote_addr
                or "unknown"
            )
            + ":"
            + email
        )

        if is_login_blocked(login_identifier):

            flash(
                "Too many failed login attempts. "
                "Please try again in 5 minutes.",
                "error"
            )

            return redirect(
                url_for("student_login")
            )


        connection = get_connection()
        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT
                id,
                name,
                email,
                password,
                department,
                year
            FROM students
            WHERE email = ?
            """,
            (
                email,
            )
        )


        student = cursor.fetchone()

        connection.close()


        if (
            student
            and check_password_hash(
                student[3],
                password
            )
        ):

            # Start a fresh session after successful student login.
            session.clear()

            session["student_id"] = student[0]
            session["student_email"] = student[2]
            audit_log(
    user_type="student",
    action="login",
    user_id=student[0],
    details="Student logged in successfully."
)
            

            clear_failed_logins(
                login_identifier
            )


            flash(
                f"Welcome back, {student[1]}!",
                "success"
            )


            return redirect(
                url_for(
                    "student_dashboard"
                )
            )


        record_failed_login(
            login_identifier
        )
        audit_log(
    user_type="student",
    action="failed_login",
    user_id=None,
    details="Failed student login attempt."
)
   

        flash(
            "Wrong email or password.",
            "error"
        )
        audit_log(
    user_type="student",
    action="failed_login",
    user_id=None,
    details="Failed student login attempt."
)



        return redirect(
            url_for("student_login")
        )


    return render_template(
        "student_login.html"
    )


# ==================================================
# STUDENT DASHBOARD
# ==================================================

@app.route(
    "/student/dashboard"
)
def student_dashboard():

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    student_email = session.get(
        "student_email"
    )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            id,
            name,
            email,
            created_at,
            department,
            year
        FROM students
        WHERE id = ?
        """,
        (
            session["student_id"],
        )
    )


    student = cursor.fetchone()


    if student is None:

        connection.close()

        session.pop(
            "student_id",
            None
        )

        session.pop(
            "student_email",
            None
        )


        flash(
            "Your student account could not be found.",
            "error"
        )


        return redirect(
            url_for("student_login")
        )


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        WHERE LOWER(email) = LOWER(?)
        ORDER BY id DESC
        """,
        (
            student_email,
        )
    )


    submissions = cursor.fetchall()


    messages = submissions


    total_submissions = len(
        submissions
    )


    new_submissions = sum(
        1
        for submission in submissions
        if submission[7] == "New"
    )


    read_submissions = sum(
        1
        for submission in submissions
        if submission[7] == "Read"
    )


    replied_submissions = sum(
        1
        for submission in submissions
        if submission[7] == "Replied"
    )


    cursor.execute(
        """
        SELECT
            id,
            submission_id,
            title,
            message,
            is_read,
            created_at
        FROM notifications
        WHERE student_id = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (
            session["student_id"],
        )
    )


    notifications = cursor.fetchall()


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM notifications
        WHERE
            student_id = ?
            AND is_read = 0
        """,
        (
            session["student_id"],
        )
    )


    unread_notifications = (
    cursor.fetchone()[0]
)


    cursor.execute(
    """
    SELECT
        id,
        submission_id,
        title,
        message,
        created_at
    FROM notifications
    WHERE student_id = ?
    ORDER BY id DESC
    LIMIT 5
    """,
    (
        session["student_id"],
    )
)


    latest_activity = cursor.fetchall()


    connection.close()


    return render_template(
    "student_dashboard.html",

    student=student,

    messages=messages,

    submissions=submissions,

    total_submissions=total_submissions,

    new_submissions=new_submissions,

    read_submissions=read_submissions,

    replied_submissions=replied_submissions,

    notifications=notifications,

    unread_notifications=unread_notifications,

    latest_activity=latest_activity
)

# ==================================================
# STUDENT NOTIFICATIONS
# ==================================================

@app.route(
    "/student/notifications",
    endpoint="student_notifications_page"
)
def student_notifications_page():

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            id,
            submission_id,
            title,
            message,
            is_read,
            created_at
        FROM notifications
        WHERE student_id = ?
        ORDER BY id DESC
        """,
        (
            session["student_id"],
        )
    )


    notifications = cursor.fetchall()


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM notifications
        WHERE
            student_id = ?
            AND is_read = 0
        """,
        (
            session["student_id"],
        )
    )


    unread_notifications = (
        cursor.fetchone()[0]
    )


    connection.close()


    return render_template(
        "student_notifications.html",

        notifications=notifications,

        unread_notifications=unread_notifications
    )


# ==================================================
# COMPATIBILITY ENDPOINT
# ==================================================

def student_notifications_compatibility():

    return student_notifications_page()


try:

    app.add_url_rule(
        "/student/notifications",
        endpoint="student_notifications",
        view_func=student_notifications_compatibility
    )

except AssertionError:

    pass


# ==================================================
# MARK ONE NOTIFICATION AS READ
# ==================================================

@app.route(
    "/student/notifications/read/<int:notification_id>",
    methods=["POST"]
)
def mark_notification_read(
    notification_id
):

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE
            id = ?
            AND student_id = ?
        """,
        (
            notification_id,
            session["student_id"]
        )
    )


    connection.commit()
    connection.close()


    return redirect(
        url_for("student_notifications_page")
    )


# ==================================================
# MARK ALL NOTIFICATIONS AS READ
# ==================================================

@app.route(
    "/student/notifications/read-all",
    methods=["POST"]
)
def mark_all_notifications_read():

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE student_id = ?
        """,
        (
            session["student_id"],
        )
    )


    connection.commit()
    connection.close()


    flash(
        "All notifications marked as read.",
        "success"
    )


    return redirect(
        url_for("student_dashboard")
    )


# ==================================================
# STUDENT CONVERSATION
# ==================================================

@app.route(
    "/student/conversation/<int:message_id>"
)
def student_conversation(message_id):

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    student_email = session.get(
        "student_email"
    )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT
            {MESSAGE_COLUMNS}
        FROM messages
        WHERE
            id = ?
            AND LOWER(email) = LOWER(?)
        """,
        (
            message_id,
            student_email
        )
    )


    submission = cursor.fetchone()


    if submission is None:

        connection.close()

        flash(
            "Conversation not found.",
            "error"
        )


        return redirect(
            url_for(
                "student_dashboard"
            )
        )


    cursor.execute(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE
            student_id = ?
            AND submission_id = ?
        """,
        (
            session["student_id"],
            message_id
        )
    )


    cursor.execute(
        """
        SELECT conversation_cleared
        FROM messages
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    cleared_result = cursor.fetchone()


    conversation_cleared = 0


    if cleared_result:

        conversation_cleared = (
            cleared_result[0]
        )


    cursor.execute(
        """
        SELECT
            id,
            submission_id,
            sender_type,
            sender_name,
            message,
            created_at
        FROM conversation_messages
        WHERE submission_id = ?
        ORDER BY id ASC
        """,
        (
            message_id,
        )
    )


    conversation = cursor.fetchall()


    if (
        not conversation
        and conversation_cleared == 0
    ):

        cursor.execute(
            """
            INSERT INTO conversation_messages
            (
                submission_id,
                sender_type,
                sender_name,
                message
            )
            VALUES
            (
                ?,
                'student',
                ?,
                ?
            )
            """,
            (
                message_id,
                submission[1],
                submission[5]
            )
        )


        if submission[8]:

            cursor.execute(
                """
                INSERT INTO conversation_messages
                (
                    submission_id,
                    sender_type,
                    sender_name,
                    message
                )
                VALUES
                (
                    ?,
                    'admin',
                    'Jemea Team',
                    ?
                )
                """,
                (
                    message_id,
                    submission[8]
                )
            )


        connection.commit()


        cursor.execute(
            """
            SELECT
                id,
                submission_id,
                sender_type,
                sender_name,
                message,
                created_at
            FROM conversation_messages
            WHERE submission_id = ?
            ORDER BY id ASC
            """,
            (
                message_id,
            )
        )


        conversation = cursor.fetchall()


    connection.commit()
    connection.close()


    return render_template(
        "student_conversation.html",
        submission=submission,
        conversation=conversation
    )


# ==================================================
# STUDENT SEND CONVERSATION MESSAGE
# ==================================================

@app.route(
    "/student/conversation/<int:message_id>/send",
    methods=["POST"]
)
def student_send_message(message_id):

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    student_email = session.get(
        "student_email"
    )


    message_text = request.form.get(
        "message",
        ""
    ).strip()


    if not message_text:

        flash(
            "Please write a message.",
            "error"
        )


        return redirect(
            url_for(
                "student_conversation",
                message_id=message_id
            )
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        f"""
        SELECT
            {MESSAGE_COLUMNS}
        FROM messages
        WHERE
            id = ?
            AND LOWER(email) = LOWER(?)
        """,
        (
            message_id,
            student_email
        )
    )


    submission = cursor.fetchone()


    if submission is None:

        connection.close()

        flash(
            "You are not allowed to access "
            "this conversation.",
            "error"
        )


        return redirect(
            url_for(
                "student_dashboard"
            )
        )


    cursor.execute(
        """
        SELECT name
        FROM students
        WHERE id = ?
        """,
        (
            session["student_id"],
        )
    )


    student = cursor.fetchone()


    student_name = (
        student[0]
        if student
        else "Student"
    )


    cursor.execute(
        """
        INSERT INTO conversation_messages
        (
            submission_id,
            sender_type,
            sender_name,
            message
        )
        VALUES
        (
            ?,
            'student',
            ?,
            ?
        )
        """,
        (
            message_id,
            student_name,
            message_text
        )
    )


    cursor.execute(
        """
        UPDATE messages
        SET
            status = 'New',
            conversation_cleared = 0
        WHERE id = ?
        """,
        (
            message_id,
        )
    )


    connection.commit()
    connection.close()

    audit_log(
        user_type="student",
        action="conversation_message",
        user_id=session.get("student_id"),
        details=(
            "Student sent a message in submission "
            + str(message_id)
        )
    )


    flash(
        "Your message was sent.",
        "success"
    )


    return redirect(
        url_for(
            "student_conversation",
            message_id=message_id
        )
    )


# ==================================================
# STUDENT PROFILE
# ==================================================

@app.route(
    "/student/profile",
    methods=["GET", "POST"]
)
def student_profile():

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            id,
            name,
            email,
            department,
            year
        FROM students
        WHERE id = ?
        """,
        (
            session["student_id"],
        )
    )


    student = cursor.fetchone()


    if not student:

        connection.close()

        session.clear()

        return redirect(
            url_for("student_login")
        )


    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        department = request.form.get(
            "department",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        validation_error = None

        for field_name, field_value, limit_key in [
            ("Name", name, "name"),
            ("Department", department, "department"),
            ("Year", year, "year"),
        ]:
            validation_error = validate_input(
                field_value,
                field_name,
                INPUT_LIMITS[limit_key]
            )

            if validation_error:
                break

        if validation_error:

            flash(
                validation_error,
                "error"
            )

        elif (
            not name
            or not department
            or not year
        ):

            flash(
                "Please fill in all profile fields.",
                "error"
            )


        else:

            cursor.execute(
                """
                UPDATE students
                SET
                    name = ?,
                    department = ?,
                    year = ?
                WHERE id = ?
                """,
                (
                    name,
                    department,
                    year,
                    session["student_id"]
                )
            )
            connection.commit()

            audit_log(
                user_type="student",
                action="profile_update",
                user_id=session.get("student_id"),
                details="Student updated their profile."
            )


            session["student_name"] = name


           


            flash(
                "Your profile has been updated successfully.",
                "success"
            )


            connection.close()


            return redirect(
                url_for("student_profile")
            )


    connection.close()


    return render_template(
        "student_profile.html",
        student=student
    )


# ==================================================
# CHANGE STUDENT PASSWORD
# ==================================================

@app.route(
    "/student/change-password",
    methods=["GET", "POST"]
)
def student_change_password():

    if not session.get("student_id"):

        return redirect(
            url_for("student_login")
        )


    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        current_password_error = validate_password(
            current_password
        )

        new_password_error = validate_password(
            new_password
        )

        confirm_password_error = validate_password(
            confirm_password
        )

        if (
            current_password_error
            or new_password_error
            or confirm_password_error
        ):

            flash(
                current_password_error
                or new_password_error
                or confirm_password_error,
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        if not current_password:

            flash(
                "Please enter your current password.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        if not new_password:

            flash(
                "Please enter a new password.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        if len(new_password) < 8:

            flash(
                "New password must be at least 8 characters.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        if new_password != confirm_password:

            flash(
                "New passwords do not match.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        if current_password == new_password:

            flash(
                "New password must be different from "
                "your current password.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        connection = get_connection()
        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT password
            FROM students
            WHERE id = ?
            """,
            (
                session["student_id"],
            )
        )


        result = cursor.fetchone()


        if not result:

            connection.close()

            session.clear()

            return redirect(
                url_for("student_login")
            )


        stored_password = result[0]


        if not check_password_hash(
            stored_password,
            current_password
        ):

            connection.close()

            flash(
                "Current password is incorrect.",
                "error"
            )

            return redirect(
                url_for(
                    "student_change_password"
                )
            )


        hashed_password = generate_password_hash(
            new_password
        )


        cursor.execute(
            """
            UPDATE students
            SET password = ?
            WHERE id = ?
            """,
            (
                hashed_password,
                session["student_id"]
            )
        )


        connection.commit()
        connection.close()

        audit_log(
            user_type="student",
            action="password_change",
            user_id=session.get("student_id"),
            details="Student changed their password successfully."
        )

        flash(
            "Your password has been changed successfully.",
            "success"
        )


        return redirect(
            url_for("student_profile")
        )


    return render_template(
        "student_change_password.html"
    )


# ==================================================
# STUDENT LOGOUT
# ==================================================

@app.route(
    "/student/logout"
)
def student_logout():

    # Save the student ID before clearing the session.
    student_id = session.get(
        "student_id"
    )

    audit_log(
        user_type="student",
        action="logout",
        user_id=student_id,
        details="Student logged out."
    )

    # Clear the entire session so no old role/session data remains.
    session.clear()


    flash(
        "You have been logged out.",
        "success"
    )


    return redirect(
        url_for("student_login")
    )

# ==================================================
# ADMIN LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    admin_id = session.get(
        "admin_id"
    )

    audit_log(
        user_type="admin",
        action="logout",
        user_id=admin_id,
        details="Admin logged out."
    )

    session.pop(
        "admin",
        None
    )

    session.pop(
        "admin_id",
        None
    )

    session.pop(
        "admin_username",
        None
    )


    flash(
        "You have been logged out.",
        "success"
    )


    return redirect(
        url_for("login")
    )


# ==================================================
# ADMIN ANALYTICS
# ==================================================

@app.route("/admin/analytics")
def admin_analytics():

    if not session.get("admin"):

        return redirect(
            url_for("login")
        )


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute(
        "SELECT COUNT(*) FROM messages"
    )

    total_messages = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'New'
        """
    )

    new_messages = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'Read'
        """
    )

    read_messages = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE status = 'Replied'
        """
    )

    replied_messages = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT department, COUNT(*)
        FROM messages
        GROUP BY department
        ORDER BY COUNT(*) DESC, department ASC
        """
    )

    department_rows = (
        cursor.fetchall()
    )


    cursor.execute(
        """
        SELECT year, COUNT(*)
        FROM messages
        GROUP BY year
        ORDER BY year ASC
        """
    )

    year_rows = (
        cursor.fetchall()
    )


    cursor.execute(
        """
        SELECT DATE(created_at), COUNT(*)
        FROM messages
        WHERE DATE(created_at)
            >= DATE('now', '-29 days')
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at) ASC
        """
    )

    daily_rows = (
        cursor.fetchall()
    )


    cursor.execute(
        """
        SELECT
            DATE(
                created_at,
                'start of month'
            ) AS month,
            COUNT(*)
        FROM messages
        GROUP BY
            DATE(
                created_at,
                'start of month'
            )
        ORDER BY month DESC
        LIMIT 12
        """
    )

    monthly_rows = (
        cursor.fetchall()
    )


    monthly_rows.reverse()


    cursor.execute(
        f"""
        SELECT {MESSAGE_COLUMNS}
        FROM messages
        ORDER BY id DESC
        LIMIT 8
        """
    )

    recent_messages = (
        cursor.fetchall()
    )


    connection.close()


    return render_template(
        "admin_analytics.html",

        total_messages=total_messages,

        new_messages=new_messages,

        read_messages=read_messages,

        replied_messages=replied_messages,

        department_labels=[
            row[0]
            for row in department_rows
        ],

        department_values=[
            row[1]
            for row in department_rows
        ],

        year_labels=[
            row[0]
            for row in year_rows
        ],

        year_values=[
            row[1]
            for row in year_rows
        ],

        daily_labels=[
            row[0]
            for row in daily_rows
        ],

        daily_values=[
            row[1]
            for row in daily_rows
        ],

        monthly_labels=[
            row[0]
            for row in monthly_rows
        ],

        monthly_values=[
            row[1]
            for row in monthly_rows
        ],

        recent_messages=recent_messages
    )


# ==================================================
# SECURITY #8 - GLOBAL ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def page_not_found(error):

    app.logger.warning(
        "404 error: %s - path=%s",
        error,
        request.path
    )

    return (
        "Page not found.",
        404
    )


@app.errorhandler(405)
def method_not_allowed(error):

    app.logger.warning(
        "405 error: %s - path=%s method=%s",
        error,
        request.path,
        request.method
    )

    return (
        "Method not allowed.",
        405
    )


@app.errorhandler(500)
def internal_server_error(error):

    app.logger.error(
        "Unhandled Jemea server error: %s",
        error,
        exc_info=True
    )

    return (
        "Something went wrong. Please try again later.",
        500
    )


# ==================================================
# START APPLICATION
# ==================================================
@app.route("/admin/audit-logs")
def admin_audit_logs():
    if not session.get("admin"):
        return redirect(url_for("login"))

    search = request.args.get(
        "search",
        ""
    ).strip()

    user_type = request.args.get(
        "user_type",
        ""
    ).strip().lower()

    action = request.args.get(
        "action",
        ""
    ).strip()

    try:
        page = int(
            request.args.get(
                "page",
                1
            )
        )
    except (TypeError, ValueError):
        page = 1

    if page < 1:
        page = 1

    per_page = 15

    connection = get_connection()
    cursor = connection.cursor()

    where_clauses = []
    params = []

    if search:
        where_clauses.append(
            """
            (
                CAST(user_id AS TEXT) LIKE ?
                OR action LIKE ?
                OR details LIKE ?
                OR ip_address LIKE ?
            )
            """
        )

        search_value = "%" + search + "%"

        params.extend(
            [
                search_value,
                search_value,
                search_value,
                search_value,
            ]
        )

    if user_type in (
        "admin",
        "student"
    ):
        where_clauses.append(
            "user_type = ?"
        )

        params.append(
            user_type
        )
    else:
        user_type = ""

    if action:
        where_clauses.append(
            "action = ?"
        )

        params.append(
            action
        )

    where_sql = ""

    if where_clauses:
        where_sql = (
            "WHERE "
            + " AND ".join(
                where_clauses
            )
        )

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM audit_logs
        {where_sql}
        """,
        params
    )

    total_logs = cursor.fetchone()[0]

    total_pages = max(
        1,
        (
            total_logs
            + per_page
            - 1
        ) // per_page
    )

    if page > total_pages:
        page = total_pages

    offset = (
        page - 1
    ) * per_page

    cursor.execute(
        f"""
        SELECT
            id,
            user_type,
            user_id,
            action,
            details,
            ip_address,
            created_at
        FROM audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        [
            *params,
            per_page,
            offset
        ]
    )

    logs = cursor.fetchall()

    cursor.execute(
        """
        SELECT DISTINCT action
        FROM audit_logs
        WHERE action IS NOT NULL
          AND action != ''
        ORDER BY action
        """
    )

    actions = [
        row[0]
        for row in cursor.fetchall()
    ]

    connection.close()

    return render_template(
        "admin_audit_logs.html",
        logs=logs,
        search=search,
        user_type=user_type,
        action=action,
        actions=actions,
        page=page,
        total_pages=total_pages,
        total_logs=total_logs,
    )

if __name__ == "__main__":

    app.run(
        debug=True
    )
