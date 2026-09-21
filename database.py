import sqlite3


DATABASE_NAME = "jemea.db"


def get_database_connection():

    connection = sqlite3.connect(
        DATABASE_NAME,
        timeout=10
    )

    # Make SQLite enforce foreign-key relationships.
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def create_database():

    connection = get_database_connection()
    cursor = connection.cursor()

    # =====================================================
    # MESSAGES TABLE
    # =====================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            email TEXT NOT NULL,
            department TEXT NOT NULL,
            year TEXT NOT NULL,
            reply TEXT DEFAULT ''
        )
        """
    )

    # =====================================================
    # STUDENTS TABLE
    # =====================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            department TEXT NOT NULL,
            year TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # =====================================================
    # CONVERSATION MESSAGES TABLE
    # =====================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS conversation_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            submission_id INTEGER NOT NULL,

            sender_type TEXT NOT NULL,

            sender_name TEXT NOT NULL,

            message TEXT NOT NULL,

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (submission_id)
                REFERENCES messages(id)
                ON DELETE CASCADE
        )
        """
    )

    # =====================================================
    # DATABASE INDEXES
    # =====================================================

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_conversation_submission
        ON conversation_messages(submission_id)
        """
    )

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
        idx_messages_created_at
        ON messages(created_at)
        """
    )

    # =====================================================
    # DATABASE CLEANUP
    # =====================================================

    # Remove conversation records whose submission
    # no longer exists.
    #
    # This is safe because these records cannot belong
    # to an existing submission.

    cursor.execute(
        """
        DELETE FROM conversation_messages
        WHERE submission_id NOT IN (
            SELECT id
            FROM messages
        )
        """
    )

    connection.commit()
    connection.close()


def cleanup_database():

    connection = get_database_connection()
    cursor = connection.cursor()

    try:

        # =================================================
        # REMOVE ORPHANED CONVERSATION MESSAGES
        # =================================================

        cursor.execute(
            """
            DELETE FROM conversation_messages
            WHERE submission_id NOT IN (
                SELECT id
                FROM messages
            )
            """
        )

        # =================================================
        # CHECK DATABASE INTEGRITY
        # =================================================

        cursor.execute(
            """
            PRAGMA integrity_check
            """
        )

        integrity_result = cursor.fetchone()

        # =================================================
        # CHECK FOREIGN-KEY CONSISTENCY
        # =================================================

        cursor.execute(
            """
            PRAGMA foreign_key_check
            """
        )

        foreign_key_errors = cursor.fetchall()

        connection.commit()

        return {
            "integrity": (
                integrity_result[0]
                if integrity_result
                else "unknown"
            ),
            "foreign_key_errors": len(
                foreign_key_errors
            )
        }

    finally:

        connection.close()
        create_database()