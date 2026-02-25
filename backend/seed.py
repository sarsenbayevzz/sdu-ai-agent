import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import init_db, get_db, hash_password, latlng_to_h3

def seed():
    init_db()
    db = get_db()

    users = [
        ("azhar",    "azhar@sdu.edu.kz",    "admin123",   "admin"),
        ("aziz",     "aziz@sdu.edu.kz",     "student123", "student"),
        ("kamiliya", "kamiliya@sdu.edu.kz", "advisor123", "advisor"),
        ("dana",     "dana@sdu.edu.kz",     "student123", "student"),
    ]
    for username, email, pw, role in users:
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, role, sharing_enabled) VALUES (?,?,?,?,1)",
                (username, email, hash_password(pw), role),
            )
        except Exception:
            pass

    aziz_id = db.execute("SELECT id FROM users WHERE username='aziz'").fetchone()["id"]
    dana_id = db.execute("SELECT id FROM users WHERE username='dana'").fetchone()["id"]

    try:
        db.execute(
            "INSERT INTO friendships (user_a, user_b, status) VALUES (?,?,'accepted')",
            (aziz_id, dana_id),
        )
    except Exception:
        pass

    for uid, lat, lng in [(aziz_id, 51.0890, 71.4100), (dana_id, 51.0885, 71.4115)]:
        h3i = latlng_to_h3(lat, lng)
        db.execute("INSERT INTO locations (user_id, lat, lng, h3_index) VALUES (?,?,?,?)", (uid, lat, lng, h3i))
        db.execute(
            "INSERT INTO location_stats (h3_index, user_count) VALUES (?,1) "
            "ON CONFLICT(h3_index) DO UPDATE SET user_count=user_count+1",
            (h3i,),
        )

    db.commit()
    db.close()
    print("Database seeded.")
    print("\nDemo accounts:")
    print("  Admin:   azhar@sdu.edu.kz   / admin123")
    print("  Student: aziz@sdu.edu.kz    / student123")
    print("  Advisor: kamiliya@sdu.edu.kz / advisor123")
    print("  Student: dana@sdu.edu.kz    / student123")

if __name__ == "__main__":
    seed()
