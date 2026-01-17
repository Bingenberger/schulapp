from app import app, db, User, Schueler, Bogen, Item
from werkzeug.security import generate_password_hash

# App-Kontext herstellen
with app.app_context():
    print("--- Starte Datenbank-Reparatur ---")
    
    # 1. ADMIN USER PRÜFEN
    # Wir suchen den Admin
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        print("Erstelle Admin-User...")
        # Neues Passwort hashen (ohne Methode, für Kompatibilität)
        pw_hash = generate_password_hash("schule123")
        admin = User(username='admin', password_hash=pw_hash)
        db.session.add(admin)
    else:
        print("Admin existiert bereits. Setze Passwort zurück auf 'schule123'...")
        admin.password_hash = generate_password_hash("schule123")

    # ALLES SPEICHERN
    db.session.commit()
    print("--- FERTIG! Alle Daten wurden gespeichert. ---")
