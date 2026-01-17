import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import pandas as pd
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps # NEU: Für Bildbearbeitung

app = Flask(__name__)
app.config['SECRET_KEY'] = 'geheim' # Ändern Sie das für Produktion
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///schule.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Wohin werden nicht-eingeloggte User geschickt?

# Ordner für Uploads erstellen, falls nicht vorhanden
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# --- DATENBANK MODELLE ---
class Schueler(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vorname = db.Column(db.String(100))
    nachname = db.Column(db.String(100))
    klasse = db.Column(db.String(20))

class Bogen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titel = db.Column(db.String(100))
    items = db.relationship('Item', backref='bogen', lazy=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bogen_id = db.Column(db.Integer, db.ForeignKey('bogen.id'))
    text = db.Column(db.String(200))
    bereich = db.Column(db.String(100))

class Beobachtung(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datum = db.Column(db.DateTime, default=datetime.utcnow)
    wert = db.Column(db.Integer)
    kommentar = db.Column(db.Text)
    foto_pfad = db.Column(db.String(200))
    # NEU: Der Titel des Durchlaufs (z.B. "Test 1")
    anlass = db.Column(db.String(100))

    schueler_id = db.Column(db.Integer, db.ForeignKey('schueler.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

def komprimiere_und_speichere(file_storage, ziel_pfad):
    """
    Nimmt ein hochgeladenes Bild, korrigiert die Drehung,
    verkleinert es auf max 1024px Kantenlänge und speichert es als JPG.
    """
    try:
        # 1. Bild öffnen
        img = Image.open(file_storage)

        # 2. Drehung korrigieren (Handy-Fotos liegen oft "falsch" und haben nur ein EXIF-Flag)
        img = ImageOps.exif_transpose(img)

        # 3. Wenn es ein PNG/RGBA ist, in RGB umwandeln (JPG kann keine Transparenz)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # 4. Verkleinern (Maximal 1024x1024 Pixel, Seitenverhältnis bleibt erhalten)
        img.thumbnail((1024, 1024))

        # 5. Speichern mit Kompression (Quality=80 ist ein guter Kompromiss)
        img.save(ziel_pfad, "JPEG", quality=80, optimize=True)

        return True
    except Exception as e:
        print(f"Fehler beim Komprimieren: {e}")
        return False

# Hilfsfunktion für Flask-Login, um User zu laden
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES (Die Logik) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        # Prüfen ob User existiert UND Passwort stimmt
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Benutzername oder Passwort falsch!')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Erfolgreich ausgeloggt.')
    return redirect(url_for('login'))

# PASSWORT ÄNDERN
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        altes_pw = request.form.get('altes_pw')
        neues_pw = request.form.get('neues_pw')
        neues_pw_wdh = request.form.get('neues_pw_wdh')

        # 1. Prüfen: Stimmt das alte Passwort?
        if not check_password_hash(current_user.password_hash, altes_pw):
            flash('Das alte Passwort ist falsch!')
            return redirect(url_for('change_password'))

        # 2. Prüfen: Stimmen die neuen Passwörter überein?
        # HIER WAR DER FEHLER (new_pw -> neues_pw)
        if neues_pw != neues_pw_wdh:
            flash('Die neuen Passwörter stimmen nicht überein!')
            return redirect(url_for('change_password'))

        # 3. Speichern
        # Auch hier sicherheitshalber 'neues_pw' nutzen
        current_user.password_hash = generate_password_hash(neues_pw)
        db.session.commit()

        flash('Passwort erfolgreich geändert!')
        return redirect(url_for('index'))

    return render_template('change_password.html')

@app.route('/')
@login_required   # <--- DAS HIER EINFÜGEN
def index():
    return render_template('index.html')

# 1 & 2: IMPORT
@app.route('/import/<typ>', methods=['GET', 'POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def data_import(typ):
    if request.method == 'POST':
        file = request.files['file']
        if file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)
            if typ == 'schueler':
                # Erwartet Excel Spalten: Vorname, Nachname, Klasse
                for _, row in df.iterrows():
                    s = Schueler(vorname=row['Vorname'], nachname=row['Nachname'], klasse=row['Klasse'])
                    db.session.add(s)
            elif typ == 'bogen':
                # Erwartet Excel Spalten: Bogen, Bereich, Item
                # Dies ist vereinfacht. In Produktion prüfen, ob Bogen schon existiert.
                # Hier nehmen wir an, der Bogenname in der ersten Zeile gilt.
                current_bogen = None
                for _, row in df.iterrows():
                    bogen_titel = row['Bogen']
                    # Prüfen ob Bogen existiert, sonst erstellen
                    exist_bogen = Bogen.query.filter_by(titel=bogen_titel).first()
                    if not exist_bogen:
                        exist_bogen = Bogen(titel=bogen_titel)
                        db.session.add(exist_bogen)
                        db.session.flush() # ID generieren
                    
                    item = Item(bogen_id=exist_bogen.id, bereich=row['Bereich'], text=row['Item'])
                    db.session.add(item)
            
            db.session.commit()
            flash(f'{typ.capitalize()} erfolgreich importiert!')
            return redirect(url_for('index'))
    return render_template('import.html', typ=typ)

# 3a: START DER REIHENABFRAGE (Setup)
@app.route('/erfassen/reihe/start', methods=['GET', 'POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def reihe_start():
    if request.method == 'POST':
        # 1. Einstellungen aus Formular holen
        item_id = request.form.get('item_id')
        anlass = request.form.get('anlass')
        datum_str = request.form.get('datum') # Kommt als String YYYY-MM-DD

        # 2. Liste aller Schüler-IDs holen (Sortiert nach Nachname)
        schueler = Schueler.query.order_by(Schueler.nachname).all()
        schueler_ids = [s.id for s in schueler]

        # 3. Alles in der Session speichern (Browser-Gedächtnis)
        session['reihe_item_id'] = item_id
        session['reihe_anlass'] = anlass
        session['reihe_datum'] = datum_str
        session['reihe_ids'] = schueler_ids
        session['reihe_index'] = 0 # Wir starten beim ersten Kind (Index 0)

        return redirect(url_for('reihe_schueler'))

    # Zeige das Setup-Formular
    return render_template('reihe_start.html', boegen=Bogen.query.all())

# 3b: DAS AKTUELLE KIND ANZEIGEN
@app.route('/erfassen/reihe/schueler')
@login_required   # <--- DAS HIER EINFÜGEN
def reihe_schueler():
    # Sicherheitscheck: Läuft überhaupt eine Reihe?
    if 'reihe_ids' not in session or session['reihe_index'] >= len(session['reihe_ids']):
        flash('Reihenabfrage beendet!')
        return redirect(url_for('index'))

    # Aktuelle Daten laden
    current_student_id = session['reihe_ids'][session['reihe_index']]
    schueler = Schueler.query.get(current_student_id)
    item = Item.query.get(session['reihe_item_id'])

    # Fortschritt berechnen (z.B. "Kind 3 von 25")
    progress = f"{session['reihe_index'] + 1} / {len(session['reihe_ids'])}"

    return render_template('reihe_student.html',
                           schueler=schueler,
                           item=item,
                           anlass=session['reihe_anlass'],
                           progress=progress)

# 3c: SPEICHERN ODER ÜBERSPRINGEN
@app.route('/erfassen/reihe/next', methods=['POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def reihe_next():
    action = request.form.get('action') # "speichern" oder "skip"

    if action == 'speichern':
        # Daten holen
        wert = request.form.get('wert')
        kommentar = request.form.get('kommentar')
        foto = request.files['foto']

        # Foto speichern
        filename = None
        if foto and foto.filename != '':
            filename = secure_filename(foto.filename)
            speicher_pfad = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            komprimiere_und_speichere(foto, speicher_pfad)

        # Datum aus Session konvertieren
        datum_obj = datetime.strptime(session['reihe_datum'], '%Y-%m-%d') if session['reihe_datum'] else datetime.utcnow()

        # In DB schreiben
        current_id = session['reihe_ids'][session['reihe_index']]
        entry = Beobachtung(
            schueler_id=current_id,
            item_id=session['reihe_item_id'],
            wert=int(wert) if wert else None,
            kommentar=kommentar,
            foto_pfad=filename,
            anlass=session['reihe_anlass'],
            datum=datum_obj
        )
        db.session.add(entry)
        db.session.commit()

    # Egal ob gespeichert oder geskippt: Index hochzählen
    session['reihe_index'] += 1

    return redirect(url_for('reihe_schueler'))

# 4: BOGENERFASSUNG (Ein Schüler, ganzer Bogen)
@app.route('/erfassen/schueler', methods=['GET', 'POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def erfassen_schueler():
    s_id = request.args.get('schueler_id')
    b_id = request.args.get('bogen_id')
    
    if not s_id or not b_id:
        return render_template('batch_schueler.html', step=1, schueler=Schueler.query.all(), boegen=Bogen.query.all())

    schueler = Schueler.query.get(s_id)
    items = Item.query.filter_by(bogen_id=b_id).all()

    if request.method == 'POST':
        for i in items:
            wert = request.form.get(f'wert_{i.id}')
            if wert:
                b = Beobachtung(schueler_id=schueler.id, item_id=i.id, wert=int(wert))
                db.session.add(b)
        db.session.commit()
        flash('Bogen gespeichert!')
        return redirect(url_for('index'))

    return render_template('batch_schueler.html', step=2, schueler=schueler, items=items)

# 5: EINZELERFASSUNG
@app.route('/erfassen/einzel', methods=['GET', 'POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def erfassen_einzel():
    if request.method == 'POST':
        foto = request.files['foto']
        filename = None
        if foto and foto.filename != '':
            filename = secure_filename(foto.filename)
            speicher_pfad = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            komprimiere_und_speichere(foto, speicher_pfad)
        
        b = Beobachtung(
            schueler_id=request.form.get('schueler_id'),
            item_id=request.form.get('item_id'),
            wert=request.form.get('wert'),
            kommentar=request.form.get('kommentar'),
            foto_pfad=filename
        )
        db.session.add(b)
        db.session.commit()
        flash('Beobachtung gespeichert!')
        return redirect(url_for('index'))
        
    return render_template('einzel.html', schueler=Schueler.query.all(), boegen=Bogen.query.all())

# SETUP HELPER (Für den ersten Start)
@app.route('/setup')

def setup():
    db.create_all()
    # Prüfen, ob schon ein Admin existiert
    if not User.query.filter_by(username='admin').first():
        # Passwort hashen! Niemals Klartext speichern.
        # Hier ist das Start-Passwort: "schule123" (Bitte ändern!)
        hashed_pw = generate_password_hash("schule123")
        admin = User(username='admin', password_hash=hashed_pw)
        db.session.add(admin)
        return "Datenbank & Admin-User (Passwort: schule123) angelegt! <a href='/login'>Zum Login</a>"
    # Testdaten erzeugen
    if not Schueler.query.first():
        db.session.add(Schueler(vorname="Max", nachname="Muster", klasse="4a"))
        db.session.add(Schueler(vorname="Lisa", nachname="Lustig", klasse="4a"))
        
        b = Bogen(titel="Sozialverhalten")
        db.session.add(b)
        db.session.flush()
        db.session.add(Item(bogen_id=b.id, bereich="Konflikt", text="Löst Streit friedlich"))
        db.session.add(Item(bogen_id=b.id, bereich="Arbeit", text="Arbeitet konzentriert"))
        
        db.session.commit()
        return "Datenbank erstellt und Testdaten angelegt! <a href='/'>Zum Start</a>"
    return "Datenbank existiert schon. <a href='/'>Zum Start</a>"

# 6: BERICHT / ÜBERSICHT
@app.route('/report/schueler', methods=['GET'])
@login_required   # <--- DAS HIER EINFÜGEN
def report_schueler():
    s_id = request.args.get('schueler_id')
    b_id = request.args.get('bogen_id')

    # Wenn nichts gewählt ist -> Auswahlmenü zeigen
    if not s_id or not b_id:
        return render_template('report_select.html',
                               schueler=Schueler.query.all(),
                               boegen=Bogen.query.all())

    # Daten laden
    schueler = Schueler.query.get(s_id)
    bogen = Bogen.query.get(b_id)

    # Items laden
    items = Item.query.filter_by(bogen_id=b_id).all()

    report_data = []

    # Mapping für die Symbole
    symbol_map = {1: '-', 2: 'o', 3: '+', 4: '++'}
    color_map = {1: 'danger', 2: 'warning', 3: 'success', 4: 'success'}

    for item in items:
        # Alle Einträge zu diesem Item und Schüler holen, neuste zuerst
        eintraege = Beobachtung.query.filter_by(
            schueler_id=s_id,
            item_id=item.id
        ).order_by(Beobachtung.datum.desc()).all()

        durchschnitt = 0
        anzahl = len(eintraege)

        if anzahl > 0:
            summe = sum(e.wert for e in eintraege if e.wert is not None)
            durchschnitt = round(summe / anzahl, 1)

        report_data.append({
            'item': item,
            'eintraege': eintraege,
            'anzahl': anzahl,
            'durchschnitt': Durchschnitt if False else durchschnitt, # HIER WAR DER FEHLER (jetzt korrigiert zu 'durchschnitt')
        })

    # Damit im Bericht das aktuelle Datum steht
    jetzt = datetime.now().strftime("%d.%m.%Y %H:%M")

    return render_template('report_view.html',
                           schueler=schueler,
                           bogen=bogen,
                           report_data=report_data,
                           symbol_map=symbol_map,
                           color_map=color_map,
                           now=jetzt)

# ---------------------------------------------------------
# NEU: MULTI-ITEM REIHENABFRAGE (Mehrere Kompetenzen gleichzeitig)
# ---------------------------------------------------------

# 1. SETUP: Mehrere Items wählen
@app.route('/erfassen/multi/start', methods=['GET', 'POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def multi_start():
    if request.method == 'POST':
        # 1. Liste der gewählten Item-IDs holen (Checkboxen)
        selected_items = request.form.getlist('item_ids') # Gibt z.B. ['1', '5', '8'] zurück

        if not selected_items:
            flash("Bitte mindestens eine Kompetenz auswählen!")
            return redirect(request.url)

        # 2. Metadaten
        anlass = request.form.get('anlass')
        datum_str = request.form.get('datum')

        # 3. Schülerliste laden
        schueler = Schueler.query.order_by(Schueler.nachname).all()
        schueler_ids = [s.id for s in schueler]

        # 4. Session befüllen
        session['multi_item_ids'] = selected_items # Liste speichern
        session['multi_anlass'] = anlass
        session['multi_datum'] = datum_str
        session['multi_student_ids'] = schueler_ids
        session['multi_index'] = 0

        return redirect(url_for('multi_schueler'))

    return render_template('multi_start.html', boegen=Bogen.query.all())

# 2. ANZEIGE: Der Loop pro Schüler
@app.route('/erfassen/multi/schueler')
@login_required   # <--- DAS HIER EINFÜGEN
def multi_schueler():
    # Sicherheitscheck
    if 'multi_student_ids' not in session or session['multi_index'] >= len(session['multi_student_ids']):
        flash('Multi-Erfassung abgeschlossen!')
        return redirect(url_for('index'))

    # Aktuellen Schüler laden
    s_id = session['multi_student_ids'][session['multi_index']]
    schueler = Schueler.query.get(s_id)

    # Die gewählten Items als Objekte laden
    item_ids = session['multi_item_ids']
    # Wir holen alle Items, deren ID in der Liste ist
    items = Item.query.filter(Item.id.in_(item_ids)).all()

    progress = f"{session['multi_index'] + 1} / {len(session['multi_student_ids'])}"

    return render_template('multi_student.html',
                           schueler=schueler,
                           items=items,
                           anlass=session['multi_anlass'],
                           progress=progress)

# 3. SPEICHERN: Alles verarbeiten
@app.route('/erfassen/multi/next', methods=['POST'])
@login_required   # <--- DAS HIER EINFÜGEN
def multi_next():
    action = request.form.get('action') # 'speichern' oder 'skip'

    if action == 'speichern':
        # Wir müssen über ALLE gewählten Items loopen
        item_ids = session['multi_item_ids']
        s_id = session['multi_student_ids'][session['multi_index']]

        datum_obj = datetime.strptime(session['multi_datum'], '%Y-%m-%d') if session['multi_datum'] else datetime.utcnow()

        for i_id in item_ids:
            # Daten pro Item holen (Name der Felder ist dynamisch: wert_1, wert_5 etc.)
            wert = request.form.get(f'wert_{i_id}')
            kommentar = request.form.get(f'kommentar_{i_id}')

            # Foto holen (falls vorhanden)
            foto = request.files.get(f'foto_{i_id}')
            filename = None
            if foto and foto.filename != '':
                filename = secure_filename(foto.filename)
                speicher_pfad = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                komprimiere_und_speichere(foto, speicher_pfad)

            # Nur speichern, wenn eine Wertung abgegeben wurde (oder Pflicht machen, je nach Wunsch)
            if wert:
                entry = Beobachtung(
                    schueler_id=s_id,
                    item_id=i_id,
                    wert=int(wert),
                    kommentar=kommentar,
                    foto_pfad=filename,
                    anlass=session['multi_anlass'],
                    datum=datum_obj
                )
                db.session.add(entry)

        db.session.commit()

    # Nächster Schüler
    session['multi_index'] += 1
    return redirect(url_for('multi_schueler'))

# ---------------------------------------------------------
# ADMIN BEREICH
# ---------------------------------------------------------

# 1. DAS ADMIN DASHBOARD (Verteiler)
@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# 2. USER VERWALTUNG (Nur für 'admin')
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    # Sicherheit: Nur der "admin" darf hier rein
    if current_user.username != 'admin':
        flash('Zugriff verweigert. Nur der Administrator darf Benutzer verwalten.')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Neuen User anlegen
        username = request.form.get('username')
        password = request.form.get('password')

        # Prüfen ob Name schon weg ist
        if User.query.filter_by(username=username).first():
            flash('Benutzername existiert bereits!')
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Benutzer {username} angelegt.')
            return redirect(url_for('admin_users'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
def admin_user_delete(user_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    user_to_delete = User.query.get(user_id)

    # Verhindern, dass man sich selbst löscht
    if user_to_delete.username == 'admin':
        flash('Der Haupt-Administrator kann nicht gelöscht werden.')
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Benutzer {user_to_delete.username} gelöscht.')

    return redirect(url_for('admin_users'))

# 3. SCHÜLER VERWALTUNG (Liste)
@app.route('/admin/students')
@login_required
def admin_students():
    # Sortiert nach Klasse und dann Nachname
    schueler = Schueler.query.order_by(Schueler.klasse, Schueler.nachname).all()
    return render_template('admin_students.html', schueler=schueler)

# 4. SCHÜLER BEARBEITEN
@app.route('/admin/student/edit/<int:s_id>', methods=['GET', 'POST'])
@login_required
def admin_student_edit(s_id):
    schueler = Schueler.query.get(s_id)

    if request.method == 'POST':
        schueler.vorname = request.form.get('vorname')
        schueler.nachname = request.form.get('nachname')
        schueler.klasse = request.form.get('klasse')
        db.session.commit()
        flash('Schülerdaten aktualisiert.')
        return redirect(url_for('admin_students'))

    return render_template('admin_student_edit.html', s=schueler)

# 5. SCHÜLER LÖSCHEN
@app.route('/admin/student/delete/<int:s_id>')
@login_required
def admin_student_delete(s_id):
    schueler = Schueler.query.get(s_id)

    # WICHTIG: Erst alle Beobachtungen dieses Schülers löschen!
    Beobachtung.query.filter_by(schueler_id=s_id).delete()

    # Dann den Schüler selbst löschen
    db.session.delete(schueler)
    db.session.commit()

    flash(f'{schueler.vorname} {schueler.nachname} und alle zugehörigen Daten wurden gelöscht.')
    return redirect(url_for('admin_students'))

# ---------------------------------------------------------
# NEU: BOGEN & ITEM VERWALTUNG (Admin)
# ---------------------------------------------------------

# 1. BÖGEN VERWALTEN (Liste)
@app.route('/admin/boegen')
@login_required
def admin_boegen():
    if current_user.username != 'admin':
        return redirect(url_for('index'))
    
    boegen = Bogen.query.all()
    return render_template('admin_boegen.html', boegen=boegen)

# 2. BOGEN ERSTELLEN / BEARBEITEN
@app.route('/admin/bogen/edit/<int:b_id>', methods=['GET', 'POST'])
@app.route('/admin/bogen/new', defaults={'b_id': None}, methods=['GET', 'POST'])
@login_required
def admin_bogen_edit(b_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    if b_id:
        bogen = Bogen.query.get_or_404(b_id)
        titel_prefix = "Bogen bearbeiten"
    else:
        bogen = Bogen()
        titel_prefix = "Neuen Bogen anlegen"

    if request.method == 'POST':
        bogen.titel = request.form.get('titel')
        
        if not b_id:
            db.session.add(bogen)
        
        db.session.commit()
        flash(f'Bogen "{bogen.titel}" gespeichert.')
        return redirect(url_for('admin_boegen'))

    return render_template('admin_bogen_edit.html', bogen=bogen, titel_prefix=titel_prefix)

# 3. BOGEN LÖSCHEN
@app.route('/admin/bogen/delete/<int:b_id>')
@login_required
def admin_bogen_delete(b_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    bogen = Bogen.query.get_or_404(b_id)
    
    # ACHTUNG: Das löscht auch alle Items und Beobachtungen daran (cascade wäre besser in DB, aber hier manuell)
    # 1. Alle Items des Bogens finden
    items = Item.query.filter_by(bogen_id=b_id).all()
    for item in items:
        # 2. Alle Beobachtungen zu diesen Items löschen
        Beobachtung.query.filter_by(item_id=item.id).delete()
        # 3. Item löschen
        db.session.delete(item)
    
    db.session.delete(bogen)
    db.session.commit()
    flash(f'Bogen "{bogen.titel}" und alle zugehörigen Items/Daten gelöscht.')
    return redirect(url_for('admin_boegen'))

# 4. ITEMS EINES BOGENS ANZEIGEN
@app.route('/admin/bogen/<int:b_id>/items')
@login_required
def admin_items(b_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))
    
    bogen = Bogen.query.get_or_404(b_id)
    items = Item.query.filter_by(bogen_id=b_id).all()
    return render_template('admin_items.html', bogen=bogen, items=items)

# 5. ITEM ERSTELLEN / BEARBEITEN
@app.route('/admin/item/edit/<int:i_id>', methods=['GET', 'POST'])
@app.route('/admin/bogen/<int:b_id>/item/new', defaults={'i_id': None}, methods=['GET', 'POST'])
@login_required
def admin_item_edit(b_id, i_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    if i_id:
        item = Item.query.get_or_404(i_id)
        bogen = item.bogen # Bogen aus Relation holen
        titel_prefix = "Item bearbeiten"
    else:
        bogen = Bogen.query.get_or_404(b_id) # Wir brauchen den Bogen für die ID
        item = Item(bogen_id=b_id)
        titel_prefix = "Neues Item anlegen"

    if request.method == 'POST':
        item.text = request.form.get('text')
        item.bereich = request.form.get('bereich')
        
        if not i_id:
            db.session.add(item)
            
        db.session.commit()
        flash('Item gespeichert.')
        return redirect(url_for('admin_items', b_id=bogen.id))

    return render_template('admin_item_edit.html', item=item, bogen=bogen, titel_prefix=titel_prefix)

# 6. ITEM LÖSCHEN
@app.route('/admin/item/delete/<int:i_id>')
@login_required
def admin_item_delete(i_id):
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    item = Item.query.get_or_404(i_id)
    bogen_id = item.bogen_id
    
    # Beobachtungen löschen
    Beobachtung.query.filter_by(item_id=i_id).delete()
    
    db.session.delete(item)
    db.session.commit()
    flash('Item gelöscht.')
    return redirect(url_for('admin_items', b_id=bogen_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
