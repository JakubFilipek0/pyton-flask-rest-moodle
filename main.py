from flask import Flask
from functools import wraps
from flask import request, jsonify, send_file
from models.models import User, db, Team, TeamMember, Task
import jwt
import datetime
import hashlib
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'txt'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SECRET_KEY'] = 'thisissecret'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db.init_app(app)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


""" ---------- Check user token ---------- """


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        print(f'Token: {token}')
        print(jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256']))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


""" ---------- Login, Logout, Register ---------- """


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Nie podano adresu e-mail lub hasła"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "Użytkownik o podanym adresie e-mail nie istnieje"}), 401

    hashed_password = user.password
    if hashed_password == hashlib.sha256(password.encode()).hexdigest():
        # Hasło jest poprawne, wygeneruj token JWT
        token = jwt.encode(
            {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        print(app.config['SECRET_KEY'])

        return jsonify({'token': token})
    else:
        return jsonify({"message": "Nieprawidłowe hasło"}), 401


@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    return jsonify({'message': 'User logged out'}), 200


# Endpoint do dodawania użytkownika
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    # Sprawdz czy uzytkownik z takim emailem juz istnieje
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Użytkownik z takim emailem istnieje"}), 409

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(email=email, password=hashed_password, teacher=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Użytkownik dodany'}), 201


""" ---------- Create team, Add user to team, Get my team, Get team's users ---------- """


@app.route('/teams/create', methods=['POST'])
@token_required
def create_team(current_user):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    data = request.get_json()
    team_name = data.get('name')

    if Team.query.filter_by(name=team_name).first():
        return jsonify({"message": "Zespół z taką nazwą istnieje"}), 409

    new_team = Team(name=team_name, creator_id=current_user.id)
    db.session.add(new_team)
    db.session.commit()

    team_member = TeamMember(team_id=new_team.id, user_id=current_user.id, role=True)
    db.session.add(team_member)
    db.session.commit()

    return jsonify({'message': 'Zespół został utworzony'}), 201


@app.route('/teams/<int:team_id>/delete', methods=['DELETE'])
@token_required
def delete_team(current_user, team_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    team = Team.query.get(team_id)
    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

    # Usuń członków zespołu
    team_members = TeamMember.query.filter_by(team_id=team_id).all()
    for team_member in team_members:
        db.session.delete(team_member)

    # Usuń zadania związane z zespołem
    tasks = Task.query.filter_by(team_id=team_id).all()
    for task in tasks:
        db.session.delete(task)

    # Usuń zespół
    db.session.delete(team)
    db.session.commit()

    return jsonify({'message': 'Zespół został usunięty wraz z członkami i zadaniami'}), 200


@app.route('/teams/<int:team_id>/add-user', methods=['POST'])
@token_required
def add_user_to_team(current_user, team_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    team = Team.query.get(team_id)

    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

    if team.creator_id != current_user.id:
        return jsonify({'message': 'Nie jesteś twórcą tego zespołu'}), 403

    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Użytkownik o podanym adresie e-mail nie istnieje'}), 404

    team_member = TeamMember.query.filter_by(team_id=team.id, user_id=user.id).first()
    if team_member:
        return jsonify({'message': 'Użytkownik już jest członkiem tego zespołu'}), 409

    team_member = TeamMember(team_id=team.id, user_id=user.id, role=False)
    db.session.add(team_member)
    db.session.commit()

    return jsonify({'message': 'Użytkownik został dodany do zespołu'}), 201


# Endpoint do pobierania zespołów, do których aktualnie zalogowany użytkownik jest członkiem
@app.route('/my-teams', methods=['GET'])
@token_required
def get_my_teams(current_user):
    team_memberships = TeamMember.query.filter_by(user_id=current_user.id).all()

    teams = []
    for membership in team_memberships:
        team = Team.query.get(membership.team_id)
        if team:
            team_data = {
                'id': team.id,
                'name': team.name,
                'creator_id': team.creator_id,
                'creator_email': User.query.get(team.creator_id).email,
                'role': 'Teacher' if membership.role else 'Student'
            }
            teams.append(team_data)

    return jsonify({'my_teams': teams}), 200


@app.route('/teams/<int:team_id>/users', methods=['GET'])
@token_required
def get_team_users(current_user, team_id):
    # Sprawdź, czy zalogowany użytkownik jest członkiem zespołu
    team_member = TeamMember.query.filter_by(team_id=team_id, user_id=current_user.id).first()

    if not team_member:
        return jsonify({'message': 'Nie jesteś członkiem tego zespołu'}), 403

    # Pobierz listę użytkowników przypisanych do tego zespołu
    team_users = TeamMember.query.filter_by(team_id=team_id).all()
    user_list = []

    for team_user in team_users:
        user = User.query.get(team_user.user_id)
        user_data = {
            'id': user.id,
            'email': user.email,
            'teacher': user.teacher
        }
        user_list.append(user_data)

    return jsonify({'team_users': user_list}), 200


# Endpoint do tworzenia zadania
@app.route('/teams/<int:team_id>/create', methods=['POST'])
@token_required
def create_task(current_user, team_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    data = request.get_json()
    assigned_to_email = data.get('assigned_to_email')
    content = data.get('content')

    team = Team.query.get(team_id)
    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

    # Sprawdź czy minimum 1 email zotały podany
    if not assigned_to_email:
        return jsonify({'message': 'Nie podano adresów e-mail uczniów'}), 400

    # Przypisane zadania do każdego ucznia
    for emails in assigned_to_email:
        print(assigned_to_email)
        assigned_user = User.query.filter_by(email=emails).first()
        if not assigned_user:
            return jsonify({'message': 'Użytkownik o podanym adresie e-mail nie istnieje'}), 404

        team_member = TeamMember.query.filter_by(team_id=team.id, user_id=assigned_user.id).first()
        if not team_member:
            return jsonify({'message': 'Użytkownik nie jest członkiem tego zespołu'}), 403

        new_task = Task(team_id=team_id, assigned_to_user=assigned_user.id, content=content, status="Nie zwrócono")
        db.session.add(new_task)

    db.session.commit()

    return jsonify({'message': 'Zadanie zostało utworzone'}), 201


# Endpoint do aktualizowania zadania
@app.route('/teams/<int:team_id>/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, team_id, task_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    team = Team.query.get(team_id)
    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Zadanie o podanym identyfikatorze nie istnieje'}), 404

    # Sprawdź, czy zadanie należy do zespołu
    if task.team_id != team.id:
        return jsonify({'message': 'Zadanie nie należy do tego zespołu'}), 403

    data = request.get_json()
    content = data.get('content')

    task.content = content
    db.session.commit()

    return jsonify({'message': 'Zadanie zostało zaktualizowane'}), 200


@app.route('/teams/<int:team_id>/tasks/<int:task_id>/submit', methods=['POST'])
@token_required
def submit_task(current_user, team_id, task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Zadanie o podanym identyfikatorze nie istnieje'}), 404

    if task.assigned_to_user != current_user.id:
        return jsonify({'message': 'Nie jesteś przypisanym użytkownikiem tego zadania'}), 403

    if 'file' not in request.files:
        return jsonify({'message': 'Brak pliku w żądaniu'}), 400

    file = request.files['file']
    print(f"Plik z request {file}")
    print(f'Ścieżka do zapisu {app.config["UPLOAD_FOLDER"]}')

    if file.filename == '':
        return jsonify({'message': 'Brak wybranego pliku'}), 400

    # Sprawdzenie czy katalog uploads istnieje. Jeżeli nie to utwórz go
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        print(f'Katalog nie istnieje. Tworzę katalog...')
        os.makedirs(app.config["UPLOAD_FOLDER"])
    else:
        print("Katalog już istnieje")

    if file and allowed_file(file.filename):
        print("Próba zapisu pliku")
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(file_path)
            print("Plik zapisano pomyślnie")
        except Exception as save_error:
            print(f"Błąd zapisu {save_error}")

        task.status = 'Zwrócono'
        task.file = file_path
        db.session.commit()

        return jsonify({'message': 'Plik został przesłany i zadanie zostało zaktualizowane'}), 200
    else:
        return jsonify({'message': 'Nieprawidłowy format pliku'}), 400


# Endpoint do usuwania zadania
@app.route('/teams/<int:team_id>/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, team_id, task_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Zadanie o podanym identyfikatorze nie istnieje'}), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({'message': 'Zadanie zostało usunięte'}), 200


# Endpoint do wystawiania oceny za zadanie
@app.route('/teams/<int:team_id>/tasks/<int:task_id>/grade', methods=['POST'])
@token_required
def grade_task(current_user, team_id, task_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wystawiania oceny'})

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Zadanie o podanym identyfikatorze nie istnieje'}), 404

    if task.team_id != team_id:
        return jsonify({'message': 'Zadanie nie należy do tego zespołu'}), 403

    if task.status != 'Zwrócono':
        return jsonify({'message': 'Zadanie nie zostało jeszcze zwrócone przez ucznia'}), 400

    data = request.get_json()
    grade = data.get('grade')

    if not grade:
        return jsonify({'message': 'Brak oceny w żądaniu'}), 400

    task.status = 'Oceniono'
    task.grade = grade
    db.session.commit()

    return jsonify({'message': f'Ocena za zadanie {task_id} została wystawiona: {grade}'}), 200


""" ---------- Pobieranie zadań ---------- """


@app.route('/teams/<int:team_id>/tasks/<int:task_id>/download', methods=['GET'])
@token_required
def download_task_file(current_user, team_id, task_id):
    task = Task.query.get(task_id)

    if not task:
        return jsonify({'message': 'Zadanie o podanym identyfikatorze nie istnieje'}), 404

    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do pobierania plików'}), 403

    # if task.status != 'Zwrócono' or task.status != 'Oceniono':
    #     return jsonify({'message': 'Zadanie nie zostało jeszcze zwrócone przez ucznia'}), 400

    return send_file(task.file, as_attachment=True)


# Endpoint do pobierania wszystkich zadań w obrębie zespołu (dla nauczyciela)
@app.route('/teams/<int:team_id>/tasks', methods=['GET'])
@token_required
def get_all_tasks_in_team(current_user, team_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    team = Team.query.get(team_id)
    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

    tasks = Task.query.filter_by(team_id=team_id).all()

    tasks_data = [
        {
            'id': task.id,
            'team_id': task.team_id,
            'assigned_to_user': task.assigned_to_user,
            'content': task.content
        }
        for task in tasks
    ]

    return jsonify({'tasks': tasks_data}), 200


# Endpoint do pobierania przypisanych zadań w obrębie zespołu (dla zwykłego użytkownika)
@app.route('/my-tasks', methods=['GET'])
@token_required
def get_my_tasks(current_user):
    tasks = Task.query.filter_by(assigned_to_user=current_user.id).all()

    tasks_data = [
        {
            'id': task.id,
            'team_id': task.team_id,
            'assigned_to_user': task.assigned_to_user,
            'content': task.content
        }
        for task in tasks
    ]

    return jsonify({'tasks': tasks_data}), 200


# Endpoint do pobierania wszystkich użytkowników
@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    users = User.query.all()
    user_list = []
    for user in users:
        user_data = {
            'id': user.id,
            'email': user.email,
            'teacher': user.teacher
        }
        user_list.append(user_data)
    return jsonify({'users': user_list}), 200


# Endpoint do modyfikowania użytkownika
@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    data = request.get_json()
    user = User.query.get(user_id)
    if user is None:
        return jsonify({'message': 'Użytkownik nie istnieje'}), 404
    user.email = data.get('email', user.email)
    user.password = data.get('password', user.password)
    db.session.commit()
    return jsonify({'message': 'Użytkownik zaktualizowany'}), 200


# Endpoint do usuwania użytkownika
@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    user = User.query.get(user_id)
    if user is None:
        return jsonify({'message': 'Użytkownik nie istnieje'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Użytkownik usunięty'}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Sprawdź, czy istnieje użytkownik "teacher" w bazie danych
        teacher = User.query.filter_by(email='teacher@example.com').first()

        # Jeśli nie istnieje, stwórz użytkownika "teacher"
        if not teacher:
            teacher_password = 'teacher_password'  # Hasło dla użytkownika "teacher"
            hashed_teacher_password = hashlib.sha256(teacher_password.encode()).hexdigest()
            new_teacher = User(email='teacher@example.com', password=hashed_teacher_password, teacher=True)
            db.session.add(new_teacher)
            db.session.commit()

    app.run(debug=True)
