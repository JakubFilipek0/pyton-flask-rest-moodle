from flask import Flask
from functools import wraps
from flask import request, jsonify
from models.models import User, db, Team, TeamMember
import jwt
import datetime
import hashlib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SECRET_KEY'] = 'thisissecret'
db.init_app(app)

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


""" ---------- Create team, Add user to team, Get my team ---------- """


@app.route('/create-team', methods=['POST'])
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


@app.route('/add-user-to-team/<int:team_id>', methods=['POST'])
@token_required
def add_user_to_team(current_user, team_id):
    if not current_user.teacher:
        return jsonify({'message': 'Nie masz uprawnień do wykonania tej akcji'})

    team = Team.query.get(team_id)

    if not team:
        return jsonify({'message': 'Zespół o podanym identyfikatorze nie istnieje'}), 404

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
