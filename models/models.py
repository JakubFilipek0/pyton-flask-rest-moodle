from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# Model użytkownika
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    teacher = db.Column(db.Boolean, nullable=False)


# Model drużyny
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False, unique=True)
    creator = db.relationship('User', foreign_keys=creator_id)


# Model członka drużyny
class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.Boolean, nullable=False)
    team = db.relationship('Team', foreign_keys=team_id)
    user = db.relationship('User', foreign_keys=user_id)


# Model zadania
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    assigned_to_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    file = db.Column(db.String, nullable=True)
    grade = db.Column(db.String, nullable=True)
    team = db.relationship('Team', foreign_keys=team_id)
    assigned_user = db.relationship('User', foreign_keys=assigned_to_user)
