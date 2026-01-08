import re
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

DB_NAME = 'points.db'
SESSION_STORAGE = {}

# --- ДОПОМІЖНІ ФУНКЦІЇ ---

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def get_ects_grade(value):
    """Визначає ECTS оцінку за числовим значенням"""
    if value is None: return None
    if value >= 90: return 'A'
    elif value >= 82: return 'B'
    elif value >= 74: return 'C'
    elif value >= 65: return 'D'
    elif value >= 60: return 'E'
    else: return 'F'

def is_authenticated():
    session_id = request.cookies.get("session_id")
    return session_id in SESSION_STORAGE

# --- АВТОРИЗАЦІЯ ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session_id = secrets.token_urlsafe(32)
            SESSION_STORAGE[session_id] = {"user_id": user["id"], "username": user["username"]}
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("session_id", session_id, httponly=True, samesite='Lax')
            return resp
        flash("Невірний логін або пароль", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session_id = request.cookies.get("session_id")
    if session_id in SESSION_STORAGE:
        del SESSION_STORAGE[session_id]
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("session_id", "", expires=0)
    return resp

# --- ОСНОВНІ МАРШРУТИ ---

@app.route("/")
def index():
    session_id = request.cookies.get("session_id")
    user = SESSION_STORAGE.get(session_id)
    return render_template("index.html", user=user)

@app.route("/points")
def points():
    if not is_authenticated(): return redirect(url_for("login"))
    conn = get_db_connection()
    grades = conn.execute('''
        SELECT p.id, s.name as student, c.title as course, c.semester, p.value
        FROM points p
        JOIN student s ON p.id_student = s.id
        JOIN course c ON p.id_course = c.id
        ORDER BY s.name, c.semester, c.title
    ''').fetchall()
    conn.close()
    return render_template("points.html", grades=grades)

@app.route("/ects_grades")
def ects_grades():
    """Додано для виправлення BuildError"""
    if not is_authenticated(): return redirect(url_for("login"))
    conn = get_db_connection()
    all_data = conn.execute('''
        SELECT c.id, c.title, c.semester, p.value
        FROM course c
        LEFT JOIN points p ON c.id = p.id_course
    ''').fetchall()
    conn.close()
    
    ects_stats = {}
    for row in all_data:
        key = (row['id'], row['title'], row['semester'])
        if key not in ects_stats:
            ects_stats[key] = {'A':0,'B':0,'C':0,'D':0,'E':0,'F':0, 'total':0}
        grade = get_ects_grade(row['value'])
        if grade:
            ects_stats[key][grade] += 1
            ects_stats[key]['total'] += 1

    result = [{'title': k[1], 'semester': k[2], **v} for k, v in ects_stats.items()]
    return render_template("ects_grades.html", ects_data=result, ects_order=['A','B','C','D','E','F'])

@app.route("/students")
def students():
    if not is_authenticated(): return redirect(url_for("login"))
    conn = get_db_connection()
    students_list = conn.execute("SELECT id, name FROM student ORDER BY name").fetchall()
    conn.close()
    return render_template("students.html", students=students_list)

@app.route("/student/<int:student_id>")
def student_grades(student_id):
    if not is_authenticated(): return redirect(url_for("login"))
    conn = get_db_connection()
    student = conn.execute("SELECT name FROM student WHERE id = ?", (student_id,)).fetchone()
    grades = conn.execute('''
        SELECT c.title as course, c.semester, p.value
        FROM points p
        JOIN course c ON p.id_course = c.id
        WHERE p.id_student = ?
    ''', (student_id,)).fetchall()
    conn.close()
    return render_template("student_grades.html", student_name=student["name"], grades=grades)

# --- БЕЗПЕКА ---

@app.after_request
def apply_csp(response):
    response.headers["Content-Security-Policy"] = "script-src 'self'"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)