from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # replace for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apartment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------- Models ---------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default="tenant")  # tenant or admin
    requests = db.relationship('ServiceRequest', backref='user', lazy=True)

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issue_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ---------------- Routes ---------------- #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required.')
            return redirect(url_for('register'))
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash('Username already taken.')
            return redirect(url_for('register'))
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') == 'admin':
        requests_list = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    else:
        requests_list = ServiceRequest.query.filter_by(user_id=session['user_id']).order_by(ServiceRequest.created_at.desc()).all()
    return render_template('dashboard.html', requests=requests_list, role=session.get('role'), username=session.get('username'))

@app.route('/create_request', methods=['GET','POST'])
def create_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        issue_type = request.form['issue_type']
        description = request.form['description']
        priority = request.form['priority']
        if not issue_type or not description:
            flash('Issue type and description are required.')
            return redirect(url_for('create_request'))
        req = ServiceRequest(issue_type=issue_type, description=description, priority=priority, user_id=session['user_id'])
        db.session.add(req)
        db.session.commit()
        flash('Service request created successfully.')
        return redirect(url_for('dashboard'))
    return render_template('create_request.html')

@app.route('/update_status/<int:req_id>', methods=['POST'])
def update_status(req_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized.')
        return redirect(url_for('login'))
    req = ServiceRequest.query.get_or_404(req_id)
    new_status = request.form.get('status')
    if new_status:
        req.status = new_status
        db.session.commit()
        flash('Status updated.')
    return redirect(url_for('dashboard'))

# Simple route to create an admin user for first-time setup (use once)
@app.route('/create_admin')
def create_admin():
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        flash('Admin already exists.')
        return redirect(url_for('index'))
    u = User(username='admin', password=generate_password_hash('adminpass'), role='admin')
    db.session.add(u)
    db.session.commit()
    flash('Admin created (username: admin, password: adminpass). Change immediately.')
    return redirect(url_for('index'))

# ---------------- Main ---------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
