from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "875191554080d26963bf5106f03ae256dd655a94639703176ddd638fd8e73d92"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Set up Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

migrate = Migrate(app, db)


# Database model for the Users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add this field for admin users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_picture = db.Column(db.String(150), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'


# Database model for the books
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)

    def __repr__(self):
        return f"Book('{self.title}', '{self.author}', '{self.price}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Homepage / Index route
@app.route('/')
def index():
    books = Book.query.all()
    return render_template('index.html', books=books)


# View all books in database
@app.route('/books')
def view_books():
    books = Book.query.all()
    return render_template('view_books.html', books=books)


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))

        login_user(user)
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('profile'))

    return render_template('login.html')


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please try another.", "warning")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# Profile route
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Route to edit password and profile picture
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Update password if provided
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # If passwords match and are not empty
        if password and password == confirm_password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            current_user.password = hashed_password
            flash("Password updated successfully!", "success")
        elif password and password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")

        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join('static/uploads', filename))
                current_user.profile_picture = filename  # Save filename to the database
                db.session.commit()

        if 'remove_pfp' in request.form:
            current_user.profile_picture = None  # This will make it fall back to the default
            db.session.commit()
            flash("Profile picture reset to default.", "success")
            return redirect(url_for('edit_profile'))

        return redirect(url_for('profile'))

    return render_template('edit_profile.html')


# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# See more details about specific books and add related books by author
@app.route('/book/<int:book_id>')
def book_details(book_id):
    book = Book.query.get_or_404(book_id)
    related_books = Book.query.filter(
        Book.author == book.author,
        Book.id != book.id
    ).limit(3).all()
    return render_template('book_details.html', book=book, related_books=related_books)


# Admin login details - Username: admin, Password: adminpassword
# Admin routes for managing books - ADD BOOKS
@app.route('/admin/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        description = request.form.get('description')
        price = request.form.get('price')
        image_url = request.form.get('image_url')

        new_book = Book(title=title, author=author, description=description, price=price, image_url=image_url)
        db.session.add(new_book)
        db.session.commit()

        flash("Book added successfully!", "success")
        return redirect(url_for('index'))

    return render_template('add_book.html')


# Admin routes for managing books - EDIT BOOKS
@app.route('/admin/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))

    book = Book.query.get_or_404(book_id)

    if request.method == 'POST':
        book.title = request.form.get('title')
        book.author = request.form.get('author')
        book.description = request.form.get('description')
        book.price = request.form.get('price')
        book.image_url = request.form.get('image_url')

        db.session.commit()
        flash("Book updated successfully!", "success")
        return redirect(url_for('book_details', book_id=book.id))

    return render_template('edit_book.html', book=book)


# Admin routes for managing books - DELETE BOOKS
@app.route('/admin/delete_book/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))

    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()

    flash("Book deleted successfully!", "success")
    return redirect(url_for('index'))


@app.route('/wp-admin')
def wp_admin():
    return render_template('wp-admin.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=generate_password_hash('adminpassword', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True)

