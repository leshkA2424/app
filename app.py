from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required
from flask_login import current_user
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # замени на свой безопасный ключ

# Настройки базы данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ----------------- Модели -----------------
movie_actors = db.Table('movie_actors',
    db.Column('movie_id', db.Integer, db.ForeignKey('movie.id')),
    db.Column('actor_id', db.Integer, db.ForeignKey('actor.id'))
)

class Actor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    movies = db.relationship('Movie', secondary=movie_actors, back_populates='actors')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    phone = db.Column(db.String(20))


class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    director = db.Column(db.String(100))
    genre = db.Column(db.String(100))
    year = db.Column(db.Integer)
    rating = db.Column(db.Float)
    poster_url = db.Column(db.String(200))
    type = db.Column(db.String(10), nullable=False)  # "фильм" или "сериал"
    reviews = db.relationship('Review', back_populates='movie', lazy=True)
    country = db.Column(db.String(100))  # в модели Movie
    trailer_url = db.Column(db.String(200))
    actors = db.relationship('Actor', secondary=movie_actors, back_populates='movies')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='reviews')
    movie = db.relationship('Movie', back_populates='reviews')
    

class PendingMovieRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    poster_url = db.Column(db.String(500))
    year = db.Column(db.Integer)
    director = db.Column(db.String(255))
    genre = db.Column(db.String(255))
    country = db.Column(db.String(255))
    rating = db.Column(db.Float)
    description = db.Column(db.Text)
    is_series = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    trailer_url = db.Column(db.String(200))
    actors = db.Column(db.Text)  # список имён через запятую




# ----------------- Маршруты -----------------

from werkzeug.security import check_password_hash, generate_password_hash
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/user', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        flash('Сначала войдите в аккаунт', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(user.password, current_password):
            flash('Неверный текущий пароль.', 'danger')
        elif new_password != confirm_password:
            flash('Новый пароль и подтверждение не совпадают.', 'danger')
        elif len(new_password) < 6:
            flash('Пароль должен содержать не менее 6 символов.', 'warning')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Пароль успешно изменён.', 'success')
            return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user' not in session:
        flash('Сначала войдите в аккаунт', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not check_password_hash(user.password, current_password):
        flash('Неверный текущий пароль.', 'danger')
    elif new_password != confirm_password:
        flash('Пароли не совпадают.', 'danger')
    else:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Пароль успешно изменён.', 'success')

    return redirect(url_for('profile'))


@app.route('/')
def index():
    genre = request.args.get('genre')
    year = request.args.get('year', type=int)
    rating = request.args.get('rating', type=float)
    country = request.args.get('country')
    actor_name = request.args.get('actor')

    query = Movie.query

    if genre:
        query = query.filter(Movie.genre.ilike(f'%{genre}%'))
    if year:
        query = query.filter(Movie.year == year)
    if rating:
        query = query.filter(Movie.rating >= rating)
    if country:
        query = query.filter(Movie.director.ilike(f'%{country}%') | Movie.country.ilike(f'%{country}%'))  # если поле country добавлено
    if actor_name:
        query = query.join(Movie.actors).filter(Actor.name.ilike(f'%{actor_name}%'))

    top_movies = query.filter(Movie.rating >= 7.5).order_by(Movie.rating.desc()).limit(10).all()
    all_movies = query.filter(Movie.type == 'movie').all()
    all_series = query.filter(Movie.type == 'series').all()

    return render_template('index.html',
                           top_movies=top_movies,
                           all_movies=all_movies,
                           all_series=all_series)

@app.route('/movies')
def show_movies():
    genre = request.args.get('genre')
    year = request.args.get('year', type=int)
    rating = request.args.get('rating', type=float)

    query = Movie.query.filter_by(type='movie')

    if genre:
        query = query.filter(Movie.genre.ilike(f'%{genre}%'))
    if year:
        query = query.filter(Movie.year == year)
    if rating:
        query = query.filter(Movie.rating >= rating)
        

    movies = query.all()
    return render_template('movies.html', movies=movies)


@app.route('/series')
def show_series():
    genre = request.args.get('genre')
    year = request.args.get('year', type=int)
    rating = request.args.get('rating', type=float)

    query = Movie.query.filter_by(type='series')

    if genre:
        query = query.filter(Movie.genre.ilike(f'%{genre}%'))
    if year:
        query = query.filter(Movie.year == year)
    if rating:
        query = query.filter(Movie.rating >= rating)

    series_list = query.all()
    return render_template('series.html', series_list=series_list)

@app.route('/add', methods=['GET', 'POST'])
def add_movie():
    if 'user' not in session:
        flash('Сначала войдите в аккаунт', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()

    if request.method == 'POST':
        is_series = request.form.get('type') == 'series'
        actors_input = request.form.get('actors')  # строка с именами актёров
        actor_names = [name.strip() for name in actors_input.split(',')] if actors_input else []

        new_request = PendingMovieRequest(
            title=request.form['title'],
            poster_url=request.form['poster_url'],
            trailer_url=request.form['trailer_url'],
            year=request.form['year'],
            director=request.form['director'],
            genre=request.form['genre'],
            country=request.form['country'],
            rating=request.form['rating'],
            description=request.form['description'],
            is_series=is_series,
            created_by=user.id,
            actors=actors_input
        )
        db.session.add(new_request)
        db.session.flush()  # получаем ID для связи

        db.session.commit()
        flash("Заявка на добавление отправлена на модерацию", "info")
        return redirect(url_for('index'))

    return render_template('add_movie.html')


from flask_login import current_user

@app.route('/moderate_requests')
def moderate_requests():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Доступ только для администраторов.', 'danger')
        return redirect(url_for('login'))
    
    requests = PendingMovieRequest.query.order_by(PendingMovieRequest.created_at.desc()).all()
    return render_template('moderate_requests.html', requests=requests)

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    if 'user' not in session or session.get('role') != 'admin':
        abort(403)

    req = PendingMovieRequest.query.get_or_404(request_id)

    new_movie = Movie(  # Movie используется и для сериалов, раз у тебя один класс
        title=req.title,
        poster_url=req.poster_url,
        year=req.year,
        director=req.director,
        genre=req.genre,
        country=req.country,
        rating=req.rating,
        description=req.description,
        trailer_url=req.trailer_url,
        type='series' if req.is_series else 'movie'
    )
    db.session.add(new_movie)
    db.session.flush()
    
    # Обработка актёров
    if req.actors:
        actor_names = [name.strip() for name in req.actors.split(',')]
        for actor_name in actor_names:
            actor = Actor.query.filter_by(name=actor_name).first()
            if not actor:
                actor = Actor(name=actor_name)
                db.session.add(actor)
                db.session.flush()
            new_movie.actors.append(actor)

    db.session.delete(req)
    db.session.commit()
    flash("Фильм одобрен и добавлен", "success")
    return redirect(url_for('moderate_requests'))


@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'user' not in session or session.get('role') != 'admin':
        abort(403)

    req = PendingMovieRequest.query.get_or_404(request_id)
    db.session.delete(req)
    db.session.commit()
    flash("Заявка отклонена", "warning")
    return redirect(url_for('moderate_requests'))


from werkzeug.security import generate_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # ← обязательно определить до хеша
        role = request.form['role']
        phone = request.form['phone']

        password_hash = generate_password_hash(password)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь уже существует', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, password=password_hash, role=role, phone=phone)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # ← обязательно

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session.clear()
            session['user'] = user.username
            session['role'] = user.role
            flash('Добро пожаловать!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из аккаунта', 'info')
    return redirect(url_for('login'))

@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
def movie_detail(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if request.method == 'POST':
        if 'user' not in session:
            flash('Сначала войдите в аккаунт', 'warning')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=session['user']).first()
        content = request.form['content']
        rating = int(request.form['rating'])

        new_review = Review(movie_id=movie.id, user_id=user.id, content=content, rating=rating)
        db.session.add(new_review)
        db.session.commit()
        flash('Отзыв добавлен!', 'success')
        return redirect(url_for('movie_detail', movie_id=movie.id))

    return render_template('movie_detail.html', movie=movie)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        results = Movie.query.filter(Movie.title.ilike(f"%{query}%")).all()
    else:
        results = []

    return render_template('search_results.html', query=query, results=results)
# ----------------- Запуск -----------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)