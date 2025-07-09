# app.py

# --- 1. Importaciones Necesarias ---
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from flask_paginate import Pagination, get_page_parameter
from wtforms_sqlalchemy.fields import QuerySelectField
from wtforms import StringField, PasswordField, SubmitField, DecimalField, IntegerField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, NumberRange, Email, EqualTo, ValidationError
from flask_wtf import FlaskForm # Importado aquí para las definiciones de formularios
import os

# --- 2. Inicialización de la Aplicación Flask y Configuraciones ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una_clave_secreta_muy_larga_y_aleatoria_por_favor_cambiala') # ¡CAMBIA ESTO POR UNA CLAVE SEGURA!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# **CORRECCIÓN:** os.environ.get() toma el NOMBRE de la variable de entorno, no el valor literal.
# Si no usas variables de entorno, pon el string directamente.
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'ejecutivobraja01@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'xqckzwshoedqxvsx') # Contraseña de aplicación (generada en Google)

# --- 3. Inicialización de Extensiones de Flask ---
db = SQLAlchemy(app) # ¡IMPORTANTE: db debe inicializarse DESPUÉS de 'app' y ANTES de usarlo!
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app) # Inicializa login_manager con la instancia de 'app'
login_manager.login_view = 'login' # La ruta a la que redirigir si se requiere login
login_manager.login_message_category = 'info' # Categoría de mensaje flash para login requerido

# El serializador ahora usa app.config directamente para evitar current_app en contexto global
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Constante del aeropuerto de Barinas
BARINAS_AIRPORT_CODE = 'BNS'


# --- 4. Definición de Modelos (DB) ---
# Los modelos deben definirse DESPUÉS de db = SQLAlchemy(app)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)  # Nombre
    last_name = db.Column(db.String(50), nullable=True)   # Apellido
    phone_number = db.Column(db.String(20), nullable=True) # Número de teléfono
    address = db.Column(db.String(200), nullable=True)     # Dirección

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # MÉTODO AÑADIDO: para establecer la contraseña hasheada
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Airport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(3), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Airport {self.code} - {self.city}>'

class Airline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    logo_url = db.Column(db.String(200))

    def __repr__(self):
        return f'<Airline {self.name}>'

class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_number = db.Column(db.String(20), unique=True, nullable=False)
    origin_airport_id = db.Column(db.Integer, db.ForeignKey('airport.id'), nullable=False)
    destination_airport_id = db.Column(db.Integer, db.ForeignKey('airport.id'), nullable=False)
    airline_id = db.Column(db.Integer, db.ForeignKey('airline.id'), nullable=False)
    departure_datetime = db.Column(db.DateTime, nullable=False)
    arrival_datetime = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Float, nullable=False)
    total_seats = db.Column(db.Integer, nullable=False, default=0)
    available_seats = db.Column(db.Integer, nullable=False, default=0)

    origin_airport = db.relationship('Airport', foreign_keys=[origin_airport_id], backref='departing_flights', lazy=True)
    destination_airport = db.relationship('Airport', foreign_keys=[destination_airport_id], backref='arriving_flights', lazy=True)
    airline = db.relationship('Airline', backref='flights', lazy=True)

    def __repr__(self):
        return f'<Flight {self.flight_number} from {self.origin_airport.code} to {self.destination_airport.code}>'

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flight_id = db.Column(db.Integer, db.ForeignKey('flight.id'), nullable=False)
    booking_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    num_passengers = db.Column(db.Integer, nullable=False, default=1)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Confirmed')

    user = db.relationship('User', backref='bookings', lazy=True)
    flight = db.relationship('Flight', backref='bookings', lazy=True)

    def __repr__(self):
        return f'<Booking {self.id} - User: {self.user.username} - Flight: {self.flight.flight_number}>'

# --- 5. User Loader para Flask-Login (Solo una definición) ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 6. Funciones de ayuda para QuerySelectField (necesitan los modelos Airport y Airline) ---
# **CORRECCIÓN:** Movidas aquí, DESPUÉS de la definición de los modelos.
def get_airports():
    return Airport.query.order_by(Airport.city).all()

def get_airlines():
    return Airline.query.order_by(Airline.name).all()

# --- 7. Definición de Formularios (WTForms) ---
# Los formularios deben definirse DESPUÉS de los modelos si usan QuerySelectField
class RegisterForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('Nombre', validators=[Length(max=50), DataRequired()])
    last_name = StringField('Apellido', validators=[Length(max=50), DataRequired()])
    phone_number = StringField('Número de Teléfono', validators=[Length(max=20), DataRequired()])
    address = StringField('Dirección', validators=[Length(max=200), DataRequired()])
    submit = SubmitField('Registrarse')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ese nombre de usuario ya está en uso. Por favor, elige uno diferente.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Ese email ya está en uso. Por favor, elige uno diferente.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class ProfileForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Actualizar Perfil')
    first_name = StringField('Nombre', validators=[Length(max=50), DataRequired()])
    last_name = StringField('Apellido', validators=[Length(max=50), DataRequired()])
    phone_number = StringField('Número de Teléfono', validators=[Length(max=20), DataRequired()])
    address = StringField('Dirección', validators=[Length(max=200), DataRequired()])

    def validate_username(self, username):
        if username.data != current_user.username:
            user_exists = User.query.filter_by(username=username.data).first()
            if user_exists:
                raise ValidationError('Ese nombre de usuario ya está en uso. Por favor, elige uno diferente.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user_exists = User.query.filter_by(email=email.data).first()
            if user_exists:
                raise ValidationError('Ese email ya está en uso. Por favor, elige uno diferente.')

class RequestResetForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    submit = SubmitField('Solicitar Restablecimiento')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Restablecer Contraseña')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Contraseña Actual', validators=[DataRequired()])
    new_password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('Confirmar Nueva Contraseña', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Cambiar Contraseña')

    def validate_old_password(self, field):
        # **CORRECCIÓN:** current_user es un proxy, y check_password es un método del modelo User.
        if not current_user.check_password(field.data):
            raise ValidationError('La contraseña actual es incorrecta.')

class AddFlightForm(FlaskForm):
    flight_number = StringField('Número de Vuelo', validators=[DataRequired(), Length(min=3, max=10)])

    origin_airport = QuerySelectField(
        'Aeropuerto de Origen',
        query_factory=get_airports,
        get_pk=lambda a: a.id,
        get_label=lambda a: f"{a.city} ({a.code})",
        allow_blank=False,
        validators=[DataRequired()]
    )

    destination_airport = QuerySelectField(
        'Aeropuerto de Destino',
        query_factory=get_airports,
        get_pk=lambda a: a.id,
        get_label=lambda a: f"{a.city} ({a.code})",
        allow_blank=False,
        validators=[DataRequired()]
    )

    airline = QuerySelectField(
        'Aerolínea',
        query_factory=get_airlines,
        get_pk=lambda a: a.id,
        get_label=lambda a: a.name,
        allow_blank=False,
        validators=[DataRequired()]
    )

    departure_datetime = DateTimeLocalField('Fecha y Hora de Salida', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    arrival_datetime = DateTimeLocalField('Fecha y Hora de Llegada', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    price = DecimalField('Precio', validators=[DataRequired(), NumberRange(min=0.01)])
    total_seats = IntegerField('Asientos Totales', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Añadir Vuelo')

    def validate_arrival_datetime(self, field):
        if field.data and self.departure_datetime.data and field.data <= self.departure_datetime.data:
            raise ValidationError('La fecha y hora de llegada debe ser posterior a la de salida.')


# --- 8. Funciones Auxiliares ---

# Función de ayuda para enviar correos de restablecimiento de contraseña
def send_reset_email(user):
    token = serializer.dumps(user.id, salt='reset-password-salt')
    msg = Message('Restablecimiento de Contraseña',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    reset_url = url_for('reset_token', token=token, _external=True)
    msg.body = f'''Para restablecer tu contraseña, visita el siguiente enlace:
{reset_url}

Si tú no solicitaste esto, simplemente ignora este correo y tu contraseña permanecerá sin cambios.
'''
    mail.send(msg)

# Función de ayuda para verificar si el usuario es administrador (muy básica, por ID)
# **CORRECCIÓN:** Movida aquí como función global, eliminando la definición dentro de Booking.
def is_admin():
    return current_user.is_authenticated and current_user.id == 1 

# --- 9. Context Processors (Variables disponibles en todas las plantillas) ---
@app.context_processor
def inject_global_data():
    return dict(
        is_admin=is_admin(),
        now=datetime.now(),
        current_user=current_user
    )

# --- 10. Rutas de la Aplicación ---

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        first_name=form.first_name.data,
        last_name=form.last_name.data,
        phone_number=form.phone_number.data,
        address=form.address.data,

        new_user = User(username=username, email=email)
        new_user.set_password(password) # Usamos el método set_password
        db.session.add(new_user)
        db.session.commit()
        flash('¡Registro exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data 
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            flash('¡Inicio de sesión exitoso!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Email o contraseña incorrectos.', 'error')
    
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        if form.username.data != current_user.username:
            current_user.username = form.username.data
        if form.email.data != current_user.email:
            current_user.email = form.email.data

        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone_number = form.phone_number.data
        current_user.address = form.address.data

        db.session.commit()
        flash('Tu perfil ha sido actualizado con éxito.', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.phone_number.data = current_user.phone_number
        form.address.data = current_user.address

    return render_template('profile.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No hay una cuenta con ese correo electrónico. Por favor, verifica.', 'warning')
    return render_template('reset_request.html', title='Restablecer Contraseña', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    try:
        user_id = serializer.loads(token, salt='reset-password-salt', max_age=3600) # Token válido por 1 hora
    except:
        flash('El token es inválido o ha expirado.', 'warning')
        return redirect(url_for('reset_request'))

    user = User.query.get(user_id)
    if not user:
        flash('Token inválido. Usuario no encontrado.', 'warning')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data) # Usamos el método set_password
        db.session.commit()
        flash('Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', title='Restablecer Contraseña', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data) # Usamos el método set_password
        db.session.commit()
        flash('Tu contraseña ha sido cambiada exitosamente.', 'success')
        return redirect(url_for('profile'))
    return render_template('change_password.html', title='Cambiar Contraseña', form=form)

@app.route('/admin/add_test_data')
@login_required
def add_test_data():
    if not is_admin():
        flash('Acceso denegado. Solo administradores pueden añadir datos de prueba.', 'error')
        return redirect(url_for('home'))

    # Usamos db.session.query(Airport).first() en lugar de Airport.query.first()
    # para asegurar que la consulta se haga correctamente en el contexto de la aplicación.
    # Si Airport.query.first() falla, es un problema de contexto.
    with app.app_context(): # Aseguramos el contexto si esta ruta se ejecuta de forma independiente
        if db.session.query(Airport).first() and db.session.query(Airline).first() and db.session.query(Flight).first():
            flash('Datos de prueba ya existen.', 'info')
            return redirect(url_for('home'))

        # Añadir aeropuertos
        barinas = Airport(code='BNS', name='Aeropuerto Luisa Cáceres de Arismendi', city='Barinas', country='Venezuela')
        maiquetia = Airport(code='CCS', name='Aeropuerto Internacional Simón Bolívar', city='Maiquetía', country='Venezuela')
        maracaibo = Airport(code='MAR', name='Aeropuerto Internacional La Chinita', city='Maracaibo', country='Venezuela')
        valencia = Airport(code='VLN', name='Aeropuerto Internacional Arturo Michelena', city='Valencia', country='Venezuela')

        db.session.add_all([barinas, maiquetia, maracaibo, valencia])
        db.session.commit()
#aqui estuvo Geo buuajajajajjaja
        # Añadir aerolíneas
        laser = Airline(name='Laser Airlines', logo_url='https://example.com/laser.png')
        conviasa = Airline(name='Conviasa', logo_url='https://example.com/conviasa.png')
        venezolana = Airline(name='Venezolana', logo_url='https://example.com/venezolana.png')

        db.session.add_all([laser, conviasa, venezolana])
        db.session.commit()

        # Añadir vuelos de prueba
        vuelo1 = Flight(
            flight_number='LA101', origin_airport=barinas, destination_airport=maiquetia,
            airline=laser, departure_datetime=datetime(2025, 7, 10, 8, 0),
            arrival_datetime=datetime(2025, 7, 10, 9, 30), price=85.50, total_seats=100, available_seats=50
        )
        vuelo2 = Flight(
            flight_number='CO202', origin_airport=barinas, destination_airport=maracaibo,
            airline=conviasa, departure_datetime=datetime(2025, 7, 11, 14, 0),
            arrival_datetime=datetime(2025, 7, 11, 15, 45), price=120.00, total_seats=150, available_seats=75
        )
        vuelo3 = Flight(
            flight_number='VE303', origin_airport=barinas, destination_airport=valencia,
            airline=venezolana, departure_datetime=datetime(2025, 7, 12, 10, 0),
            arrival_datetime=datetime(2025, 7, 12, 11, 15), price=70.00, total_seats=60, available_seats=30
        )
        vuelo4 = Flight(
            flight_number='LA102', origin_airport=maiquetia, destination_airport=barinas,
            airline=laser, departure_datetime=datetime(2025, 7, 10, 18, 0),
            arrival_datetime=datetime(2025, 7, 10, 19, 30), price=85.50, total_seats=80, available_seats=40
        )

        db.session.add_all([vuelo1, vuelo2, vuelo3, vuelo4])
        db.session.commit()

        flash('¡Datos de prueba añadidos exitosamente!', 'success')
        return redirect(url_for('home'))

@app.route('/admin/add_flight', methods=['GET', 'POST'])
@login_required
def add_flight():
    if not is_admin():
        flash('Acceso denegado. Solo administradores pueden añadir vuelos.', 'error')
        return redirect(url_for('home'))

    barinas_airport = Airport.query.filter_by(code=BARINAS_AIRPORT_CODE).first()
    if not barinas_airport:
        flash(f'Error: El aeropuerto con código {BARINAS_AIRPORT_CODE} no se encontró en la base de datos. Por favor, añada los datos de prueba.', 'error')
        return redirect(url_for('home'))

    form = AddFlightForm()

    # Si quieres que el aeropuerto de origen siempre sea Barinas y no seleccionable en el formulario:
    form.origin_airport.query = Airport.query.filter_by(code=BARINAS_AIRPORT_CODE)
    form.origin_airport.data = barinas_airport

    if form.validate_on_submit():
        try:
            # **CORRECCIÓN:** .data ya devuelve el objeto si es QuerySelectField.
            # Necesitas acceder al .id del objeto para asignarlo a la FK.
            destination_airport = form.destination_airport.data
            airline = form.airline.data

            new_flight = Flight(
                flight_number=form.flight_number.data,
                origin_airport_id=barinas_airport.id,
                destination_airport_id=destination_airport.id, # Acceder al ID del objeto
                airline_id=airline.id, # Acceder al ID del objeto
                departure_datetime=form.departure_datetime.data,
                arrival_datetime=form.arrival_datetime.data,
                price=form.price.data,
                total_seats=form.total_seats.data,
                available_seats=form.total_seats.data
            )
            db.session.add(new_flight)
            db.session.commit()
            flash('¡Vuelo añadido exitosamente!', 'success')
            return redirect(url_for('add_flight'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al añadir el vuelo: {e}', 'error')

    return render_template('add_flight.html', form=form, barinas_airport=barinas_airport)


@app.route('/search_flights', methods=['GET', 'POST'])
def search_flights():
    barinas_airport = Airport.query.filter_by(code=BARINAS_AIRPORT_CODE).first()
    if not barinas_airport:
        flash(f'Error: El aeropuerto con código {BARINAS_AIRPORT_CODE} no se encontró en la base de datos.', 'error')
        return redirect(url_for('home'))

    airports = Airport.query.order_by(Airport.city).all()
    found_flights = []
    pagination = None
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10

    origin_id = str(barinas_airport.id)
    destination_id = None
    departure_date_str = None
    
    search_performed = False

    if request.method == 'POST':
        destination_id = request.form['destination_airport']
        departure_date_str = request.form['departure_date']

        session['last_search'] = {
            'origin_id': origin_id,
            'destination_id': destination_id,
            'departure_date_str': departure_date_str
        }
        search_performed = True
    else:
        last_search = session.get('last_search')
        if last_search and last_search['origin_id'] == origin_id:
            destination_id = last_search['destination_id']
            departure_date_str = last_search['departure_date_str']

    query = Flight.query.filter(Flight.origin_airport_id == barinas_airport.id)

    if destination_id and departure_date_str:
        try:
            departure_date = datetime.strptime(departure_date_str, '%Y-%m-%d').date()
            query = query.filter(
                Flight.destination_airport_id == destination_id,
                db.func.date(Flight.departure_datetime) == departure_date
            )
        except ValueError:
            flash('Formato de fecha inválido.', 'error')
            return render_template('search_flights.html', airports=airports, flights=[], pagination=None,
                                   selected_origin=origin_id, selected_destination=destination_id, selected_date=departure_date_str,
                                   barinas_airport=barinas_airport)
    else:
        today = date.today()
        query = query.filter(db.func.date(Flight.departure_datetime) >= today)

    query = query.order_by(Flight.departure_datetime)
    flights_paged = query.paginate(page=page, per_page=per_page, error_out=False)
    found_flights = flights_paged.items
    pagination = flights_paged

    if search_performed and not found_flights:
        flash('No se encontraron vuelos para los criterios de búsqueda especificados desde Barinas.', 'info')
    elif not search_performed and not found_flights:
        flash('No hay vuelos futuros disponibles desde Barinas en este momento.', 'info')


    return render_template('search_flights.html',
                           airports=airports,
                           flights=found_flights,
                           pagination=pagination,
                           selected_origin=origin_id,
                           selected_destination=destination_id,
                           selected_date=departure_date_str,
                           barinas_airport=barinas_airport)


@app.route('/book_flight/<int:flight_id>', methods=['POST'])
@login_required
def book_flight(flight_id):
    flight = Flight.query.get_or_404(flight_id)
    num_passengers = int(request.form.get('num_passengers', 1))

    if num_passengers <= 0:
        flash('El número de pasajeros debe ser al menos 1.', 'error')
        return redirect(url_for('search_flights'))

    if flight.available_seats < num_passengers:
        flash(f'Lo sentimos, solo quedan {flight.available_seats} asientos disponibles para este vuelo.', 'error')
        return redirect(url_for('search_flights'))

    try:
        total_price = flight.price * num_passengers
        new_booking = Booking(
            user=current_user,
            flight=flight,
            num_passengers=num_passengers,
            total_price=total_price,
            booking_date=datetime.utcnow()
        )
        db.session.add(new_booking)

        flight.available_seats -= num_passengers

        db.session.commit()
        flash('¡Reserva realizada con éxito!', 'success')
        return redirect(url_for('my_bookings'))
    except Exception as e:
        db.session.rollback()
        flash(f'Hubo un error al procesar tu reserva: {e}', 'error')
        return redirect(url_for('search_flights'))

@app.route('/my_bookings')
@login_required
def my_bookings():
    user_bookings = Booking.query.filter_by(user=current_user).order_by(Booking.booking_date.desc()).all()
    return render_template('my_bookings.html', bookings=user_bookings)


@app.route('/flight_details/<int:flight_id>')
def flight_details(flight_id):
    flight = Flight.query.get_or_404(flight_id)
    return render_template('flight_details.html', flight=flight)

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    if booking.user_id != current_user.id:
        flash('No tienes permiso para cancelar esta reserva.', 'error')
        return redirect(url_for('my_bookings'))

    if booking.status != 'Confirmed':
        flash('Esta reserva no se puede cancelar (estado actual: ' + booking.status + ').', 'error')
        return redirect(url_for('my_bookings'))

    if booking.flight.departure_datetime < datetime.utcnow():
        flash('No se puede cancelar esta reserva porque la fecha del vuelo ya ha pasado.', 'error')
        return redirect(url_for('my_bookings'))

    try:
        db.session.begin_nested() # Inicia una transacción anidada

        booking.status = 'Cancelled'
        db.session.add(booking)

        flight = booking.flight
        flight.available_seats += booking.num_passengers
        db.session.add(flight)

        db.session.commit()
        flash('Reserva cancelada con éxito. Se han añadido ' + str(booking.num_passengers) + ' asientos de vuelta al vuelo.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Hubo un error al cancelar la reserva: {e}', 'error')
    
    return redirect(url_for('my_bookings'))


# --- 11. Bloque Principal de Ejecución ---
if __name__ == '__main__':
    # Asegúrate de configurar tus variables de entorno antes de ejecutar:
    # export SECRET_KEY="una_clave_secreta_muy_larga_y_aleatoria"
    # export MAIL_USERNAME="ejecutivobraja01@gmail.com"
    # export MAIL_PASSWORD="xqckzwshoedqxvsx" # Contraseña de aplicación
    # (¡No uses tu contraseña normal de Gmail, usa una "contraseña de aplicación" para MAIL_PASSWORD!)

    with app.app_context(): # Es crucial usar app.app_context() para interactuar con db fuera de una solicitud
        db.create_all() # Esto creará las tablas si no existen
    app.run(debug=True)
