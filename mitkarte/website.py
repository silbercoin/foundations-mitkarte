from flask import Flask
from flask import render_template, request, flash, redirect, url_for, session, logging
# from data import Stores
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# config Mysql
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init mysql
mysql = MySQL(app)


# Stores = Stores()

# configure Flask using environment variables
app.config.from_pyfile("config.py")


@app.route("/")
def index():
    return render_template("index.html", page_title="mitkarte")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/stores")
def stores():

    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM stores")

    stores = cur.fetchall()

    if result > 0:
        return render_template('stores.html', stores=stores)
    else:
        msg = 'No Stores Found'
        return render_template('stores.html', msg=msg)

    cur.close()


@app.route("/store/<string:id>/")
def store(id):

    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM stores WHERE id = %s", [id])

    store = cur.fetchone()

    return render_template("store.html", store=store)


class RegisterForm(Form):
    email = StringField(
        'Email', [validators.Email(check_deliverability=True, granular_message=True)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor
        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO users(email, password) VALUES(%s,%s)", (email, password))

        # commit to DB
        mysql.connection.commit()

        # close connection
        cur.close()

        flash('You are now registered and can log in now', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # Ger user by email
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            # get stored hash
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # passed
                session['logged_in'] = True
                session['email'] = email

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
            return render_template('login.html', error=error)

            cur.close()
        else:
            error = 'Email was not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():

    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM stores")

    stores = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', stores=stores)
    else:
        msg = 'No Stores Found'
        return render_template('dashboard.html', msg=msg)

    cur.close()


class StoreForm(Form):
    name = StringField(
        'Name', [validators.Length(min=1, max=200)])
    address = TextAreaField(
        'Address', [validators.Length(min=10)])
    category = StringField(
        'Category', [validators.Length(min=1, max=30)])


@app.route('/add_store', methods=['GET', 'POST'])
@is_logged_in
def add_store():
    form = StoreForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        address = form.address.data
        category = form.category.data

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO stores(name, address, category, poster) VALUES(%s,%s,%s,%s)",
                    (name, address, category, session['email']))

        mysql.connection.commit()

        cur.close()

        flash('Store added', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_store.html', form=form)


@app.route('/edit_store/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_store(id):

    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM stores WHERE id = %s", [id])

    store = cur.fetchone()

    form = StoreForm(request.form)

    form.name.data = store['name']
    form.address.data = store['address']
    form.category.data = store['category']

    if request.method == 'POST' and form.validate():
        name = request.form['name']
        address = request.form['address']
        category = request.form['category']

        cur = mysql.connection.cursor()

        cur.execute("UPDATE stores SET name = %s, address = %s, category = %s WHERE id = %s",
                    (name, address, category, id))

        mysql.connection.commit()

        cur.close()

        flash('Store Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_store.html', form=form)


@app.route('/delete_store/<string:id>', methods=['POST'])
@is_logged_in
def delete_store(id):

    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM stores WHERE id = %s", [id])

    mysql.connection.commit()

    cur.close()

    flash('Store Deleted', 'success')

    return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.secret_key = 'secret123'
    app.run(host="localhost", port=8080, debug=True)
