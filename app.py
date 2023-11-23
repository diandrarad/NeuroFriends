import sys
sys.path.append('/home/neptune/.local/lib/python3.10/site-packages')
import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from jinja2 import Markup, evalcontextfilter
from PIL import Image
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import apology, login_required


# Copied from CS50 pset9 Finance #######################################################


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure session is secure
app.secret_key = os.urandom(24)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///neurodivergent.db")


# Configure upload folder and allowed file extensions
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/profile_pics')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to check if file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.context_processor
def inject_profile_pic():
    """Loads user's profile picture"""
    if 'user_id' in session:
        profile = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
        if len(profile) > 0 and profile[0]["profile_picture"]:
            return dict(profile_pic=url_for("static", filename="profile_pics/" + profile[0]["profile_picture"]))
    return dict(profile_pic=url_for("static", filename="profile_pics/default.png"))


@app.template_filter()
@evalcontextfilter
def truncate_filter(eval_ctx, value, length):
    if len(value) <= length:
        return value
    else:
        return value[:length] + Markup('&hellip;')


# Routes ##################################################################


@app.route("/")
def index():
    # Query the database to get the latest 10 events
    events = db.execute("SELECT * FROM events ORDER BY date LIMIT 4")

    # Query the database to get FAQs
    faqs = db.execute("SELECT * FROM faqs")
    
    # Pass the events and FAQs data to the HTML template for rendering
    return render_template("index.html", events=events, faqs=faqs)


@app.route("/messaging/received")
@login_required
def received():
    # Query the database to get the current user's username and messages
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    messages = db.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY timestamp DESC", username)
    
    # Pass the current user's username and messages data to the HTML template for rendering
    return render_template("messaging/messages.html", messages=messages, method="Sender")
            

@app.route("/messaging/delete/<int:id>", methods=["POST"])
@login_required
def delete_message(id):
    if request.method == "POST":
        # Query for the message
        message = db.execute('SELECT * FROM messages WHERE id = ?', id)[0]

        # If the message doesn't exist or the user is not the author, return a 404
        if not message:
            return apology("invalid message")
        
        # Delete the entry with the specified ID
        db.execute("DELETE FROM messages WHERE id = ?", id)
        flash("Message deleted successfully!")
        return redirect("/messaging/received")


@app.route("/messaging/compose/<int:recipient_id>", methods=["GET", "POST"])
@login_required
def compose(recipient_id):
    if request.method == "POST":
        sender = request.form.get("sender")
        recipient = request.form.get("recipient")
        subject = request.form.get("subject")
        body = request.form.get("body")
        
        if not sender or not recipient or not subject or not body:
            return apology("no empty field")
        
        db.execute("INSERT INTO messages (sender, recipient, subject, body) VALUES (?, ?, ?, ?)", sender, recipient, subject, body)
                
        flash("Message Sent.", "success")
        return redirect("/messaging/sent")
    
    sender = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    recipient = db.execute("SELECT username FROM users WHERE id = ?", recipient_id)[0]["username"]
    return render_template("messaging/compose.html", sender=sender, recipient=recipient, recipient_id=recipient_id)


@app.route("/messaging/compose", methods=["GET", "POST"])
@login_required
def compose2():
    if request.method == "POST":
        sender = request.form.get("sender")
        recipient = request.form.get("recipient")
        subject = request.form.get("subject")
        body = request.form.get("body")
        
        if not sender or not recipient or not subject or not body:
            return apology("no empty field")
        
        usernames = [row['username'] for row in db.execute("SELECT username FROM users")]
        if recipient not in usernames:
            return apology("invalid recipient username")
        
        db.execute("INSERT INTO messages (sender, recipient, subject, body) VALUES (?, ?, ?, ?)", sender, recipient, subject, body)

        flash("Message Sent.", "success")
        return redirect("/messaging/sent")
    
    sender = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    all_users = db.execute("SELECT * FROM users WHERE id != ?", session["user_id"])
    return render_template("messaging/compose2.html", sender=sender, all_users=all_users)
    

@app.route("/messaging/sent")
@login_required
def sent():
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    messages = db.execute("SELECT * FROM messages WHERE sender = ? ORDER BY timestamp DESC", username)
    return render_template("messaging/messages.html", messages=messages, method="Recipient")


@app.route("/messaging/detail", methods=["POST"])
@login_required
def detail():
    if request.method == "POST":
        detail = db.execute("SELECT * FROM messages WHERE id = ?", request.form.get("message_id"))[0]
        current_user = db.execute("SELECT username FROM users WHERE id=?", session["user_id"])[0]["username"]
        role = 0
        if detail["recipient"] == current_user:
            role = 1
        return render_template("messaging/detail.html", detail=detail, role=role)


@app.route("/messaging/reply", methods=["POST"])
@login_required
def reply():
    if request.method == "POST":
        detail = db.execute("SELECT * FROM messages WHERE id = ?", request.form.get("message_id"))[0]
        return render_template("messaging/reply.html", detail=detail)


@app.route("/people", methods=["GET", "POST"])
@login_required
def people():
    all_users = db.execute("SELECT * FROM users WHERE id != ?", session["user_id"])
    users_details = []
    for user in all_users:
        user_profile = db.execute("SELECT * FROM users WHERE id = ?", user["id"])[0]
        user_interests = db.execute(
            "SELECT interests.name FROM interests JOIN profile_interests ON interests.id = profile_interests.interest_id WHERE profile_interests.profile_id = ?",
            user_profile["id"]
        )
        user_dict = {
            "id": user["id"],
            "username": user["username"],
            "first_name": user_profile["first_name"],
            "last_name": user_profile["last_name"],
            "pronouns": user_profile["pronouns"],
            "bio": user_profile["bio"],
            "interests": [interest["name"] for interest in user_interests],
            "profile_picture": user_profile["profile_picture"]
        }
        if user_dict["id"] != session["user_id"]:
            users_details.append(user_dict)
    if request.method == "POST":
        interest = request.form.get("interest")
        if interest:
            users_details = [user for user in users_details if interest in user["interests"]]
    interests = db.execute("SELECT * FROM interests")
    return render_template("people.html", users=users_details, interests=interests)


@app.route("/user", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        # Get the form data
        first_name = request.form.get("first_name").title()
        last_name = request.form.get("last_name").title()
        pronouns = request.form.get("pronouns").title()
        age = request.form.get("age")
        bio = request.form.get("bio")

        # Check if profile picture uploaded
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            # Check if the file is one of the allowed types/extensions
            if profile_pic and allowed_file(profile_pic.filename):
                filename = secure_filename(f"user_id_{session['user_id']}.jpg")
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                profile_pic.save(filepath)
                with Image.open(filepath) as img:
                    width, height = img.size
                    size = min(width, height)
                    img = img.crop(((width - size) // 2, (height - size) // 2, (width + size) // 2, (height + size) // 2))
                    img = img.resize((256, 256))
                    img.save(filepath)
                db.execute("UPDATE users SET first_name=?, last_name=?, pronouns=?, age=?, bio=?, profile_picture=? WHERE id=?",
                            first_name, last_name, pronouns, age, bio, filename, session["user_id"])
            elif profile_pic:
                flash("Invalid file type. Only JPG, JPEG, PNG, and GIF files are allowed.", "danger")
                return redirect("/user")

        # Update profile without profile picture
        db.execute("UPDATE users SET first_name=?, last_name=?, pronouns=?, age=?, bio=? WHERE id=?",
                    first_name, last_name, pronouns, age, bio, session["user_id"])
        # Handle interests
        interests = request.form.getlist("interests[]")
        if interests:
            # Delete existing interests
            db.execute("DELETE FROM profile_interests WHERE profile_id=?", session["user_id"])
            # Insert new interests
            for interest_id in interests:
                db.execute("INSERT INTO profile_interests (profile_id, interest_id) VALUES (?, ?)", session["user_id"], interest_id)
                
        flash("Profile updated successfully.", "success")
        return redirect("/user")
    
    profile = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
    
    if profile[0]['profile_picture']:
        profile_picture = url_for('static', filename='profile_pics/' + profile[0]['profile_picture'])
    else:
        profile_picture = url_for('static', filename='profile_pics/default.png')
    
    interests = db.execute("SELECT interests.id, interests.name, profile_interests.interest_id FROM interests LEFT JOIN profile_interests ON interests.id=profile_interests.interest_id AND profile_interests.profile_id=? ORDER BY interests.name", session["user_id"])
    selected_interests = [interest["interest_id"] for interest in interests if interest["interest_id"]]

    return render_template("user.html", profile=profile[0], profile_picture=profile_picture, interests=interests, selected_interests=selected_interests)


@app.route("/create_profile", methods=["GET", "POST"])
@login_required
def create_profile():
    
    if request.method == "POST":
        # Get the form data
        first_name = request.form.get("first_name").title()
        last_name = request.form.get("last_name").title()
        gender = request.form.get("gender")
        age = request.form.get("age")
        bio = request.form.get("bio")
        
        if not first_name or not last_name or not gender or not age or not bio:
            return apology("no empty field")

        # Check if profile picture uploaded
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            # Check if the file is one of the allowed types/extensions
            if profile_pic and allowed_file(profile_pic.filename):
                filename = secure_filename(f"user_id_{session['user_id']}.jpg")
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                profile_pic.save(filepath)
                with Image.open(filepath) as img:
                    width, height = img.size
                    size = min(width, height)
                    img = img.crop(((width - size) // 2, (height - size) // 2, (width + size) // 2, (height + size) // 2))
                    img = img.resize((256, 256))
                    img.save(filepath)
                db.execute("INSERT INTO profiles (user_id, first_name, last_name, gender, age, bio, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    session["user_id"], first_name, last_name, gender, age, bio, filename)
            elif profile_pic:
                flash("Invalid file type. Only JPG, JPEG, PNG, and GIF files are allowed.", "danger")
                return redirect("/user")

        # Insert the user's profile into the database
        db.execute("INSERT INTO profiles (user_id, first_name, last_name, gender, age, bio) VALUES ( ?, ?, ?, ?, ?, ?)",
                    session["user_id"], first_name, last_name, gender, age, bio)
        # Handle interests
        interests = request.form.getlist("interests[]")
        if interests:
            # Insert new interests
            for interest_id in interests:
                db.execute("INSERT INTO profile_interests (profile_id, interest_id) VALUES (?, ?)", session["user_id"], interest_id)

        flash("Profile created successfully.", "success")
        return redirect("/user")

    # Check if user has already created a profile
    profile = db.execute("SELECT * FROM profiles WHERE user_id=?", session["user_id"])
    if len(profile) > 0:
        return redirect("/user")
    
    profile_picture = url_for('static', filename='profile_pics/default.png')
    
    interests = db.execute("SELECT * FROM interests")
    
    # Render the create profile page
    return render_template("create_profile.html", profile_picture=profile_picture, interests=interests)


@app.route("/user/<int:user_id>")
@login_required
def view_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id=?", user_id)
    if len(user) == 0:
        flash("User not found", "danger")
        return redirect(url_for("index"))
    
    interests = db.execute("SELECT interests.id, interests.name, profile_interests.interest_id FROM interests LEFT JOIN profile_interests ON interests.id=profile_interests.interest_id AND profile_interests.profile_id=? ORDER BY interests.name", session["user_id"])
    
    return render_template("view_user.html", user=user[0], interests=interests)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        password = request.form.get("password")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password and confirmation was submitted
        elif not password or not request.form.get("confirmation"):
            return apology("must provide password and confirmation", 400)

        if len(password) < 8:
            return apology("Password must be at least 8 characters long")
        if not re.search("[a-z]", password):
            return apology("Password must contain at least one lowercase letter")
        if not re.search("[A-Z]", password):
            return apology("Password must contain at least one uppercase letter")
        if not re.search("[0-9]", password):
            return apology("Password must contain at least one number")

        # Ensure password was submitted
        elif password != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not already exist
        if len(rows) != 0:
            return apology("username already exist", 400)

        # Insert new user into database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                   request.form.get("username"), generate_password_hash(password))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":

        # Get current and new password from form data
        current_password = request.form.get("current_password")
        new_password = request.form.get("password")

        # Ensure password and confirmation was submitted
        if not current_password:
            return apology("must provide current password", 403)

        # Query database for user's current password hash
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Verify current password is correct
        if not check_password_hash(rows[0]["hash"], current_password):
            return apology("Current password is incorrect")

        if len(new_password) < 8:
            return apology("Password must be at least 8 characters long")
        if not re.search("[a-z]", new_password):
            return apology("Password must contain at least one lowercase letter")
        if not re.search("[A-Z]", new_password):
            return apology("Password must contain at least one uppercase letter")
        if not re.search("[0-9]", new_password):
            return apology("Password must contain at least one number")

        if new_password != request.form.get("confirm_password"):
            return apology("passwords must match", 403)

        # Update user's password in database with new hash
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        # Redirect user to home page
        flash("Password Changed", "success")
        return redirect("/")

    # If request method is GET, render the change password form
    return render_template("change_password.html")


@app.route("/forum", methods=["GET", "POST"])
@login_required
def forum():
    # Query the database to get the latest forum posts
    posts = db.execute("SELECT * FROM posts ORDER BY created_at DESC")

    # Pass the forum posts data to the HTML template for rendering
    return render_template("forum.html", posts=posts, current_user=str(session["user_id"]))


@app.route("/forum/create_post", methods=["GET", "POST"])
@login_required
def create_post():
    if request.method == "POST":
        # Get the post data from the form
        title = request.form.get("title")
        body = request.form.get("body")
        
        if not title or not body:
            return apology("no empty field")

        # Insert the post data into the database
        db.execute("INSERT INTO posts (author, title, body) VALUES (?, ?, ?)",
                   session["user_id"], title, body)

        # Redirect the user to the forum page
        flash("Post Uploaded", "success")
        return redirect(url_for("forum"))
    
    # Render the create post form if the request method is GET
    return render_template("forum/create_post.html")


@app.route("/forum/posts/<int:id>")
def view_post(id):
    # Query database for post
    post = db.execute("SELECT * FROM posts WHERE id = ?", id)[0]

    # If posts doesn't exist, return 404 error page
    if not post:
        return apology("404")
    
    # Retrieve the author information from the database
    author = db.execute('SELECT * FROM users WHERE id = ?', post['author'])[0]

    # Render view post page with post data
    return render_template("forum/view_post.html", post=post, author=author)


@app.route('/forum/edit_post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    # Query for the post
    post = db.execute('SELECT * FROM posts WHERE id = ?', id)[0]

    # If the post doesn't exist or the user is not the author, return a 404
    if not post or post['author'] != str(session['user_id']):
        return apology("author only")

    if request.method == 'POST':
        # Get the form data
        title = request.form.get('title')
        body = request.form.get('body')
        
        if not title or not body:
            return apology("no empty field")

        # Update the post in the database
        db.execute('UPDATE posts SET title = ?, body = ? WHERE id = ?', title, body, id)

        # Redirect to the post page
        flash("Post updated successfully.", "success")
        return redirect(url_for("forum"))
    else:
        # Render the edit post form
        return render_template('forum/edit_post.html', post=post)
            

@app.route("/forum/delete/<int:id>", methods=["POST"])
@login_required
def delete_post(id):
    if request.method == "POST":
        # Query for the post
        post = db.execute('SELECT * FROM posts WHERE id = ?', id)[0]

        # If the post doesn't exist or the user is not the author, return a 404
        if not post or post['author'] != str(session['user_id']):
            return apology("author only")
        
        # Delete the entry with the specified ID
        db.execute("DELETE FROM posts WHERE id = ?", id)
        flash("Post deleted successfully!")
        return redirect("/forum")
    

@app.route("/events")
@login_required
def events():
    # Query database for all events
    events = db.execute("SELECT * FROM events ORDER BY id DESC")

    # Render events page with events data
    return render_template("events.html", events=events, current_user=session["user_id"])


@app.route("/events/create", methods=["GET", "POST"])
@login_required
def create_event():
    if request.method == 'POST':
        # Get the form data
        title = request.form.get('title')
        date = request.form.get('date')
        time = request.form.get('time')
        location = request.form.get('location')
        description = request.form.get('description')
        
        if not title or not date or not time or not location or not description:
            return apology("no empty field")

        db.execute('INSERT INTO events (title, date, time, location, description, author) VALUES (?, ?, ?, ?, ?, ?)',
                    title, date, time, location, description, session['user_id'])

        flash('Event created successfully!', 'success')
        return redirect(url_for('events'))
    
    return render_template('events/create_event.html')


@app.route('/events/<int:id>', methods=['GET'])
@login_required
def view_event(id):
    # Retrieve the event information from the database
    event = db.execute('SELECT * FROM events WHERE id = ?', id)[0]
    if not event:
        redirect(events)

    # Retrieve the author information from the database
    author = db.execute('SELECT * FROM users WHERE id = ?', event['author'])[0]

    current_user = db.execute("SELECT id FROM users WHERE id=?", session["user_id"])[0]["id"]
    is_author = 0
    if author["id"] == current_user:
        is_author = 1

    # Render the template with the event information
    return render_template('events/view_event.html', event=event, author=author, is_author=is_author)


@app.route('/events/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_event(id):
    # Query for the event
    event = db.execute('SELECT * FROM events WHERE id = ?', id)[0]

    # If the event doesn't exist or the user is not the author, return a 404
    if not event or event['author'] != session['user_id']:
        return apology("author only")

    if request.method == 'POST':
        # Get the form data
        title = request.form.get('title')
        date = request.form.get('date')
        time = request.form.get('time')
        location = request.form.get('location')
        description = request.form.get('description')
        
        if not title or not date or not time or not location or not description:
            return apology("no empty field")

        # Update the event in the database
        db.execute('UPDATE events SET title = ?, date = ?, time = ?, location = ?, description = ? WHERE id = ?',
                    title, date, time, location, description, id)

        # Redirect to the event page
        flash("Event updated successfully.", "success")
        return redirect(url_for('view_event', id=id))
    else:
        # Render the edit event form
        return render_template('events/edit_event.html', event=event)
            

@app.route("/events/delete/<int:id>", methods=["POST"])
@login_required
def delete_event(id):
    if request.method == "POST":
        # Query for the event
        event = db.execute('SELECT * FROM events WHERE id = ?', id)[0]

        # If the event doesn't exist or the user is not the author, return a 404
        if not event or event['author'] != session['user_id']:
            return apology("author only")
        
        # Delete the entry with the specified ID
        db.execute("DELETE FROM events WHERE id = ?", id)
        flash("Event deleted successfully!")
        return redirect("/events")
    

@app.route('/resources')
def resources():
    # Get all resources from the database
    resources = db.execute("SELECT * FROM resources ORDER BY id DESC")

    # Render the resources template with the resources data
    return render_template('resources.html', resources=resources, current_user=session["user_id"])


@app.route('/resources/create', methods=['GET', 'POST'])
@login_required
def create_resources():
    if request.method == 'POST':
        # Get the form data
        title = request.form.get('title')
        description = request.form.get('description')
        link = request.form.get('link')
        
        if not title or not description or not link:
            return apology("no empty field")

        # Insert resource into database
        db.execute('INSERT INTO resources (title, description, link, author) VALUES (?, ?, ?, ?)',
                   title, description, link, session["user_id"])

        flash('Resource created successfully', 'success')
        return redirect(url_for('resources'))
    
    return render_template('resources/create_resources.html')


@app.route('/resources/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_resource(id):
    # Query for the resource
    resource = db.execute('SELECT * FROM resources WHERE id = ?', id)[0]

    # If the resource doesn't exist or the user is not the author, return a 404
    if not resource or resource['author'] != session['user_id']:
        return apology("author only")

    if request.method == 'POST':
        # Get the form data
        title = request.form.get('title')
        description = request.form.get('description')
        link = request.form.get('link')

        # Update the resource in the database
        db.execute('UPDATE resources SET title = ?, description = ?, link = ? WHERE id = ?', title, description, link, id)

        # Redirect to the resource page
        flash("Resource updated successfully.", "success")
        return redirect(url_for('resources'))
    else:
        # Render the edit resource form
        return render_template('resources/edit_resource.html', resource=resource)
            

@app.route("/resources/delete/<int:id>", methods=["POST"])
@login_required
def delete_resource(id):
    if request.method == "POST":
        # Query for the resource
        resource = db.execute('SELECT * FROM resources WHERE id = ?', id)[0]

        # If the resource doesn't exist or the user is not the author, return a 404
        if not resource or resource['author'] != session['user_id']:
            return apology("author only")
        
        # Delete the entry with the specified ID
        db.execute("DELETE FROM resources WHERE id = ?", id)
        flash("Resource deleted successfully!")
        return redirect("/resources")


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
