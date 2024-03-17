![NeuroFriends logo](./static/logo.png)

![Screenshot](demo.gif)

### [Video Demo](https://youtu.be/5Mp0ZaFU1gs)

# Overview
NeuroFriends is a social networking site for neurodiverse individuals to connect and communicate with each other. The goal is to provide a safe and supportive space for individuals who are on the autism spectrum, have ADHD, or other neurological differences.

NeuroFriends is a social networking site designed specifically for neurodiverse individuals to connect and communicate with each other in a safe and supportive environment. The platform offers a range of features to facilitate this, including user registration and login, as well as customizable user profiles.

Users have the option to add their information to their profiles and can choose what information to share with others. Additionally, NeuroFriends provides a private messaging system between users, which allows for secure and direct communication.

The forum feature is an important aspect of the platform, offering a space for discussions and support. Users can create forum posts, and read posts from other users on a range of topics relevant to neurodiverse individuals.

Another key feature of NeuroFriends is the event creation system, which allows users to create and manage events.

Finally, the platform includes a resource-sharing and management system, which allows users to share resources related to neurodiversity. Users can create, view, and edit resources, as well as manage their contributions.

# Technologies

- Flask (Python web framework)
- Jinja2 (template engine)
- SQLite (relational database management system)
- Werkzeug (utility library for WSGI applications)
- Javascript
- HTML
- CSS
- Bootstrap 5

# Basic Functionality

NeuroFriends provides the following functionality:

- User registration and login
- User profiles with customizable information
- Private messaging system between users
- Forum for discussions and support
- Event creation
- Resource sharing and management

# Installation

To run the NeuroFriends application on your local machine, follow these steps:

- Clone the repository to your local machine
- Set up a virtual environment in the project directory
- Install the required dependencies by running pip install -r requirements.txt
- To run the project, all you have to do is go "flask run" in your terminal window.

Once the web application is running, you can use the provided functionality by navigating to the appropriate route:

- /user: View your own profile or update your profile information
- /user/<int:user_id>: View another user's profile
- /messaging: View your private messages and send new messages
- /forum: View and create forum posts, as well as edit or delete your own posts
- /events: View events, as well as create or edit events you are hosting
- /resources: View and create resources, as well as edit or delete your own resources

Note: Some functionality may require you to be logged in or have appropriate permissions.
