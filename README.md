# Student Management System

A web-based academic management platform built using **Python Flask, SQLite, HTML, CSS, and JavaScript** to simplify student records, attendance tracking, internal assessment results, online examinations, and teacher availability.

## About the Project

The Student Management System is designed to bring essential academic activities into one centralized application. It reduces the need for manual registers and separate spreadsheets by providing dedicated dashboards for students, teachers, and administrators.

The system also includes a rule-based help assistant that guides students and teachers in using the application.

## Features

### Student Dashboard
- View personal academic details.
- Check lecture attendance records.
- View internal assessment (IAT) marks and quiz scores.
- Generate and print academic report cards.
- Attempt online quizzes and written tests.
- Check teacher availability.
- Use the built-in help assistant.
- Change account password.

### Teacher Dashboard
- Mark and manage student attendance.
- Enter internal assessment marks.
- Create, start, and stop online quizzes and written tests.
- View student performance and attendance analytics.
- Check and update teacher availability.
- Register student details.
- Use the help assistant.

### Administrator Dashboard
- Add, view, and delete student records.
- Add, view, and delete teacher records.
- Create and manage user passwords.
- View and delete quiz scores and IAT marks.

### Additional Features
- Role-based access control for students, teachers, and administrators.
- Password hashing and session-based authentication.
- Online quizzes with automatic server-side scoring.
- Full-screen mode and camera permission requests during assessments.
- Attendance percentage and academic performance analysis.
- Rule-based chatbot with keyword matching, synonyms, and spelling-error tolerance.
- SQLite database for storing academic records.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| SQLite | Database management |
| HTML5 | Web page structure |
| CSS3 | Styling and responsive layouts |
| JavaScript | Client-side interactivity |
| Jinja2 | Dynamic HTML templates |

## System Architecture

The application follows a simple client-server architecture:

1. **Frontend:** HTML, CSS, JavaScript, and Jinja2 templates provide the login page and role-specific dashboards.
2. **Backend:** Flask handles authentication, attendance, marks, quizzes, examinations, and other application operations.
3. **Database:** SQLite stores user accounts, student and teacher details, attendance records, results, quiz scores, examinations, and teacher availability.

## Installation and Setup

### Prerequisites
- Python 3.10 or later
- pip (Python package installer)
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
```

Navigate to the project folder:

```bash
cd YOUR-REPOSITORY
```

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

On macOS or Linux:

```bash
source venv/bin/activate
```

### Step 3: Install Dependencies

If the project contains a `requirements.txt` file, run:

```bash
pip install -r requirements.txt
```

Otherwise, install the required packages used by the application:

```bash
pip install Flask Werkzeug
```

### Step 4: Run the Application

Run the Flask application using the Python file that contains your Flask app. For example, if the main file is `app.py`:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000/
```

**Note:** Follow the application's initial setup page to create the administrator account if your version uses first-time administrator setup.

## Database

The project uses SQLite, a lightweight database that does not require a separate database server. The database stores user credentials as password hashes along with academic and administrative records.

The database file is created or initialized according to the application's implementation.

## Security

The system incorporates several security measures:

- Password hashing using the scrypt algorithm.
- Session-based authentication.
- Role-based authorization.
- Parameterized SQL queries to help prevent SQL injection.
- Input validation and output escaping.
- Restrictions on unauthorized access to student and teacher records.
- Server-side quiz scoring to prevent users from submitting arbitrary scores.

For production deployment, HTTPS, automated database backups, and audit logging should be configured.

## Future Enhancements

- Implement timetable and assignment management.
- Add study material sharing.
- Introduce complaint and leave request modules.
- Improve chatbot understanding of paraphrased questions.
- Add automated database backups and audit logs.
- Improve pagination and database performance for larger institutions.
- Strengthen online examination monitoring.

## Project Purpose

This project demonstrates the development of a role-based academic management application that integrates student information, attendance, assessment, examination, and teacher availability features into one platform.

## Contributors

- Noor Fatima Chandel
- Tanishka Bhoir
- Kanak Nikalje
- Sumedha Patil

Department of Computer Engineering  
Terna Engineering College, Navi Mumbai, Maharashtra, India

## License

This project is intended for academic and educational purposes. Add a suitable open-source license if you wish to permit reuse or redistribution.
