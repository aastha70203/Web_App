# Scalable Dashboard Web App

A modern, secure, and full-stack web application for managing personal notes. This project features a robust RESTful API backend and a responsive, glassmorphism-styled frontend dashboard. It includes user authentication, full-text search, sorting, pagination, and CRUD operations.

## Features

### User Authentication
- **Secure Sign Up & Login**: User registration and authentication using JWT (JSON Web Tokens)
- **Security**: Passwords are hashed using bcryptjs before storage
- **Session Management**: Uses HTTP-Only cookies for secure token storage (configurable) and local storage for client-side state

### Dashboard & Note Management
- **CRUD Operations**: Create, Read, Update, and Delete notes seamlessly
- **Search**: Real-time full-text search capability to find notes by title or content
- **Sorting**: Sort notes by "Newest", "Oldest", or "Relevance" (when searching)
- **Pagination**: Easy navigation through large sets of notes
- **Responsive Grid**: Notes are displayed in a responsive grid layout that adapts to screen size

### Security (Backend)
- **Rate Limiting**: Protects against brute-force attacks on auth routes and general API abuse
- **Data Sanitization**: Middleware to prevent NoSQL injection and XSS attacks
- **Secure Headers**: Uses helmet to set various HTTP headers for security
- **CORS Policy**: Configured Cross-Origin Resource Sharing to allow only trusted clients

### UI/UX
- **Modern Design**: Features a "Glassmorphism" aesthetic with vibrant gradients and blur effects
- **Interactive**: Smooth transitions, hover effects, and toast notifications for user feedback
- **Responsive**: Built with Tailwind CSS to look great on desktop and mobile

## 🛠️ Tech Stack

### Frontend
- **Framework**: React (via Vite)
- **Styling**: Tailwind CSS
- **HTTP Client**: Axios
- **State/Forms**: React Hook Form
- **Routing**: React Router DOM
- **Notifications**: React Hot Toast
- **Validation**: Zod

### Backend
- **Runtime**: Node.js
- **Framework**: Express.js (v5)
- **Database**: MongoDB (via Mongoose)
- **Authentication**: JSON Web Token (JWT) & Bcryptjs
- **Security**: Helmet, Express Rate Limit, XSS-Clean, Express Mongo Sanitize
- **Validation**: Zod

## 📋 Prerequisites

Before running the project, ensure you have the following installed:

- Node.js (v18+ recommended)
- MongoDB (Local instance or MongoDB Atlas cluster)
- Git

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd <your-project-folder>
```

### 2. Backend Setup

Navigate to the backend folder, install dependencies, and configure the environment.

```bash
cd backend
npm install
```

**Configure Environment Variables**: Create a `.env` file in the backend directory and add the following keys (you can copy from `.env.sample`):

```env
PORT=4000
MONGO_URI=mongodb://localhost:27017/dashboard_db  # Or your MongoDB Atlas connection string
JWT_SECRET=your_super_secret_random_key
JWT_EXPIRES_IN=1h
JWT_COOKIE_EXPIRES_DAYS=7
BCRYPT_SALT_ROUNDS=12
CLIENT_URL=http://localhost:5173  # URL where your frontend is running
NODE_ENV=development
```

**Start the Backend**:

```bash
npm run dev
```

You should see "Server running on 4000" and "MongoDB connected" in the terminal.

### 3. Frontend Setup

Open a new terminal, navigate to the frontend folder, install dependencies, and start the app.

```bash
cd frontend
npm install
```

**Configure Environment Variables**: Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:4000/api
```

**Start the Frontend**:

```bash
npm run dev
```

The app should now be running at http://localhost:5173.

## 📖 Usage Guide

1. **Register**: Open the app in your browser. Use the Sign Up page to create a new account.

2. **Login**: Log in with your new credentials.

3. **Dashboard**:
   - **Add Note**: Use the form at the top to type a title and content, then click "Add Note"
   - **Edit Note**: Click the pencil icon on any note card to populate the form with its data. Make changes and click "Update Note"
   - **Delete Note**: Click the trash icon on a note to remove it
   - **Search**: Type in the search bar to filter notes instantly
   - **Sort**: Use the dropdown to sort by Date or Relevance
   - **Pagination**: Use "Next" and "Previous" buttons at the bottom if you have many notes

4. **Logout**: Click the "Logout" button in the top right to end your session.

## 🛡️ API Endpoints

### Auth
- `POST /api/auth/signup` - Register a new user
- `POST /api/auth/login` - Authenticate user and receive token
- `GET /api/auth/check-email` - Check if an email exists

### Notes
- `GET /api/notes` - Fetch all notes (supports pagination, search, sort)
- `POST /api/notes` - Create a new note
- `GET /api/notes/:id` - Get a single note
- `PUT /api/notes/:id` - Update a note
- `DELETE /api/notes/:id` - Delete a note

### Users
- `GET /api/users/me` - Get current user profile