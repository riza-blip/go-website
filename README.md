# 🎪 EventHub - Event Management System

A full-featured event management system built with **Go**, **MySQL (XAMPP)**, and **Bootstrap 5**.

---

## 🚀 Quick Start

### Prerequisites
- **Go** 1.21+ → https://golang.org/dl/
- **XAMPP** (MySQL) → https://www.apachefriends.org/
- **VS Code** with Go extension

---

## 📦 Setup Steps

### Step 1: Database Setup
1. Start **XAMPP** and start the **MySQL** service
2. Open **phpMyAdmin** → http://localhost/phpmyadmin
3. Click **Import** → Choose `database.sql` → Click **Go**

### Step 2: Run the Application
**Windows:** Double-click `run.bat`

**Or manually:**
```bash
cd event_management
go mod tidy
go run main.go
```

### Step 3: Open the App
Go to → http://localhost:8080

---

## 👥 Demo Accounts

| Role       | Email                  | Password  |
|------------|------------------------|-----------|
| Admin      | admin@events.com       | admin123  |
| Organizer  | organizer@events.com   | admin123  |
| User       | user@events.com        | admin123  |

---

## 🎯 Features by Role

### 👑 Admin
- Dashboard with stats (users, events, bookings, revenue)
- **Approve/Reject** organizer events with reason
- **Feature** events on homepage
- Manage all users (add, edit, delete, ban)
- View all bookings across the platform
- Reports & analytics with charts

### 🎪 Organizer
- Dashboard with event performance metrics
- **Submit events** for admin review
- Edit and delete own events
- View all bookings for their events
- Get notified on approval/rejection
- Profile management

### 👤 User/Attendee
- Browse and search events by category
- **Book events** with ticket count
- View booking history with unique codes
- **Cancel bookings**
- **Leave reviews** for attended events
- Notification center
- Profile management with avatar upload

### 🌐 Public
- Landing page with featured events
- Browse all approved events
- Filter by category and search

---

## 📁 Project Structure

```
event_management/
├── main.go              # Main application + all handlers
├── go.mod               # Go module file
├── database.sql         # Database schema + seed data
├── run.bat              # Windows quick-start script
├── README.md            # This file
├── templates/           # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── admin_*.html
│   ├── organizer_*.html
│   ├── user_*.html
│   ├── event_view.html
│   └── events.html
└── static/
    └── uploads/         # User-uploaded images
```

---

## 🛠 Configuration

If your MySQL has a different password, edit `main.go` line:
```go
db, err = sql.Open("mysql", "root:YOUR_PASSWORD@tcp(localhost:3306)/event_management?parseTime=true")
```

---

## 🔄 Workflow

1. **Organizer** creates an event → Status: `pending`
2. **Admin** gets notified → Reviews the event
3. **Admin** approves → Event goes live → Organizer notified ✅
4. **Admin** rejects → Organizer gets rejection reason + can edit & resubmit
5. **Users** browse → Book events → Get booking confirmation code
6. **Organizer** sees all bookings for their events
7. **Users** can review events they've attended

---

## 📞 Tech Stack

- **Backend:** Go (net/http, standard library)
- **Database:** MySQL via XAMPP
- **Frontend:** Bootstrap 5, Chart.js, Google Fonts
- **Auth:** Cookie-based sessions with bcrypt passwords
- **Templates:** Go html/template

---

*Built for Go + XAMPP + VS Code setup*
