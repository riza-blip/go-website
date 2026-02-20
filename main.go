package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ===================== MODELS =====================

type User struct {
	ID        int
	Name      string
	Email     string
	Password  string
	Role      string
	Phone     string
	Avatar    string
	Status    string
	CreatedAt time.Time
}

type Event struct {
	ID              int
	Title           string
	Description     string
	Category        string
	Venue           string
	Location        string
	EventDate       string
	EventTime       string
	EndDate         string
	EndTime         string
	Capacity        int
	Price           float64
	Image           string
	OrganizerID     int
	OrganizerName   string
	Status          string
	RejectionReason string
	IsFeatured      bool
	BookingCount    int
	UserBooked      bool
	CreatedAt       time.Time
}

type Booking struct {
	ID          int
	EventID     int
	EventTitle  string
	EventDate   string
	UserID      int
	UserName    string
	UserEmail   string
	Tickets     int
	TotalPrice  float64
	Status      string
	BookingCode string
	Notes       string
	CreatedAt   time.Time
}

type Notification struct {
	ID        int
	UserID    int
	Title     string
	Message   string
	Type      string
	IsRead    bool
	CreatedAt time.Time
}

type Review struct {
	ID        int
	EventID   int
	UserID    int
	UserName  string
	Rating    int
	Comment   string
	CreatedAt time.Time
}

type Session struct {
	UserID int
	Email  string
	Name   string
	Role   string
}

type PageData struct {
	Session       *Session
	Events        []Event
	Event         *Event
	Users         []User
	User          *User
	Bookings      []Booking
	Booking       *Booking
	Notifications []Notification
	Reviews       []Review
	Stats         map[string]int
	Message       string
	Error         string
	Categories    []string
	CurrentPage   string
}

// ===================== GLOBALS =====================

var db *sql.DB
var sessions = make(map[string]*Session)
var templates *template.Template

var funcMap = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"mul": func(a, b int) int { return a * b },
	"iterate": func(n int) []int {
		result := make([]int, n)
		for i := range result {
			result[i] = i + 1
		}
		return result
	},
	"formatDate": func(d string) string {
		t, err := time.Parse("2006-01-02", d)
		if err != nil {
			return d
		}
		return t.Format("January 02, 2006")
	},
	"formatPrice": func(p float64) string {
		if p == 0 {
			return "Free"
		}
		return fmt.Sprintf("₱%.2f", p)
	},
	"statusClass": func(s string) string {
		switch s {
		case "approved", "confirmed", "active":
			return "success"
		case "pending":
			return "warning"
		case "rejected", "cancelled", "banned":
			return "danger"
		default:
			return "secondary"
		}
	},
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"eq": func(a, b interface{}) bool { return fmt.Sprint(a) == fmt.Sprint(b) },
	"ne": func(a, b interface{}) bool { return fmt.Sprint(a) != fmt.Sprint(b) },
	"gt": func(a, b int) bool { return a > b },
	"lt": func(a, b int) bool { return a < b },
}

var categories = []string{"Conference", "Concert", "Workshop", "Sports", "Exhibition", "Festival", "Seminar", "Networking", "Party", "Other"}

// ===================== MAIN =====================

func main() {
	var err error
	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/event_management?parseTime=true")
	if err != nil {
		log.Fatal("DB connection error:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("DB ping error:", err)
	}
	log.Println("✅ Connected to MySQL database")

	// Load templates
	templates = template.New("").Funcs(funcMap)
	templates, err = templates.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Template parse error:", err)
	}

	// Create uploads dir
	os.MkdirAll("static/uploads", 0755)

	// Routes
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Auth
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/logout", logoutHandler)

	// Events (public)
	mux.HandleFunc("/events", eventsHandler)
	mux.HandleFunc("/events/view", eventViewHandler)

	// User routes
	mux.HandleFunc("/user/dashboard", userDashboardHandler)
	mux.HandleFunc("/user/book", bookEventHandler)
	mux.HandleFunc("/user/bookings", userBookingsHandler)
	mux.HandleFunc("/user/cancel-booking", cancelBookingHandler)
	mux.HandleFunc("/user/profile", userProfileHandler)
	mux.HandleFunc("/user/review", submitReviewHandler)
	mux.HandleFunc("/user/notifications", userNotificationsHandler)
	mux.HandleFunc("/user/mark-notification", markNotificationHandler)

	// Organizer routes
	mux.HandleFunc("/organizer/dashboard", organizerDashboardHandler)
	mux.HandleFunc("/organizer/events", organizerEventsHandler)
	mux.HandleFunc("/organizer/events/add", organizerAddEventHandler)
	mux.HandleFunc("/organizer/events/edit", organizerEditEventHandler)
	mux.HandleFunc("/organizer/events/delete", organizerDeleteEventHandler)
	mux.HandleFunc("/organizer/bookings", organizerBookingsHandler)

	// Admin routes
	mux.HandleFunc("/admin/dashboard", adminDashboardHandler)
	mux.HandleFunc("/admin/users", adminUsersHandler)
	mux.HandleFunc("/admin/users/add", adminAddUserHandler)
	mux.HandleFunc("/admin/users/edit", adminEditUserHandler)
	mux.HandleFunc("/admin/users/delete", adminDeleteUserHandler)
	mux.HandleFunc("/admin/events", adminEventsHandler)
	mux.HandleFunc("/admin/events/approve", adminApproveEventHandler)
	mux.HandleFunc("/admin/events/reject", adminRejectEventHandler)
	mux.HandleFunc("/admin/events/delete", adminDeleteEventHandler)
	mux.HandleFunc("/admin/events/feature", adminFeatureEventHandler)
	mux.HandleFunc("/admin/bookings", adminBookingsHandler)
	mux.HandleFunc("/admin/reports", adminReportsHandler)

	log.Println("🚀 Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ===================== HELPERS =====================

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateBookingCode() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "BK-" + strings.ToUpper(hex.EncodeToString(b))
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	sess, ok := sessions[cookie.Value]
	if !ok {
		return nil
	}
	return sess
}

func requireAuth(w http.ResponseWriter, r *http.Request) *Session {
	sess := getSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	return sess
}

func requireRole(w http.ResponseWriter, r *http.Request, roles ...string) *Session {
	sess := requireAuth(w, r)
	if sess == nil {
		return nil
	}
	for _, role := range roles {
		if sess.Role == role {
			return sess
		}
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
	return nil
}

func renderTemplate(w http.ResponseWriter, name string, data PageData) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("Template error (%s): %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func hashPassword(password string) string {
	return password
}

func checkPassword(stored, input string) bool {
	return stored == input
}

func createNotification(userID int, title, message, notifType string) {
	db.Exec("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
		userID, title, message, notifType)
}

func getUnreadCount(userID int) int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", userID).Scan(&count)
	return count
}

func handleUpload(r *http.Request, fieldName string) string {
	file, header, err := r.FormFile(fieldName)
	if err != nil {
		return ""
	}
	defer file.Close()

	ext := filepath.Ext(header.Filename)
	allowed := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true}
	if !allowed[strings.ToLower(ext)] {
		return ""
	}

	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	path := filepath.Join("static", "uploads", filename)
	dst, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer dst.Close()

	buf := make([]byte, 1024*1024*10)
	n, _ := file.Read(buf)
	dst.Write(buf[:n])
	return "/static/uploads/" + filename
}

// ===================== AUTH HANDLERS =====================

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := getSession(r)
	if sess != nil {
		switch sess.Role {
		case "admin":
			http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			return
		case "organizer":
			http.Redirect(w, r, "/organizer/dashboard", http.StatusSeeOther)
			return
		default:
			http.Redirect(w, r, "/user/dashboard", http.StatusSeeOther)
			return
		}
	}

	rows, _ := db.Query(`SELECT e.id, e.title, e.description, e.category, e.venue, e.location, 
		DATE_FORMAT(e.event_date,'%Y-%m-%d'), e.capacity, e.price, e.image, u.name, e.is_featured,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed') as booked
		FROM events e JOIN users u ON e.organizer_id=u.id 
		WHERE e.status='approved' AND e.event_date >= CURDATE() AND e.is_featured=1 LIMIT 6`)
	defer func() {
		if rows != nil {
			rows.Close()
		}
	}()

	var events []Event
	if rows != nil {
		for rows.Next() {
			var ev Event
			rows.Scan(&ev.ID, &ev.Title, &ev.Description, &ev.Category, &ev.Venue,
				&ev.Location, &ev.EventDate, &ev.Capacity, &ev.Price, &ev.Image,
				&ev.OrganizerName, &ev.IsFeatured, &ev.BookingCount)
			events = append(events, ev)
		}
	}
	renderTemplate(w, "index.html", PageData{Session: sess, Events: events})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if getSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == "GET" {
		renderTemplate(w, "login.html", PageData{})
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	var u User
	err := db.QueryRow("SELECT id, name, email, password, role, status FROM users WHERE email=?", email).
		Scan(&u.ID, &u.Name, &u.Email, &u.Password, &u.Role, &u.Status)
	if err != nil || !checkPassword(u.Password, password) {
		renderTemplate(w, "login.html", PageData{Error: "Invalid email or password"})
		return
	}
	if u.Status != "active" {
		renderTemplate(w, "login.html", PageData{Error: "Your account is " + u.Status + ". Please contact admin."})
		return
	}

	token := generateToken()
	sessions[token] = &Session{UserID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", MaxAge: 86400 * 7})

	switch u.Role {
	case "admin":
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
	case "organizer":
		http.Redirect(w, r, "/organizer/dashboard", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/user/dashboard", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		renderTemplate(w, "register.html", PageData{})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	phone := r.FormValue("phone")

	if role != "user" && role != "organizer" {
		role = "user"
	}
	if name == "" || email == "" || password == "" {
		renderTemplate(w, "register.html", PageData{Error: "All fields are required"})
		return
	}

	var exists int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE email=?", email).Scan(&exists)
	if exists > 0 {
		renderTemplate(w, "register.html", PageData{Error: "Email already registered"})
		return
	}

	_, err := db.Exec("INSERT INTO users (name, email, password, role, phone) VALUES (?,?,?,?,?)",
		name, email, hashPassword(password), role, phone)
	if err != nil {
		renderTemplate(w, "register.html", PageData{Error: "Registration failed"})
		return
	}
	http.Redirect(w, r, "/login?registered=1", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ===================== PUBLIC EVENT HANDLERS =====================

func eventsHandler(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	category := r.URL.Query().Get("category")
	search := r.URL.Query().Get("search")

	query := `SELECT e.id, e.title, e.description, e.category, e.venue, e.location,
		DATE_FORMAT(e.event_date,'%Y-%m-%d'), e.capacity, e.price, e.image, u.name, e.is_featured,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed') as booked
		FROM events e JOIN users u ON e.organizer_id=u.id 
		WHERE e.status='approved' AND e.event_date >= CURDATE()`
	args := []interface{}{}
	if category != "" {
		query += " AND e.category=?"
		args = append(args, category)
	}
	if search != "" {
		query += " AND (e.title LIKE ? OR e.description LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	query += " ORDER BY e.event_date ASC"

	rows, _ := db.Query(query, args...)
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			rows.Scan(&ev.ID, &ev.Title, &ev.Description, &ev.Category, &ev.Venue,
				&ev.Location, &ev.EventDate, &ev.Capacity, &ev.Price, &ev.Image,
				&ev.OrganizerName, &ev.IsFeatured, &ev.BookingCount)
			events = append(events, ev)
		}
	}
	renderTemplate(w, "events.html", PageData{Session: sess, Events: events, Categories: categories})
}

func eventViewHandler(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	id := r.URL.Query().Get("id")

	var ev Event
	err := db.QueryRow(`SELECT e.id, e.title, e.description, e.category, e.venue, e.location,
		DATE_FORMAT(e.event_date,'%Y-%m-%d'), e.event_time, e.capacity, e.price, e.image,
		e.organizer_id, u.name, e.status, e.is_featured,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e JOIN users u ON e.organizer_id=u.id WHERE e.id=?`, id).
		Scan(&ev.ID, &ev.Title, &ev.Description, &ev.Category, &ev.Venue, &ev.Location,
			&ev.EventDate, &ev.EventTime, &ev.Capacity, &ev.Price, &ev.Image,
			&ev.OrganizerID, &ev.OrganizerName, &ev.Status, &ev.IsFeatured, &ev.BookingCount)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if sess != nil {
		var count int
		db.QueryRow("SELECT COUNT(*) FROM bookings WHERE event_id=? AND user_id=? AND status='confirmed'",
			ev.ID, sess.UserID).Scan(&count)
		ev.UserBooked = count > 0
	}

	// Get reviews
	rows, _ := db.Query(`SELECT r.id, r.rating, r.comment, u.name, r.created_at 
		FROM reviews r JOIN users u ON r.user_id=u.id WHERE r.event_id=? ORDER BY r.created_at DESC`, id)
	var reviews []Review
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var rv Review
			rows.Scan(&rv.ID, &rv.Rating, &rv.Comment, &rv.UserName, &rv.CreatedAt)
			reviews = append(reviews, rv)
		}
	}

	renderTemplate(w, "event_view.html", PageData{Session: sess, Event: &ev, Reviews: reviews})
}

// ===================== USER HANDLERS =====================

func userDashboardHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}

	rows, _ := db.Query(`SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'), 
		e.venue, b.status, b.booking_code, b.tickets, b.total_price, b.created_at
		FROM bookings b JOIN events e ON b.event_id=e.id 
		WHERE b.user_id=? ORDER BY b.created_at DESC LIMIT 5`, sess.UserID)
	var bookings []Booking
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b Booking
			rows.Scan(&b.EventID, &b.EventTitle, &b.EventID, &b.EventDate,
				&b.EventTitle, &b.Status, &b.BookingCode, &b.Tickets, &b.TotalPrice, &b.CreatedAt)
			bookings = append(bookings, b)
		}
	}

	// Upcoming events
	rows2, _ := db.Query(`SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		e.venue, e.price, e.image, u.name,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e JOIN users u ON e.organizer_id=u.id
		WHERE e.status='approved' AND e.event_date >= CURDATE() LIMIT 6`)
	var events []Event
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var ev Event
			rows2.Scan(&ev.ID, &ev.Title, &ev.Category, &ev.EventDate, &ev.Venue,
				&ev.Price, &ev.Image, &ev.OrganizerName, &ev.BookingCount)
			events = append(events, ev)
		}
	}

	stats := map[string]int{}

	var totalBookings int
	var activeBookings int
	var unreadNotifications int

	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE user_id=?", sess.UserID).Scan(&totalBookings)
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE user_id=? AND status='confirmed'", sess.UserID).Scan(&activeBookings)
	db.QueryRow("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", sess.UserID).Scan(&unreadNotifications)

	stats["total_bookings"] = totalBookings
	stats["active"] = activeBookings
	stats["unread"] = unreadNotifications

	renderTemplate(w, "user_dashboard.html", PageData{Session: sess, Bookings: bookings, Events: events, Stats: stats})
}

func bookEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "user", "admin")
	if sess == nil {
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}

	eventID, _ := strconv.Atoi(r.FormValue("event_id"))
	tickets, _ := strconv.Atoi(r.FormValue("tickets"))
	if tickets < 1 {
		tickets = 1
	}
	notes := r.FormValue("notes")

	var ev Event
	err := db.QueryRow("SELECT id, title, capacity, price, status FROM events WHERE id=?", eventID).
		Scan(&ev.ID, &ev.Title, &ev.Capacity, &ev.Price, &ev.Status)
	if err != nil || ev.Status != "approved" {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}

	var booked int
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE event_id=? AND status='confirmed'", eventID).Scan(&booked)
	if ev.Capacity > 0 && booked+tickets > ev.Capacity {
		http.Redirect(w, r, fmt.Sprintf("/events/view?id=%d&error=no_slots", eventID), http.StatusSeeOther)
		return
	}

	var already int
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE event_id=? AND user_id=?", eventID, sess.UserID).Scan(&already)
	if already > 0 {
		http.Redirect(w, r, fmt.Sprintf("/events/view?id=%d&error=already_booked", eventID), http.StatusSeeOther)
		return
	}

	code := generateBookingCode()
	total := ev.Price * float64(tickets)
	_, err = db.Exec("INSERT INTO bookings (event_id, user_id, tickets, total_price, status, booking_code, notes) VALUES (?,?,?,?,?,?,?)",
		eventID, sess.UserID, tickets, total, "confirmed", code, notes)
	if err != nil {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}

	createNotification(sess.UserID, "Booking Confirmed!",
		fmt.Sprintf("You've booked '%s'. Code: %s", ev.Title, code), "success")

	// Notify organizer
	var orgID int
	db.QueryRow("SELECT organizer_id FROM events WHERE id=?", eventID).Scan(&orgID)
	createNotification(orgID, "New Booking!",
		fmt.Sprintf("New booking for '%s' by %s", ev.Title, sess.Name), "info")

	http.Redirect(w, r, "/user/bookings?success=booked", http.StatusSeeOther)
}

func userBookingsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}

	rows, _ := db.Query(`SELECT b.id, b.event_id, e.title, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		e.venue, b.tickets, b.total_price, b.status, b.booking_code, b.created_at
		FROM bookings b JOIN events e ON b.event_id=e.id
		WHERE b.user_id=? ORDER BY b.created_at DESC`, sess.UserID)
	var bookings []Booking
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b Booking
			rows.Scan(&b.ID, &b.EventID, &b.EventTitle, &b.EventDate, &b.EventTitle,
				&b.Tickets, &b.TotalPrice, &b.Status, &b.BookingCode, &b.CreatedAt)
			bookings = append(bookings, b)
		}
	}
	msg := r.URL.Query().Get("success")
	renderTemplate(w, "user_bookings.html", PageData{Session: sess, Bookings: bookings, Message: msg})
}

func cancelBookingHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("UPDATE bookings SET status='cancelled' WHERE id=? AND user_id=?", id, sess.UserID)
	createNotification(sess.UserID, "Booking Cancelled", "Your booking has been cancelled.", "warning")
	http.Redirect(w, r, "/user/bookings", http.StatusSeeOther)
}

func userProfileHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}

	if r.Method == "GET" {
		var u User
		db.QueryRow("SELECT id, name, email, phone, avatar, role FROM users WHERE id=?", sess.UserID).
			Scan(&u.ID, &u.Name, &u.Email, &u.Phone, &u.Avatar, &u.Role)
		renderTemplate(w, "user_profile.html", PageData{Session: sess, User: &u})
		return
	}

	r.ParseMultipartForm(10 << 20)
	name := r.FormValue("name")
	phone := r.FormValue("phone")
	password := r.FormValue("password")

	avatar := handleUpload(r, "avatar")
	if avatar != "" {
		db.Exec("UPDATE users SET avatar=? WHERE id=?", avatar, sess.UserID)
	}
	db.Exec("UPDATE users SET name=?, phone=? WHERE id=?", name, phone, sess.UserID)
	if password != "" {
		db.Exec("UPDATE users SET password=? WHERE id=?", hashPassword(password), sess.UserID)
	}
	sessions[func() string {
		c, _ := r.Cookie("session")
		if c != nil {
			return c.Value
		}
		return ""
	}()].Name = name

	http.Redirect(w, r, "/user/profile?updated=1", http.StatusSeeOther)
}

func submitReviewHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "user")
	if sess == nil {
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}

	eventID := r.FormValue("event_id")
	rating, _ := strconv.Atoi(r.FormValue("rating"))
	comment := r.FormValue("comment")

	var booked int
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE event_id=? AND user_id=? AND status='confirmed'",
		eventID, sess.UserID).Scan(&booked)
	if booked == 0 {
		http.Redirect(w, r, fmt.Sprintf("/events/view?id=%s&error=not_booked", eventID), http.StatusSeeOther)
		return
	}

	db.Exec(`INSERT INTO reviews (event_id, user_id, rating, comment) VALUES (?,?,?,?)
		ON DUPLICATE KEY UPDATE rating=VALUES(rating), comment=VALUES(comment)`,
		eventID, sess.UserID, rating, comment)
	http.Redirect(w, r, fmt.Sprintf("/events/view?id=%s&success=reviewed", eventID), http.StatusSeeOther)
}

func userNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}
	db.Exec("UPDATE notifications SET is_read=1 WHERE user_id=?", sess.UserID)
	rows, _ := db.Query("SELECT id, title, message, type, is_read, created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50", sess.UserID)
	var notifs []Notification
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var n Notification
			rows.Scan(&n.ID, &n.Title, &n.Message, &n.Type, &n.IsRead, &n.CreatedAt)
			notifs = append(notifs, n)
		}
	}
	renderTemplate(w, "notifications.html", PageData{Session: sess, Notifications: notifs})
}

func markNotificationHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireAuth(w, r)
	if sess == nil {
		return
	}
	db.Exec("UPDATE notifications SET is_read=1 WHERE user_id=?", sess.UserID)
	http.Redirect(w, r, "/user/notifications", http.StatusSeeOther)
}

// ===================== ORGANIZER HANDLERS =====================

func organizerDashboardHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}

	stats := map[string]int{}

	var totalBookings int
	var activeBookings int
	var unreadNotifications int

	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE user_id=?", sess.UserID).Scan(&totalBookings)
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE user_id=? AND status='confirmed'", sess.UserID).Scan(&activeBookings)
	db.QueryRow("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", sess.UserID).Scan(&unreadNotifications)

	stats["total_bookings"] = totalBookings
	stats["active"] = activeBookings
	stats["unread"] = unreadNotifications
	var total int
	db.QueryRow("SELECT COUNT(*) FROM events WHERE organizer_id=?", sess.UserID).Scan(&total)
	stats["total"] = total

	rows, _ := db.Query(`SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'), 
		e.status, e.capacity,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e WHERE e.organizer_id=? ORDER BY e.created_at DESC LIMIT 10`, sess.UserID)
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			rows.Scan(&ev.ID, &ev.Title, &ev.Category, &ev.EventDate, &ev.Status, &ev.Capacity, &ev.BookingCount)
			events = append(events, ev)
		}
	}
	renderTemplate(w, "organizer_dashboard.html", PageData{Session: sess, Stats: stats, Events: events})
}

func organizerEventsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}

	rows, _ := db.Query(`SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		e.venue, e.capacity, e.price, e.status, e.rejection_reason,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e WHERE e.organizer_id=? ORDER BY e.created_at DESC`, sess.UserID)
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			var reason sql.NullString
			rows.Scan(&ev.ID, &ev.Title, &ev.Category, &ev.EventDate, &ev.Venue,
				&ev.Capacity, &ev.Price, &ev.Status, &reason, &ev.BookingCount)
			if reason.Valid {
				ev.RejectionReason = reason.String
			}
			events = append(events, ev)
		}
	}
	renderTemplate(w, "organizer_events.html", PageData{Session: sess, Events: events, Categories: categories})
}

func organizerAddEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}

	if r.Method == "GET" {
		renderTemplate(w, "organizer_event_form.html", PageData{Session: sess, Categories: categories})
		return
	}

	r.ParseMultipartForm(10 << 20)
	title := r.FormValue("title")
	desc := r.FormValue("description")
	category := r.FormValue("category")
	venue := r.FormValue("venue")
	location := r.FormValue("location")
	eventDate := r.FormValue("event_date")
	eventTime := r.FormValue("event_time")
	endDate := r.FormValue("end_date")
	endTime := r.FormValue("end_time")
	capacity, _ := strconv.Atoi(r.FormValue("capacity"))
	price, _ := strconv.ParseFloat(r.FormValue("price"), 64)

	image := handleUpload(r, "image")

	_, err := db.Exec(`INSERT INTO events (title, description, category, venue, location, event_date, event_time, end_date, end_time, capacity, price, image, organizer_id, status) 
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`,
		title, desc, category, venue, location, eventDate, eventTime, endDate, endTime, capacity, price, image, sess.UserID)
	if err != nil {
		renderTemplate(w, "organizer_event_form.html", PageData{Session: sess, Error: "Failed to create event", Categories: categories})
		return
	}

	// Notify admins
	adminRows, _ := db.Query("SELECT id FROM users WHERE role='admin'")
	if adminRows != nil {
		defer adminRows.Close()
		for adminRows.Next() {
			var adminID int
			adminRows.Scan(&adminID)
			createNotification(adminID, "New Event Submitted",
				fmt.Sprintf("'%s' submitted by %s awaits approval", title, sess.Name), "info")
		}
	}

	http.Redirect(w, r, "/organizer/events?success=created", http.StatusSeeOther)
}

func organizerEditEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")

	if r.Method == "GET" {
		var ev Event
		var reason sql.NullString
		err := db.QueryRow(`SELECT id, title, description, category, venue, location,
			DATE_FORMAT(event_date,'%Y-%m-%d'), event_time, capacity, price, image, rejection_reason
			FROM events WHERE id=? AND organizer_id=?`, id, sess.UserID).
			Scan(&ev.ID, &ev.Title, &ev.Description, &ev.Category, &ev.Venue, &ev.Location,
				&ev.EventDate, &ev.EventTime, &ev.Capacity, &ev.Price, &ev.Image, &reason)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if reason.Valid {
			ev.RejectionReason = reason.String
		}
		renderTemplate(w, "organizer_event_form.html", PageData{Session: sess, Event: &ev, Categories: categories})
		return
	}

	r.ParseMultipartForm(10 << 20)
	image := handleUpload(r, "image")
	capacity, _ := strconv.Atoi(r.FormValue("capacity"))
	price, _ := strconv.ParseFloat(r.FormValue("price"), 64)

	if image != "" {
		db.Exec(`UPDATE events SET title=?, description=?, category=?, venue=?, location=?,
			event_date=?, event_time=?, capacity=?, price=?, image=?, status='pending'
			WHERE id=? AND organizer_id=?`,
			r.FormValue("title"), r.FormValue("description"), r.FormValue("category"),
			r.FormValue("venue"), r.FormValue("location"), r.FormValue("event_date"),
			r.FormValue("event_time"), capacity, price, image, id, sess.UserID)
	} else {
		db.Exec(`UPDATE events SET title=?, description=?, category=?, venue=?, location=?,
			event_date=?, event_time=?, capacity=?, price=?, status='pending'
			WHERE id=? AND organizer_id=?`,
			r.FormValue("title"), r.FormValue("description"), r.FormValue("category"),
			r.FormValue("venue"), r.FormValue("location"), r.FormValue("event_date"),
			r.FormValue("event_time"), capacity, price, id, sess.UserID)
	}
	http.Redirect(w, r, "/organizer/events?success=updated", http.StatusSeeOther)
}

func organizerDeleteEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM events WHERE id=? AND organizer_id=?", id, sess.UserID)
	http.Redirect(w, r, "/organizer/events", http.StatusSeeOther)
}

func organizerBookingsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "organizer", "admin")
	if sess == nil {
		return
	}

	rows, _ := db.Query(`SELECT b.id, b.event_id, e.title, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		u.name, u.email, b.tickets, b.total_price, b.status, b.booking_code, b.created_at
		FROM bookings b JOIN events e ON b.event_id=e.id JOIN users u ON b.user_id=u.id
		WHERE e.organizer_id=? ORDER BY b.created_at DESC`, sess.UserID)
	var bookings []Booking
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b Booking
			rows.Scan(&b.ID, &b.EventID, &b.EventTitle, &b.EventDate, &b.UserName,
				&b.UserEmail, &b.Tickets, &b.TotalPrice, &b.Status, &b.BookingCode, &b.CreatedAt)
			bookings = append(bookings, b)
		}
	}
	renderTemplate(w, "organizer_bookings.html", PageData{Session: sess, Bookings: bookings})
}

// ===================== ADMIN HANDLERS =====================

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}

	stats := map[string]int{}
	var totalUsers int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	stats["total_users"] = totalUsers
	var totalEvents int
	db.QueryRow("SELECT COUNT(*) FROM events").Scan(&totalEvents)
	stats["total_events"] = totalEvents
	var pendingEvents int
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='pending'").Scan(&pendingEvents)
	stats["pending_events"] = pendingEvents
	var totalBookings int
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE status='confirmed'").Scan(&totalBookings)
	stats["total_bookings"] = totalBookings
	var organizersCount int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role='organizer'").Scan(&organizersCount)
	stats["organizers"] = organizersCount
	var approvedEvents int
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='approved'").Scan(&approvedEvents)
	stats["approved_events"] = approvedEvents

	rows, _ := db.Query(`SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		e.status, u.name,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e JOIN users u ON e.organizer_id=u.id
		WHERE e.status='pending' ORDER BY e.created_at ASC LIMIT 5`)
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			rows.Scan(&ev.ID, &ev.Title, &ev.Category, &ev.EventDate, &ev.Status, &ev.OrganizerName, &ev.BookingCount)
			events = append(events, ev)
		}
	}

	rows2, _ := db.Query("SELECT id, name, email, role, status, created_at FROM users ORDER BY created_at DESC LIMIT 5")
	var users []User
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var u User
			rows2.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Status, &u.CreatedAt)
			users = append(users, u)
		}
	}

	renderTemplate(w, "admin_dashboard.html", PageData{Session: sess, Stats: stats, Events: events, Users: users})
}

func adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}

	search := r.URL.Query().Get("search")
	role := r.URL.Query().Get("role")
	query := "SELECT id, name, email, role, phone, status, created_at FROM users WHERE 1=1"
	args := []interface{}{}
	if search != "" {
		query += " AND (name LIKE ? OR email LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	if role != "" {
		query += " AND role=?"
		args = append(args, role)
	}
	query += " ORDER BY created_at DESC"

	rows, _ := db.Query(query, args...)
	var users []User
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Phone, &u.Status, &u.CreatedAt)
			users = append(users, u)
		}
	}
	renderTemplate(w, "admin_users.html", PageData{Session: sess, Users: users})
}

func adminAddUserHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	if r.Method == "GET" {
		renderTemplate(w, "admin_user_form.html", PageData{Session: sess})
		return
	}
	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	phone := r.FormValue("phone")

	_, err := db.Exec("INSERT INTO users (name, email, password, role, phone) VALUES (?,?,?,?,?)",
		name, email, hashPassword(password), role, phone)
	if err != nil {
		renderTemplate(w, "admin_user_form.html", PageData{Session: sess, Error: "Email already exists"})
		return
	}
	http.Redirect(w, r, "/admin/users?success=created", http.StatusSeeOther)
}

func adminEditUserHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")

	if r.Method == "GET" {
		var u User
		db.QueryRow("SELECT id, name, email, role, phone, status FROM users WHERE id=?", id).
			Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Phone, &u.Status)
		renderTemplate(w, "admin_user_form.html", PageData{Session: sess, User: &u})
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	role := r.FormValue("role")
	phone := r.FormValue("phone")
	status := r.FormValue("status")
	password := r.FormValue("password")

	db.Exec("UPDATE users SET name=?, email=?, role=?, phone=?, status=? WHERE id=?",
		name, email, role, phone, status, id)
	if password != "" {
		db.Exec("UPDATE users SET password=? WHERE id=?", hashPassword(password), id)
	}
	http.Redirect(w, r, "/admin/users?success=updated", http.StatusSeeOther)
}

func adminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	if strconv.Itoa(sess.UserID) != id {
		db.Exec("DELETE FROM users WHERE id=?", id)
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func adminEventsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}

	status := r.URL.Query().Get("status")
	query := `SELECT e.id, e.title, e.category, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		e.venue, e.capacity, e.price, e.status, e.is_featured, u.name,
		(SELECT COUNT(*) FROM bookings WHERE event_id=e.id AND status='confirmed')
		FROM events e JOIN users u ON e.organizer_id=u.id WHERE 1=1`
	args := []interface{}{}
	if status != "" {
		query += " AND e.status=?"
		args = append(args, status)
	}
	query += " ORDER BY e.created_at DESC"

	rows, _ := db.Query(query, args...)
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			rows.Scan(&ev.ID, &ev.Title, &ev.Category, &ev.EventDate, &ev.Venue,
				&ev.Capacity, &ev.Price, &ev.Status, &ev.IsFeatured, &ev.OrganizerName, &ev.BookingCount)
			events = append(events, ev)
		}
	}
	renderTemplate(w, "admin_events.html", PageData{Session: sess, Events: events})
}

func adminApproveEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("UPDATE events SET status='approved', rejection_reason=NULL WHERE id=?", id)

	var ev Event
	var orgID int
	db.QueryRow("SELECT title, organizer_id FROM events WHERE id=?", id).Scan(&ev.Title, &orgID)
	createNotification(orgID, "Event Approved! 🎉",
		fmt.Sprintf("Your event '%s' has been approved and is now live!", ev.Title), "success")
	http.Redirect(w, r, "/admin/events?status=pending", http.StatusSeeOther)
}

func adminRejectEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/events", http.StatusSeeOther)
		return
	}

	id := r.FormValue("event_id")
	reason := r.FormValue("reason")
	db.Exec("UPDATE events SET status='rejected', rejection_reason=? WHERE id=?", reason, id)

	var ev Event
	var orgID int
	db.QueryRow("SELECT title, organizer_id FROM events WHERE id=?", id).Scan(&ev.Title, &orgID)
	createNotification(orgID, "Event Rejected",
		fmt.Sprintf("Your event '%s' was rejected. Reason: %s", ev.Title, reason), "error")
	http.Redirect(w, r, "/admin/events?status=pending", http.StatusSeeOther)
}

func adminDeleteEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM events WHERE id=?", id)
	http.Redirect(w, r, "/admin/events", http.StatusSeeOther)
}

func adminFeatureEventHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("UPDATE events SET is_featured = NOT is_featured WHERE id=?", id)
	http.Redirect(w, r, "/admin/events", http.StatusSeeOther)
}

func adminBookingsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}

	rows, _ := db.Query(`SELECT b.id, b.event_id, e.title, DATE_FORMAT(e.event_date,'%Y-%m-%d'),
		u.name, u.email, b.tickets, b.total_price, b.status, b.booking_code, b.created_at
		FROM bookings b JOIN events e ON b.event_id=e.id JOIN users u ON b.user_id=u.id
		ORDER BY b.created_at DESC`)
	var bookings []Booking
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b Booking
			rows.Scan(&b.ID, &b.EventID, &b.EventTitle, &b.EventDate, &b.UserName,
				&b.UserEmail, &b.Tickets, &b.TotalPrice, &b.Status, &b.BookingCode, &b.CreatedAt)
			bookings = append(bookings, b)
		}
	}
	renderTemplate(w, "admin_bookings.html", PageData{Session: sess, Bookings: bookings})
}

func adminReportsHandler(w http.ResponseWriter, r *http.Request) {
	sess := requireRole(w, r, "admin")
	if sess == nil {
		return
	}

	stats := map[string]int{}
	var users, organizers, approved, pending, rejected, confirmed, cancelled, revenue int

	db.QueryRow("SELECT COUNT(*) FROM users WHERE role='user'").Scan(&users)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role='organizer'").Scan(&organizers)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='approved'").Scan(&approved)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='pending'").Scan(&pending)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='rejected'").Scan(&rejected)
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE status='confirmed'").Scan(&confirmed)
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE status='cancelled'").Scan(&cancelled)
	db.QueryRow("SELECT COALESCE(SUM(total_price),0) FROM bookings WHERE status='confirmed'").Scan(&revenue)

	stats["users"] = users
	stats["organizers"] = organizers
	stats["approved"] = approved
	stats["pending"] = pending
	stats["rejected"] = rejected
	stats["confirmed"] = confirmed
	stats["cancelled"] = cancelled
	stats["revenue"] = revenue

	renderTemplate(w, "admin_reports.html", PageData{Session: sess, Stats: stats})
}
