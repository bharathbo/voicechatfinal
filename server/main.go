package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"

    "github.com/golang-jwt/jwt/v4"
    "github.com/gorilla/websocket"
    "github.com/pion/webrtc/v3"
    "golang.org/x/crypto/bcrypt"
    _ "github.com/lib/pq"
)

// User struct for JSON request and response
type User struct {
    ID       int    `json:"id"`
    Email    string `json:"email"`
    Name     string `json:"name"`
    Password string `json:"password,omitempty"`
}

// JWT claims struct
type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

// JoinRoomRequest struct for JSON request
type JoinRoomRequest struct {
    Token     string `json:"token"`
    MeetingID string `json:"meetingId"`
}

var db *sql.DB // Global variable for database connection

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

// SignalingServer struct to handle WebRTC signaling
type SignalingServer struct {
    peerConnections map[string]*webrtc.PeerConnection
    connections     map[*websocket.Conn]bool
    mu              sync.Mutex
}

// NewSignalingServer creates a new SignalingServer instance
func NewSignalingServer() *SignalingServer {
    return &SignalingServer{
        peerConnections: make(map[string]*webrtc.PeerConnection),
        connections:     make(map[*websocket.Conn]bool),
    }
}

// HandleWebSocket handles WebSocket connections for WebRTC signaling
func (s *SignalingServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        http.Error(w, "Failed to upgrade to WebSocket", http.StatusInternalServerError)
        return
    }
    defer conn.Close()

    s.mu.Lock()
    s.connections[conn] = true
    s.mu.Unlock()

    for {
        var msg map[string]interface{}
        err := conn.ReadJSON(&msg)
        if err != nil {
            log.Println("Error reading JSON:", err)
            break
        }

        // Handle the signaling messages here
        if msg["type"] == "offer" {
            // Handle offer
        } else if msg["type"] == "answer" {
            // Handle answer
        } else if msg["type"] == "ice-candidate" {
            // Handle ICE candidate
        }
    }

    s.mu.Lock()
    delete(s.connections, conn)
    s.mu.Unlock()
}

func main() {
    // Database connection string
    const (
        Host     = "pg-2eec7806-manasa-dd8a.a.aivencloud.com"
        Port     = 22683
        User     = "avnadmin"
        Password = "AVNS_Vz0nNkXvfi5IWu8jjhd"
        Dbname   = "voice-chat"
        SSLMode  = "require"
    )

    // Construct connection string
    psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        Host, Port, User, Password, Dbname, SSLMode)

    // Connect to the PostgreSQL database
    var err error
    db, err = sql.Open("postgres", psqlInfo)
    if err != nil {
        log.Fatalf("Error connecting to the database: %v", err)
    }
    defer db.Close()

    // Test the database connection
    err = db.Ping()
    if err != nil {
        log.Fatalf("Error pinging database: %v", err)
    }
    fmt.Println("Successfully connected to the database!")

    // Initialize the signaling server
    signalingServer := NewSignalingServer()

    // Define HTTP request handlers with CORS enabled
    http.HandleFunc("/users", enableCors(usersHandler))
    http.HandleFunc("/users/new", enableCors(createUserHandler))
    http.HandleFunc("/login", enableCors(loginHandler))
    http.HandleFunc("/joinroom", enableCors(joinRoomHandler))
    http.HandleFunc("/ws", wsHandler(signalingServer)) // Use custom WebSocket handler

    // Start the HTTP server
    fmt.Println("Server is running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// WebSocket handler function
func wsHandler(signalingServer *SignalingServer) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Set CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Check for preflight request
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        // Handle WebSocket connection
        signalingServer.HandleWebSocket(w, r)
    }
}

// Middleware function to enable CORS (Cross-Origin Resource Sharing)
func enableCors(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Allow all origins
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Handle preflight requests (OPTIONS)
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        // Call the actual handler function
        handler(w, r)
    }
}

// Handler for GET /users to retrieve all users
func usersHandler(w http.ResponseWriter, r *http.Request) {
    // Query the database to fetch all records from the users table
    rows, err := db.Query("SELECT id, email, name FROM users")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    // Slice to hold users
    var users []User

    // Process each row of the result set
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Email, &u.Name); err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            return
        }
        users = append(users, u)
    }

    // Check for any errors encountered during iteration
    if err := rows.Err(); err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    // Encode users slice to JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

// Handler for POST /users/new to create a new user
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request body into User struct
    var newUser User
    err := json.NewDecoder(r.Body).Decode(&newUser)
    if err != nil {
        http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
        return
    }

    // Encrypt the password using bcrypt
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to encrypt password", http.StatusInternalServerError)
        return
    }
    newUser.Password = string(hashedPassword)

    // Insert new user record into the database
    _, err = db.Exec("INSERT INTO users (email, name, password) VALUES ($1, $2, $3)",
        newUser.Email, newUser.Name, newUser.Password)

    if err != nil {
        http.Error(w, "Failed to insert user", http.StatusInternalServerError)
        return
    }

    // Generate and send JWT token containing user's email
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{Email: newUser.Email})
    signedToken, err := token.SignedString([]byte("secret"))
    if err != nil {
        http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
        return
    }

    // Respond with success message and JWT token
    response := map[string]string{
        "message": "User created successfully",
        "token":   signedToken,
    }
    w.WriteHeader(http.StatusCreated)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Handler for POST /login to authenticate user
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request body into User struct
    var loginUser User
    err := json.NewDecoder(r.Body).Decode(&loginUser)
    if err != nil {
        http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
        return
    }

    // Retrieve hashed password from the database based on provided email
    var hashedPassword string
    err = db.QueryRow("SELECT password FROM users WHERE email = $1", loginUser.Email).Scan(&hashedPassword)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Compare provided password with hashed password from the database
    if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginUser.Password)); err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate JWT token containing user's email
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{Email: loginUser.Email})
    signedToken, err := token.SignedString([]byte("secret"))
    if err != nil {
        http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
        return
    }

    // Respond with success message and JWT token
    response := map[string]string{
        "message": "Login successful",
        "token":   signedToken,
    }
    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Handler for POST /joinroom to join a meeting room
func joinRoomHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request body into JoinRoomRequest struct
    var joinRequest JoinRoomRequest
    err := json.NewDecoder(r.Body).Decode(&joinRequest)
    if err != nil {
        http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
        return
    }

    // Extract email from token
    tokenString := joinRequest.Token // Token included in JSON payload
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil // Use the same secret key used for token generation
    })
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    email := claims.Email // Extract email from claims

    // Insert email and meeting ID into the database
    _, err = db.Exec("INSERT INTO meetings (email, meeting_id) VALUES ($1, $2)", email, joinRequest.MeetingID)
    if err != nil {
        http.Error(w, "Failed to join meeting room", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    response := map[string]string{
        "message": "Joined meeting room successfully",
    }
    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
