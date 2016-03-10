package main

import (
	"database/sql"
	//	"encoding/json"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/codegangsta/negroni"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
)

type Context struct {
	Title    string
	isAdmin  bool
	loggedIn bool
}
type Products struct {
	Title       string
	Productname string
	Description string
	Image       string
	Price       float32
}

type database struct {
	User     string
	Password string
	DBName   string
}

type tomlConfig struct {
	DB database `toml:"database"`
}

var db *sql.DB = setupDB()

// Setup Database
func setupDB() *sql.DB {

	var config tomlConfig
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Print(err)
	}
	db, err := sql.Open("mysql", config.DB.User+":"+config.DB.Password+"@/"+config.DB.DBName+"?charset=utf8")
	if err != nil {
		panic(err)
	}
	return db

}

func displayProducts(w http.ResponseWriter, tmpl string, p *Products) {
	t, err := template.ParseFiles("templates/" + tmpl + ".html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = t.ExecuteTemplate(w, "store.html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, context Context) {
	t, err := template.ParseFiles("templates/layout.html", "templates/"+tmpl+".html")
	if err != nil {
		log.Fatal(err)
	}
	err = t.ExecuteTemplate(w, "layout", context)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	hashed_password, hash_err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if hash_err != nil {
		log.Print(hash_err)
	}
	_, err := db.Exec("INSERT INTO users (user_name, user_password, user_email) VALUES (?, ?, ?)", username, hashed_password, email)
	if err != nil {
		log.Print(err)
	}

	http.Redirect(w, r, "/login", 302)

}

//Deletes session and redirects to rootHandler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := sessions.GetSession(r)
	session.Delete("useremail")
	http.Redirect(w, r, "/", 302)
}

func adminAuth(w http.ResponseWriter, r *http.Request, title string, page string) {
	session := sessions.GetSession(r)
	sess := session.Get("useremail")

	if sess == nil {
		http.Redirect(w, r, "/login", 301)
	}
	var (
		useremail string
		admin     int
	)

	err := db.QueryRow("SELECT user_email, admin FROM users WHERE user_email = ?", sess).Scan(&useremail, &admin)
	if admin == 1 {
		context := Context{Title: title}
		renderTemplate(w, page, context)
	}
	if err != nil && admin == 0 {
		log.Print(err)
		http.Redirect(w, r, "/login", 301)
	}

}

// Root domain handler
func rootHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "Laser"}
	renderTemplate(w, "index", context)
}

//Authentication failure handler
func authfailHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "Error"}
	renderTemplate(w, "index", context)
}

func faqHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "FAQ"}
	renderTemplate(w, "faq", context)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Login"}
		renderTemplate(w, "login", context)
	case "POST":
		session := sessions.GetSession(r)

		username := r.FormValue("username")
		password := r.FormValue("password")

		var (
			email           string
			hashed_password string
		)

		err := db.QueryRow("SELECT user_email, user_password FROM users WHERE user_name = ?", username).Scan(&email, &hashed_password)
		password_err := bcrypt.CompareHashAndPassword([]byte(hashed_password), []byte(password))
		if err != nil && password_err != nil {
			log.Print(err)
			log.Print(password_err)
			http.Redirect(w, r, "/authfail", 301)
		}

		session.Set("useremail", email)
		http.Redirect(w, r, "/", 302)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Register"}
		renderTemplate(w, "register", context)
	case "POST":
		r.ParseForm()
		password := r.FormValue("password")
		password2 := r.FormValue("password_confirm")
		if password == password2 {
			createUser(w, r)
		} else {
			fmt.Fprintf(w, "Error passwords don't match")

		}
	}

}
func storeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["productname"]

	var (
		description string
		image       string
		price       float32
	)

	err := db.QueryRow("SELECT description, image, price FROM products WHERE product_name = ?", key).Scan(&description, &image, &price)
	if err != nil {
		log.Print(err)
	}

	displayProducts(w, "store", &Products{Title: key, Productname: key, Description: description, Image: image, Price: price})
}

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Checkout"}
		renderTemplate(w, "checkout", context)
	case "POST":
		r.ParseForm()
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	adminAuth(w, r, "Admin", "admin")
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Add admin permissions", "user")
	case "POST":
		r.ParseForm()

		username := r.FormValue("username")
		id := r.FormValue("id")

		fmt.Println(username)
		fmt.Println(id)
		//		query, err := db.Prepare("UPDATE users SET admin = 1 WHERE user_name = ?;")
		//		err = query.Exec(username)

		//		if err != nil {
		//			log.Print(err)
		//		}
		http.Redirect(w, r, "/admin/user", 302)

	}
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Orders", "orders")
	}

}
func addProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Add Products", "add")
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		description := r.FormValue("description")
		file := r.FormValue("files[]")
		price := r.FormValue("price")

		_, err := db.Exec("INSERT INTO products (product_name, description, image, price) VALUES (?, ?, ?, ?)", productname, description, file, price)

		if err != nil {
			log.Print(err)
		}
		http.Redirect(w, r, "/admin/add", 302)

	}

}
func removeProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Remove Products", "remove")
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		_, err := db.Exec("DELETE from products where product_name = ?", productname)
		fmt.Println(productname)

		if err != nil {
			log.Print(err)
		}
		http.Redirect(w, r, "/admin/remove", 302)

	}

}
func modifyProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Modify Products", "modify")
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		description := r.FormValue("description")
		file := r.FormValue("files[]")

		price := r.FormValue("price")

		_, err := db.Exec("INSERT INTO products (product_name, description, image, price) VALUES (?, ?, ?, ?)", productname, description, file, price)

		if err != nil {
			log.Print(err)
		}
		http.Redirect(w, r, "/admin/modify", 302)

	}

}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		adminAuth(w, r, "Upload Product Image", "upload")
	case "POST":
		r.ParseForm()
		file, handler, err := r.FormFile("files[]")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		fmt.Fprintf(w, "%v", handler.Header)
		f, err := os.OpenFile("./build/img/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()
		io.Copy(f, file)
		http.Redirect(w, r, "/admin/modify", 302)
	}

}

func main() {
	ncpu := runtime.NumCPU()
	if ncpu > 4 {
		ncpu = 4
	}
	runtime.GOMAXPROCS(ncpu)
	flag.Parse()

	defer db.Close()

	r := mux.NewRouter()
	n := negroni.Classic()

	store := cookiestore.New([]byte("evOuIxidcFDywC4MfGyf5xamfrKGLJrmQLUfRJtOo9i8vaQln9oLwU9qGnwNQAS"))
	n.Use(sessions.Sessions("global_session_store", store))

	r.PathPrefix("/build").Handler(http.StripPrefix("/build", http.FileServer(http.Dir("build/"))))
	r.HandleFunc("/", rootHandler)
	r.HandleFunc("/faq", faqHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/register", registerHandler)
	r.HandleFunc("/store/{productname}", storeHandler)
	r.HandleFunc("/checkout", checkoutHandler)
	r.HandleFunc("/admin", adminHandler)
	r.HandleFunc("/admin/users", userHandler)
	r.HandleFunc("/admin/orders", ordersHandler)
	r.HandleFunc("/admin/add", addProductsHandler)
	r.HandleFunc("/admin/remove", removeProductsHandler)
	r.HandleFunc("/admin/modify", modifyProductsHandler)
	r.HandleFunc("/admin/upload", uploadHandler)
	r.HandleFunc("/authfail", authfailHandler)
	r.HandleFunc("/logout", logoutHandler)

	n.UseHandler(r)
	n.Run(":8080")

}
