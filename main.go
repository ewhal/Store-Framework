package main

import (
	"database/sql"
	//	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/codegangsta/negroni"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
)

type Context struct {
	Title string
}
type Products struct {
	Products    string
	Description []byte
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

// Root domain handler
func rootHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "Laser"}
	renderTemplate(w, "index.html", context)
}

//Authentication failure handler
func authfailHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "Error"}
	renderTemplate(w, "index.html", context)
}

func faqHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "FAQ"}
	renderTemplate(w, "faq.html", context)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Login"}
		renderTemplate(w, "login.html", context)
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

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "user"}
		renderTemplate(w, "user.html", context)
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

	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Register"}
		renderTemplate(w, "register.html", context)
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
	context := Context{Title: "Store"}
	renderTemplate(w, "store.html", context)
}

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Checkout"}
		renderTemplate(w, "checkout.html", context)
	case "POST":
		r.ParseForm()
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
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
		context := Context{Title: "Admin"}
		renderTemplate(w, "admin.html", context)
	}
	if err != nil && admin == 0 {
		log.Print(err)
		http.Redirect(w, r, "/login", 301)
	}

}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Orders"}
		renderTemplate(w, "orders.html", context)
	}

}
func addProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: ""}
		renderTemplate(w, "add.html", context)
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		description := r.FormValue("description")
		file := r.FormValue("files[]")

		/*
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
			io.Copy(f, file) */
		price := r.FormValue("price")

		_, err := db.Exec("INSERT INTO products (product_name, description, image, price) VALUES (?, ?, ?, ?)", productname, description, file, price)

		if err != nil {
			log.Print(err)
		}

	}

}
func removeProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Remove Products"}
		renderTemplate(w, "remove.html", context)
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		_, err := db.Exec("DELETE from products where productname = ?", productname)
		fmt.Println(productname)

		if err != nil {
			log.Print(err)
		}

	}

}
func modifyProductsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Modify Products"}
		renderTemplate(w, "modify.html", context)
	case "POST":
		r.ParseForm()
		productname := r.FormValue("productname")
		description := r.FormValue("description")
		file := r.FormValue("files[]")

		/*
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
			io.Copy(f, file) */
		price := r.FormValue("price")

		_, err := db.Exec("INSERT INTO products (product_name, description, image, price) VALUES (?, ?, ?, ?)", productname, description, file, price)

		if err != nil {
			log.Print(err)
		}

	}

}
func logoutHandler(w http.ResponseWriter, r *http.Request) {

	session := sessions.GetSession(r)
	session.Delete("useremail")
	http.Redirect(w, r, "/", 302)
}

func contactHandler(w http.ResponseWriter, r *http.Request) {
	context := Context{Title: "contact"}
	renderTemplate(w, "contact.html", context)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		context := Context{Title: "Upload"}
		renderTemplate(w, "upload.html", context)
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
	}

}

func displayProducts(w http.ResponseWriter, tmpl string, products Products) {
	t, err := template.ParseFiles("templates/layout.html", "templates/"+tmpl)
	if err != nil {
		log.Fatal(err)
	}
	t.ExecuteTemplate(w, "layout", products)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, context Context) {
	t, err := template.ParseFiles("templates/layout.html", "templates/"+tmpl)
	if err != nil {
		log.Fatal(err)
	}
	t.ExecuteTemplate(w, "layout", context)
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

func main() {

	defer db.Close()

	mux := http.NewServeMux()
	n := negroni.Classic()

	store := cookiestore.New([]byte("evOuIxidcFDywC4MfGyf5xamfrKGLJrmQLUfRJtOo9i8vaQln9oLwU9qGnwNQAS"))
	n.Use(sessions.Sessions("global_session_store", store))

	mux.Handle("/build/", http.StripPrefix("/build/", http.FileServer(http.Dir("build"))))
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/faq", faqHandler)
	mux.HandleFunc("/contact", contactHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/store", storeHandler)
	mux.HandleFunc("/admin", adminHandler)
	mux.HandleFunc("/admin/users", userHandler)
	mux.HandleFunc("/admin/orders", ordersHandler)
	mux.HandleFunc("/admin/add", addProductsHandler)
	mux.HandleFunc("/admin/remove", removeProductsHandler)
	mux.HandleFunc("/admin/modify", modifyProductsHandler)
	mux.HandleFunc("/admin/upload", uploadHandler)
	mux.HandleFunc("/authfail", authfailHandler)
	mux.HandleFunc("/logout", logoutHandler)

	n.UseHandler(mux)
	n.Run(":8080")

}
