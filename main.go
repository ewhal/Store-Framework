package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/codegangsta/negroni"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/unrolled/render"
	"golang.org/x/crypto/bcrypt"
)

// dicks
type Context struct {
	IsAdmin  bool
	LoggedIn bool
}
type Products struct {
	Context
	Id          int     `db:"id"`
	Productname string  `db:"product_name"`
	Description string  `db:"description"`
	Image       string  `db:"image"`
	Price       float32 `db:"price"`
}

type database struct {
	User     string
	Password string
	DBName   string
}

type tomlConfig struct {
	DB database `toml:"database"`
}

var db *sqlx.DB = SetupDB()

// Setup Database
func SetupDB() *sqlx.DB {

	var config tomlConfig
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Print(err)
	}
	db, err := sqlx.Open("mysql", config.DB.User+":"+config.DB.Password+"@/"+config.DB.DBName+"?charset=utf8")
	if err != nil {
		panic(err)
	}
	return db

}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	hashed_password, hash_err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if hash_err != nil {
		log.Print(hash_err)
	}
	_, err := db.Exec("insert into users (user_name, user_password, user_email) values (?, ?, ?)", username, hashed_password, email)
	if err != nil {
		log.Print(err)
	}

	http.Redirect(w, r, "/login", 302)

}

func AdminAuth(w http.ResponseWriter, r *http.Request, title string) {

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
		context := &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)}
		ren := render.New(render.Options{Directory: "templates", Layout: "layout", Extensions: []string{".tmpl", ".html"}, Charset: "UTF-8", IsDevelopment: false})
		ren.HTML(w, http.StatusOK, title, context)
	}
	if err != nil && admin == 0 {
		log.Print(err)
		http.Redirect(w, r, "/login", 301)
	}

}
func IsAdmin(r *http.Request) bool {
	session := sessions.GetSession(r)
	sess := session.Get("useremail")

	if sess == nil {
		return false
	}
	var (
		useremail string
		admin     int
	)

	err := db.QueryRow("SELECT user_email, admin FROM users WHERE user_email = ?", sess).Scan(&useremail, &admin)

	if admin == 1 {
		return true
	}
	if err != nil && admin == 0 {
		return false
	}

	return false
}

func LoggedIn(r *http.Request) bool {
	session := sessions.GetSession(r)
	sess := session.Get("useremail")
	// You can make the map key a constant to avoid typos/errors
	if sess == nil {
		return false
	}
	return true
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
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
func RegisterPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	password := r.FormValue("password")
	password2 := r.FormValue("password_confirm")
	if password == password2 {
		CreateUser(w, r)
	} else {
		fmt.Fprintf(w, "Error passwords don't match")

	}

}

func main() {
	ncpu := runtime.NumCPU()
	runtime.GOMAXPROCS(ncpu)
	flag.Parse()

	defer db.Close()
	ren := render.New(render.Options{
		Directory:     "templates",                // Specify what path to load the templates from.
		Layout:        "layout",                   // Specify a layout template. Layouts can call {{ yield }} to render the current template or {{ partial "css" }} to render a partial from the current template.
		Extensions:    []string{".tmpl", ".html"}, // Specify extensions to load for templates.
		Charset:       "UTF-8",                    // Sets encoding for json and html content-types. Default is "UTF-8".
		IsDevelopment: false,                      // Render will now recompile the templates on every HTML response.
	})
	r := mux.NewRouter()
	n := negroni.Classic()

	store := cookiestore.New([]byte("evOuIxidcFDywC4MfGyf5xamfrKGLJrmQLUfRJtOo9i8vaQln9oLwU9qGnwNQAS"))
	n.Use(sessions.Sessions("global_session_store", store))

	r.PathPrefix("/build").Handler(http.StripPrefix("/build", http.FileServer(http.Dir("build/"))))
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		ren.HTML(w, http.StatusOK, "index", &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)})

	})
	r.HandleFunc("/faq", func(w http.ResponseWriter, r *http.Request) {
		ren.HTML(w, http.StatusOK, "faq", &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)})
	})
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ren.HTML(w, http.StatusOK, "login", &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)})
		case "POST":
			LoginUser(w, r)
		}

	})
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ren.HTML(w, http.StatusOK, "register", &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)})

		case "POST":
		}

	})
	r.HandleFunc("/store", func(w http.ResponseWriter, r *http.Request) {
		products := []Products{}

		err := db.Select(&products, "SELECT * FROM products")
		if err != nil {
			if err == sql.ErrNoRows {
				http.NotFound(w, r)
				return

			} else {
				log.Fatal(err)
			}
		}

		ren.HTML(w, http.StatusOK, "storemain", &products)
	})
	r.HandleFunc("/store/{productname}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		key := vars["productname"]

		var (
			description string
			image       string
			price       float32
		)

		err := db.QueryRow("SELECT description, image, price FROM products WHERE product_name = ?", key).Scan(&description, &image, &price)
		if err != nil {
			if err == sql.ErrNoRows {
				http.NotFound(w, r)
				return

			} else {
				log.Fatal(err)
			}
		}

		ren.HTML(w, http.StatusOK, "store", &Products{Context: Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)}, Productname: key, Description: description, Image: image, Price: price})
	})
	r.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ren.HTML(w, http.StatusOK, "checkout", &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)})
		case "POST":
			r.ParseForm()
		}

	})

	r.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		AdminAuth(w, r, "admin")
	})

	r.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "user")
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

	})

	r.HandleFunc("/admin/orders", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "orders")
		}

	})

	r.HandleFunc("/admin/add", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "add")
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

	})

	r.HandleFunc("/admin/remove", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "remove")
		case "POST":
			r.ParseForm()
			productname := r.FormValue("productname")
			_, err := db.Exec("DELETE from products where product_name = ?", productname)

			if err != nil {
				log.Print(err)
			}
			http.Redirect(w, r, "/admin/remove", 302)

		}

	})

	r.HandleFunc("/admin/modify", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "modify")
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

	})

	r.HandleFunc("/admin/upload", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			AdminAuth(w, r, "upload")
		case "POST":
			r.ParseForm()
			file, handler, err := r.FormFile("files[]")
			if err != nil {
				log.Print(err)
				return
			}
			defer file.Close()
			fmt.Fprintf(w, "%v", handler.Header)
			f, err := os.OpenFile("./build/img/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				log.Print(err)
				return
			}
			defer f.Close()
			io.Copy(f, file)
			http.Redirect(w, r, "/admin/modify", 302)
		}

	})

	r.HandleFunc("/authfail", func(w http.ResponseWriter, r *http.Request) {

		context := &Context{IsAdmin: IsAdmin(r), LoggedIn: LoggedIn(r)}
		ren.HTML(w, http.StatusOK, "authfail", context)
	})

	r.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal("{'API Test': test }")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(data)

	})

	r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session := sessions.GetSession(r)
		session.Delete("useremail")
		http.Redirect(w, r, "/", 302)
	})

	n.UseHandler(r)
	n.Run(":8080")

}
