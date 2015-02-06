package main

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/go-martini/martini"
	"github.com/kelseyhightower/envconfig"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
	"github.com/motemen/go-pocket/api"
	pocketAuth "github.com/motemen/go-pocket/auth"
)

const keyTypeList = "list"

var config struct {
	ConsumerKey   string `envconfig:"POCKET_CONSUMER_KEY"`
	RedisURL      string `envconfig:"REDIS_URL"`
	SessionSecret string `envconfig:"SESSION_SECRET"`
	CSRFSecret    string `envconfig:"CSRF_SECRET"`

	redisHost string
}

type user struct {
	Auth      pocketAuth.Authorization `json:"auth"`
	ExposeKey string                   `json:"key"`
}

func init() {
	err := envconfig.Process("", &config)
	if err != nil {
		panic(err)
	}

	if config.RedisURL == "" {
		config.RedisURL = "redis://127.0.0.1:6379"
	}
	redisURL, err := url.Parse(config.RedisURL)
	if err != nil {
		panic(err)
	}

	config.redisHost = redisURL.Host

	log.Printf("config: %+v", config)
}

type Authorizer struct {
	ConsumerKey string
	RedirectURL string
	Session     sessions.Session
}

const sessionKeyAuthCode = "auth_code"

func (a Authorizer) Prepare() (string, error) {
	reqToken, err := pocketAuth.ObtainRequestToken(a.ConsumerKey, a.RedirectURL)
	if err != nil {
		return "", err
	}

	authURL := pocketAuth.GenerateAuthorizationURL(reqToken, a.RedirectURL)

	a.Session.Set(sessionKeyAuthCode, reqToken.Code)

	return authURL, nil
}

func (a Authorizer) Authorize() (*pocketAuth.Authorization, error) {
	code := a.Session.Get(sessionKeyAuthCode)
	if code == nil {
		return nil, fmt.Errorf("session %q not set", sessionKeyAuthCode)
	}

	a.Session.Delete(sessionKeyAuthCode)

	reqToken := &pocketAuth.RequestToken{Code: code.(string)}
	return pocketAuth.ObtainAccessToken(a.ConsumerKey, reqToken)
}

func withUser(c martini.Context, sess sessions.Session, repo *repository) {
	var u *user

	username := sess.Get("username")
	if username != nil {
		u, _ = repo.UserFromName(username.(string))
	}

	c.Map(u)
}

func main() {
	m := martini.Classic()

	m.Use(sessions.Sessions("s", sessions.NewCookieStore([]byte(config.SessionSecret))))
	m.Use(csrf.Generate(&csrf.Options{
		Secret:     config.CSRFSecret,
		SessionKey: "username",
	}))
	m.Use(render.Renderer())
	m.Use(martini.Recovery())

	m.Use(func(c martini.Context) {
		repo := &repository{}
		defer repo.finish()

		c.Map(&repository{})
		c.Next()
	})

	m.Get("/", withUser, func(w http.ResponseWriter, u *user, x csrf.CSRF) {
		err := indexTmpl.Execute(w, viewContext{u, x.GetToken()})
		if err != nil {
			panic(err)
		}
	})

	m.Get("/auth", func(req *http.Request, r render.Render, sess sessions.Session) {
		redirectURL := fmt.Sprintf("http://%s/auth/callback", req.Host)

		authr := Authorizer{
			ConsumerKey: config.ConsumerKey,
			RedirectURL: redirectURL,
			Session:     sess,
		}
		authURL, err := authr.Prepare()
		if err != nil {
			panic(err)
		}

		r.Redirect(authURL)
	})

	m.Get("/auth/callback", func(r render.Render, repo *repository, sess sessions.Session) {
		authr := Authorizer{
			ConsumerKey: config.ConsumerKey,
			Session:     sess,
		}
		token, err := authr.Authorize()
		if err != nil {
			panic(err)
		}

		u := &user{
			Auth: *token,
		}
		sess.Set("username", token.Username)

		if err := refresh(repo, u, false); err != nil {
			panic(err)
		}

		r.Redirect("/")
	})

	m.Get("/list/:key.txt", func(w http.ResponseWriter, repo *repository, params martini.Params) {
		key := params["key"]

		u, err := repo.UserFromExposeKey(key)
		if err != nil {
			panic(err)
		}
		if u == nil {
			w.WriteHeader(404)
			return
		}

		pocket := api.NewClient(config.ConsumerKey, u.Auth.AccessToken)

		opts := &api.RetrieveOption{}
		res, err := pocket.Retrieve(opts)
		if err != nil {
			panic(err)
		}

		items := make([]api.Item, 0, len(res.List))
		for _, item := range res.List {
			items = append(items, item)
		}

		sort.Sort(bySortID(items))

		for _, item := range items {
			w.Write([]byte(strings.Replace(item.Title(), "\n", " ", -1)))
			w.Write([]byte{'\t'})
			w.Write([]byte(item.URL()))
			w.Write([]byte{'\n'})
		}
	})

	m.Post("/refresh", csrf.Validate, withUser, func(r render.Render, u *user, repo *repository) {
		if u == nil {
			r.Status(403)
		}

		err := refresh(repo, u, true)
		if err != nil {
			panic(err)
		}

		r.Redirect("/")
	})

	m.Post("/erase", csrf.Validate, withUser, func(r render.Render, u *user, repo *repository, sess sessions.Session) {
		if u == nil {
			r.Status(403)
		}

		err := repo.EraseUser(u)
		if err != nil {
			panic(err)
		}

		sess.Delete("username")

		r.Redirect("/")
	})

	m.Run()
}

type bySortID []api.Item

func (s bySortID) Len() int           { return len(s) }
func (s bySortID) Less(i, j int) bool { return s[i].SortId < s[j].SortId }
func (s bySortID) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func refresh(repo *repository, u *user, force bool) error {
	if u.ExposeKey != "" && force == false {
		return nil
	}

	return repo.UpdateUserExposeKey(u, genKey())
}

func genKey() string {
	buf := make([]byte, 16)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	h := sha1.New()
	h.Write(buf)

	return fmt.Sprintf("%x", h.Sum(nil))
}
