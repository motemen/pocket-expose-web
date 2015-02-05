package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/garyburd/redigo/redis"
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
	Auth pocketAuth.Authorization `json:"auth"`
	Key  string                   `json:"key"`
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
}

func newRedisDial() redis.Conn {
	conn, err := redis.Dial("tcp", config.redisHost)
	if err != nil {
		panic(err)
	}
	return redis.NewLoggingConn(conn, log.New(os.Stderr, "redis", log.LstdFlags), "rd")
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

var html = `<!DOCTYPE html>
<html>
  <head>
    <title>Pocket Expose</title>
	<style>
button {
  font-family: monospace;
  border: none;
  font: inherit;
  background-color: transparent;
  color: #09F;
  padding: 0;
  text-decoration: underline;
  cursor: pointer;
}
	</style>
  </head>
  <body>
  <pre>= Pocket Expose

Pocket Expose is a web application that provides a URL exposing your <a href="https://getpocket.com/">Pocket</a> list.
{{if .User}}
- Your name: *<strong>{{.User.Auth.Username}}</strong>*
- Your list: <a href="/list/{{.User.Key}}.txt">/list/{{.User.Key}}.txt</a>

<form action="/update" method="POST"><input type="hidden" name="_csrf" value="{{.CSRFToken}}">You can <button name="refresh" value="✓">refresh</button> your URL, or <button name="erase">erase</button> your information entirely.</form>
	{{else}}
<a href="/auth">Log in</a> with Pocket
	{{end}}
-- 
<address><a href="https://twitter.com/motemen">@motemen</a></address>
	</pre>
  </body>
</html>
`
var tmpl = template.Must(template.New("index").Parse(html))

type templateContext struct {
	User      *user
	CSRFToken string
}

func loadUser(rd redis.Conn, username string) (redis.Conn, *user, error) {
	if rd == nil {
		rd = newRedisDial()
	}

	var u user
	if err := redisJSON(rd.Do("GET", "users:"+username)).Decode(&u); err != nil {
		return nil, nil, err
	}

	return rd, &u, nil
}

func main() {
	m := martini.Classic()

	store := sessions.NewCookieStore([]byte(config.SessionSecret))
	m.Use(sessions.Sessions("s", store))
	m.Use(csrf.Generate(&csrf.Options{
		Secret:     config.CSRFSecret,
		SessionKey: "username",
	}))
	m.Use(render.Renderer())
	m.Use(martini.Recovery())

	m.Get("/", func(w http.ResponseWriter, sess sessions.Session, x csrf.CSRF) string {
		var u *user

		username := sess.Get("username")
		if username != nil {
			var err error
			_, u, err = loadUser(nil, username.(string))
			if err != nil {
				panic(err)
			}
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, templateContext{u, x.GetToken()}); err != nil {
			panic(err)
		}

		return buf.String()
	})

	m.Get("/auth", func(req *http.Request, w http.ResponseWriter, sess sessions.Session) {
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

		w.Header().Set("Location", authURL)
		w.WriteHeader(302)
	})

	m.Get("/auth/callback", func(w http.ResponseWriter, sess sessions.Session) {
		authr := Authorizer{
			ConsumerKey: config.ConsumerKey,
			Session:     sess,
		}
		token, err := authr.Authorize()
		if err != nil {
			panic(err)
		}

		sess.Set("username", token.Username)

		rd := newRedisDial()

		if err := refresh(rd, token, false); err != nil {
			panic(err)
		}

		w.Write([]byte("OK"))
	})

	m.Get("/list/:key.txt", func(w http.ResponseWriter, params martini.Params) {
		key := params["key"]

		rd := newRedisDial()

		username, err := redis.String(rd.Do("GET", "keys:"+key))
		if err != nil {
			panic(err)
		}

		_, u, err := loadUser(rd, username)
		if err != nil {
			panic(err)
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

	m.Post("/update", csrf.Validate, func(r render.Render, req *http.Request, params martini.Params, sess sessions.Session) {
		rd, u, err := loadUser(nil, sess.Get("username").(string)) // may panic
		if u == nil {
			panic(err)
		}

		log.Print(req.FormValue("refresh"))

		if req.FormValue("refresh") != "" {
			err := refresh(rd, &u.Auth, true)
			if err != nil {
				panic(err)
			}
		} else {
			panic("not implemented")
		}

		r.Redirect("/")
	})

	m.Run()
}

type bySortID []api.Item

func (s bySortID) Len() int           { return len(s) }
func (s bySortID) Less(i, j int) bool { return s[i].SortId < s[j].SortId }
func (s bySortID) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func redisJSON(reply interface{}, err error) decoder {
	b, err := redis.Bytes(reply, err)
	if err != nil {
		return failDecoder{err}
	}

	r := bytes.NewReader(b)
	return json.NewDecoder(r)
}

type decoder interface {
	Decode(v interface{}) error
}

type failDecoder struct {
	err error
}

func (ed failDecoder) Decode(_ interface{}) error {
	return ed.err
}

func refresh(rd redis.Conn, token *pocketAuth.Authorization, force bool) error {
	_, u, err := loadUser(rd, token.Username)

	switch err {
	case nil:
		if force == false {
			return nil
		}

	case redis.ErrNil:
		u = &user{
			Auth: *token,
		}

	default:
		return err
	}

	u.Key = genKey()

	userJSON, err := json.Marshal(u)
	if err != nil {
		return err
	}

	if _, err := rd.Do("SET", "users:"+token.Username, userJSON); err != nil {
		return err
	}

	if _, err := rd.Do("SET", "keys:"+u.Key, u.Auth.Username); err != nil {
		return err
	}

	return nil
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
