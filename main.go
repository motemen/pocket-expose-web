package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/garyburd/redigo/redis"
	"github.com/go-martini/martini"
	"github.com/kelseyhightower/envconfig"
	"github.com/martini-contrib/sessions"
	"github.com/motemen/go-pocket/api"
	pocketAuth "github.com/motemen/go-pocket/auth"
)

const keyTypeList = "list"

var config struct {
	ConsumerKey   string `envconfig:"POCKET_CONSUMER_KEY"`
	RedisURL      string `envconfig:"REDIS_URL"`
	SessionSecret string

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
}

func (a Authorizer) Prepare() (string, *pocketAuth.RequestToken, error) {
	reqToken, err := pocketAuth.ObtainRequestToken(a.ConsumerKey, a.RedirectURL)
	if err != nil {
		return "", nil, err
	}

	authURL := pocketAuth.GenerateAuthorizationURL(reqToken, a.RedirectURL)
	return authURL, reqToken, nil
}

func main() {
	m := martini.Classic()

	store := sessions.NewCookieStore([]byte(config.SessionSecret))
	m.Use(sessions.Sessions("s", store))

	m.Get("/-/auth", func(req *http.Request, w http.ResponseWriter, sess sessions.Session) {
		redirectURL := fmt.Sprintf("http://%s/-/auth/callback", req.Host)

		authr := Authorizer{
			ConsumerKey: config.ConsumerKey,
			RedirectURL: redirectURL,
		}
		authURL, reqToken, err := authr.Prepare()

		if err != nil {
			log.Print("ERROR", err)
			w.WriteHeader(500)
		}

		sess.Set("auth_code", reqToken.Code)

		w.Header().Set("Location", authURL)
		w.WriteHeader(302)
	})

	m.Get("/-/auth/callback", func(w http.ResponseWriter, sess sessions.Session) {
		code := sess.Get("auth_code")
		if code == nil {
			w.WriteHeader(400)
			return
		}

		sess.Delete("auth_code")

		reqToken := &pocketAuth.RequestToken{Code: code.(string)}
		token, err := pocketAuth.ObtainAccessToken(config.ConsumerKey, reqToken)
		if err != nil {
			log.Print("ERROR", "(ObtainAccessToken)", err)
			w.WriteHeader(500)
			return
		}

		sess.Set("username", token.Username)

		rd := newRedisDial()

		if err := refresh(rd, token, false); err != nil {
			log.Print("ERROR", "(refresh)", err)
			w.WriteHeader(500)
			return
		}

		w.Write([]byte("OK"))
	})

	m.Get("/list/:key.txt", func(w http.ResponseWriter, param martini.Params) {
		key := param["key"]

		rd := newRedisDial()

		username, err := redis.String(rd.Do("GET", "keys:"+key))
		if err != nil {
			log.Print(err)
		}

		var u user
		err = redisJSON(rd.Do("GET", "users:"+username)).Decode(&u)
		if err != nil {
			log.Print(err)
		}

		pocket := api.NewClient(config.ConsumerKey, u.Auth.AccessToken)

		opts := &api.RetrieveOption{}
		res, err := pocket.Retrieve(opts)
		if err != nil {
			log.Print(err)
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
	var u user

	err := redisJSON(rd.Do("GET", "users:"+token.Username)).Decode(&u)
	switch err {
	case nil:
		if force == false {
			return nil
		}

	case redis.ErrNil:
		u = user{
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

	rd.Do("SET", "users:"+token.Username, userJSON)

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
