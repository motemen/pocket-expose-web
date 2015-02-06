package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"

	"github.com/garyburd/redigo/redis"
)

type repository struct {
	conn redis.Conn
}

func (repo *repository) redisConn() redis.Conn {
	if repo.conn == nil {
		repo.conn = newRedisDial()
	}
	return repo.conn
}

func (repo *repository) finish() {
	if repo.conn != nil {
		repo.conn.Close()
	}
}

func (repo *repository) UserFromName(username string) (*user, error) {
	var u user
	err := redisJSON(repo.redisConn().Do("GET", "users:"+username)).Decode(&u)
	if err != nil {
		if err != redis.ErrNil {
			return nil, err
		}
		return nil, nil
	}

	return &u, nil
}

func (repo *repository) UserFromExposeKey(key string) (*user, error) {
	username, err := redis.String(repo.redisConn().Do("GET", "keys:"+key))
	if err != nil {
		if err != redis.ErrNil {
			return nil, err
		}
		return nil, nil
	}

	return repo.UserFromName(username)
}

func (repo *repository) SaveUser(u *user) error {
	userJSON, err := json.Marshal(u)
	if err != nil {
		return err
	}

	_, err = repo.redisConn().Do("SET", "users:"+u.Auth.Username, userJSON)
	if err != nil {
		return err
	}

	_, err = repo.redisConn().Do("SET", "keys:"+u.ExposeKey, u.Auth.Username)
	return err
}

func (repo *repository) UpdateUserExposeKey(u *user, key string) error {
	_, err := repo.redisConn().Do("DEL", "keys:"+u.ExposeKey)
	if err != nil {
		return err
	}

	u.ExposeKey = key

	return repo.SaveUser(u)
}

func (repo *repository) EraseUser(u *user) error {
	_, err := repo.redisConn().Do("DEL", "keys:"+u.ExposeKey)
	if err != nil {
		return err
	}

	_, err = repo.redisConn().Do("DEL", "users:"+u.Auth.Username)
	return err
}

func newRedisDial() redis.Conn {
	conn, err := redis.Dial("tcp", config.redisHost)
	if err != nil {
		panic(err)
	}
	return redis.NewLoggingConn(conn, log.New(os.Stderr, "[repository]", log.LstdFlags), "")
}

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
