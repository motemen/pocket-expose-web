package main

import (
	"html/template"
)

var indexHTML = `<!DOCTYPE html>
<html>
  <head>
    <title>Pocket Expose</title>
	<style>
form {
  display: inline;
}
button {
  font-family: monospace;
  border: none;
  font: inherit;
  background-color: silver;
  padding: 0;
  cursor: pointer;
}
	</style>
  </head>
  <body>
  <pre>= Pocket Expose

Pocket Expose is a web application that provides a URL exposing your <a href="https://getpocket.com/">Pocket</a> list.
{{if .User}}
- Your name: *<strong>{{.User.Auth.Username}}</strong>*
- Your list: <a href="/list/{{.User.ExposeKey}}.txt">/list/{{.User.ExposeKey}}.txt</a>

You can <form action="/refresh" method="POST"><input type="hidden" name="_csrf" value="{{.CSRFToken}}"><button>refresh</button></form> your URL, or <form action="/erase" method="POST"><input type="hidden" name="_csrf" value="{{.CSRFToken}}"><button>erase</button></form> your information entirely.</form>
	{{else}}
<a href="/auth">Log in</a> with Pocket
	{{end}}
-- 
<address>By <a href="https://twitter.com/motemen">@motemen</a></address>
	</pre>
  </body>
</html>
`

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

type viewContext struct {
	User      *user
	CSRFToken string
}
