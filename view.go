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
  background-color: #DDD;
  padding: 0;
  cursor: pointer;
}
    </style>
  </head>
  <body>
  <pre>Pocket Expose
=============

Pocket Expose is a web application that provides a URL exposing your <a href="https://getpocket.com/">Pocket</a> list.
{{if .User}}
- Your name: *<strong>{{.User.Auth.Username}}</strong>*
- Your list: [<a href="/list/{{.User.ExposeKey}}.txt">Text</a>] [<a href="/list/{{.User.ExposeKey}}.atom">Atom</a>]

Action
------

You can <form action="/refresh" method="POST"><input type="hidden" name="_csrf" value="{{.CSRFToken}}"><button>refresh</button></form> your URL, or <form action="/erase" method="POST"><input type="hidden" name="_csrf" value="{{.CSRFToken}}"><button>erase</button></form> your information entirely.</form>
{{else}}
<a href="/auth">Log in</a> with Pocket
{{end}}
Author
------

<address><a href="https://twitter.com/motemen">@motemen</a></address>
    </pre>
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','//www.google-analytics.com/analytics.js','ga');
  ga('create', 'UA-38081126-2', 'auto');
  ga('send', 'pageview');
</script>
  </body>
</html>
`

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

type viewContext struct {
	User      *user
	CSRFToken string
}
