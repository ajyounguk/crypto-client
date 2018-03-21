var express = require('express')
var app = express()

// get server port from environment, otherwise use 3000
var port = process.env.PORT || 3000

// configure assets and views
app.use('/assets', express.static(__dirname+'/public'))
app.set('views', __dirname+'/views');
app.set('view engine', 'ejs')

var cryptController = require('./controllers/cryptController')


cryptController(app)


console.log("Crypt server listening on port", port)

app.listen(port)

