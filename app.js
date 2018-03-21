// crypto server, encrypt, decrypt and hash

var express = require('express')
var app = express()

// get server port from environment, otherwise use 3000
var port = process.env.PORT || 3000

// configure assets and views
app.use('/assets', express.static(__dirname+'/public'))
app.set('views', __dirname+'/views');
app.set('view engine', 'ejs')

var cryptoController = require('./controllers/cryptoController')


cryptoController(app)


console.log("Crypto server listening on port", port)

app.listen(port)

