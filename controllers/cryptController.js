module.exports = function (app) {

    var bodyParser = require('body-parser')
    var urlencodedParser = bodyParser.urlencoded({extended: false})

    var crypto = require('crypto')
    var algorithm = 'aes-256-ctr'

    var encryption = {
        data: "",
        secret: "",
        cipher: ""
    }  

    var decryption = {
        data: "",   
        secret: "",
        cipher: ""
    }

    var hashed = {
        data: "",   
        secret: "",
        hash: ""
    }

// encryption helper function
    function encrypt_helper(encryption, callback) {
        
        var cipher = crypto.createCipher(algorithm, encryption.secret)
        var crypted = cipher.update(encryption.data,'utf8','hex')
        crypted += cipher.final('hex');
        
        encryption.cipher = crypted

        callback(encryption)
    }

// decryption helper function
    function decrypt_helper(decryption, callback) {
        var decipher = crypto.createDecipher(algorithm, decryption.secret)
        var dec = decipher.update(decryption.cipher,'hex','utf8')
        dec += decipher.final('utf8');

        decryption.data = dec

        callback (decryption)

    }


// hashing helper function
    function hash_helper(hashed, callback) {

        // create hash
        var hash = crypto.createHmac('sha512', hashed.secret)
        hash.update(hashed.data)
        hashed.hash = hash.digest('hex') 

        callback (hashed)

    }


// login and serve up index
    app.get('/', function (req, res) {

        res.setHeader('Content-Type', 'text/html');
        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed})
    })

// 1. encrypt
    app.post('/encrypt', urlencodedParser, function (req, res) {

        encryption.data = req.body.data
        encryption.secret = req.body.secret

        encrypt_helper (encryption, function (encryption) {
            decryption.data = ""
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed})
        })
    })




// 2. decrypt
    app.post('/decrypt', urlencodedParser, function (req, res) {
       
        decryption.cipher = req.body.cipher
        decryption.secret = req.body.secret

        decrypt_helper (decryption, function (decryption) {
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed})
        })
    })





// 3. hash
app.post('/hash', urlencodedParser, function (req, res) {
       
    hashed.data = req.body.data
    hashed.secret = req.body.secret

    hash_helper (hashed, function (hashed) {
        console.log(hashed)
        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed})
    })
})


// EOL
}


