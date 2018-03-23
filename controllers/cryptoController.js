module.exports = function (app) {

    var bodyParser = require('body-parser')
    var urlencodedParser = bodyParser.urlencoded({extended: false})

    var crypto = require('crypto')

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
        
        var cipher = crypto.createCipher('aes-256-ctr', encryption.secret)
        var crypted = cipher.update(encryption.data,'utf8','hex')
        crypted += cipher.final('hex');
        
        encryption.cipher = crypted

        callback(encryption)
    }

// decryption helper function
    function decrypt_helper(decryption, callback) {
        var decipher = crypto.createDecipher('aes-256-ctr', decryption.secret)
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

        res.setHeader('Content-Type', 'text/html');
        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, menuitem: 0})
    })

// 1. encrypt
    app.post('/encrypt', urlencodedParser, function (req, res) {

        encryption.data = req.body.data
        encryption.secret = req.body.secret

        encrypt_helper (encryption, function (encryption) {
            decryption.data = ""
            console.log('encrypt:', encryption)
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, menuitem: 0})
        })
    })




// 2. decrypt
    app.post('/decrypt', urlencodedParser, function (req, res) {
       
        decryption.cipher = req.body.cipher
        decryption.secret = req.body.secret

        decrypt_helper (decryption, function (decryption) {
            console.log('decrypt:', decryption )
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, menuitem: 1})
        })
    })





// 3. hash
app.post('/hash', urlencodedParser, function (req, res) {
       
    hashed.data = req.body.data
    hashed.secret = req.body.secret

    hash_helper (hashed, function (hashed) {
        console.log('hash:',hashed)
        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, menuitem: 2})
    })
})


// EOL
}


