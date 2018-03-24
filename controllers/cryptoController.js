module.exports = function (app) {

    var bodyParser = require('body-parser')
    var urlencodedParser = bodyParser.urlencoded({extended: false})
    var ursa = require('ursa');

    var crypto = require('crypto')
    
// init vars
    var crypto = {
        AESenc : { data: "", secret: "", cipher: "" },  
        AESdec : { cipher: "", secret: "", data: "" },
        SHAhash : { data: "", secret: "", hash: "" },
        RSAenc : { pub: "", data: "", cipher: "" },
        RSAdec : { priv: "", data: "", cipher: "" }
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

        encryption = { data: "", secret: "", cipher: "" }  
        decryption = { data: "", secret: "", cipher: "" }
        hashed = { data: "", secret: "", hash: "" }
        rsaencrypt = { pub: "", data: "", cipher: "" }
        rsadecrypt = { priv: "", data: "", cipher: "" }

        res.setHeader('Content-Type', 'text/html');
    
        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 1})
    })

// 1. encrypt
    app.post('/encrypt', urlencodedParser, function (req, res) {

        encryption.data = req.body.data
        encryption.secret = req.body.secret

        encrypt_helper (encryption, function (encryption) {
            decryption.data = ""
            console.log('encrypt:', encryption)
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 1})
        })
    })




// 2. decrypt
    app.post('/decrypt', urlencodedParser, function (req, res) {
       
        decryption.cipher = req.body.cipher
        decryption.secret = req.body.secret

        decrypt_helper (decryption, function (decryption) {
            console.log('decrypt:', decryption )
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 2})
        })
    })





// 3. hash
    app.post('/hash', urlencodedParser, function (req, res) {
        
        hashed.data = req.body.data
        hashed.secret = req.body.secret

        hash_helper (hashed, function (hashed) {
            console.log('hash:',hashed)
            res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 3})
        })
    })




// 4. RSA Key Generation
    app.post('/rsaKeys', urlencodedParser, function (req, res) {
            
        // create a pair of keys (a private key contains both keys...)
        var keys = ursa.generatePrivateKey();

        var privPem = keys.toPrivatePem('base64');
        var pubPem = keys.toPublicPem('base64');
       
        rsadecrypt.priv = privPem
        rsaencrypt.pub = pubPem

        res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 4})

    })



// 5. RSA Encryption
app.post('/rsaEncrypt', urlencodedParser, function (req, res) {

    rsaencrypt.data = req.body.data
    rsaencrypt.pub = req.body.pub
            
    // encrypt, with the public key
    var data = new Buffer(rsaencrypt.data)
    var pub = ursa.createPublicKey(rsaencrypt.pub, 'base64')
    rsaencrypt.cipher = pub.encrypt(data)

    res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 5})

})


// 6. RSA Decryption
app.post('/rsaDecrypt', urlencodedParser, function (req, res) {

    rsadecrypt.priv = req.body.priv
    rsadecrypt.cipher = rsaencrypt.cipher
            
    // decrypt, with the private key
    var priv = ursa.createPrivateKey(rsadecrypt.priv, '', 'base64')
    rsadecrypt.data = priv.decrypt(rsadecrypt.cipher).toString('ascii')

    res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsaencrypt: rsaencrypt, rsadecrypt: rsadecrypt, menuitem: 6})

})




// 00. RSA Key Generation
app.get('/test', urlencodedParser, function (req, res) {

    
    // create a pair of keys (a private key contains both keys...)
    var keys = ursa.generatePrivateKey();
    console.log('keys:', keys);
    
    // reconstitute the private key from a base64 encoding
    var privPem = keys.toPrivatePem('base64');
    var priv = ursa.createPrivateKey(privPem, '', 'base64');
    var pubPem = keys.toPublicPem('base64');
    var pub = ursa.createPublicKey(pubPem, 'base64');
    var data = new Buffer('hello world');
    var enc = pub.encrypt(data);
    var unenc = priv.decrypt(enc);

    // /////////////////////////////////////
    var keys = ursa.generatePrivateKey()
    var privPem = keys.toPrivatePem('base64');
    var priv = ursa.createPrivateKey(privPem, '', 'base64')
    var pubPem = keys.toPublicPem('base64');
    var data = new Buffer("test")
    var pub = ursa.createPublicKey(pubPem, 'base64')
    var cipher = pub.encrypt(data)
    var plaintext = priv.decrypt(cipher)

    console.log(plaintext)

res.render('./index', {encryption: encryption, decryption: decryption, hashed: hashed, rsa: rsa, menuitem: 0})

})




// EOL
}


