module.exports = function (app) {

    var bodyParser = require('body-parser')
    var urlencodedParser = bodyParser.urlencoded({extended: false})
    var ursa = require('ursa');

    var crypto = require('crypto')
    
// init controller data obj
    var cryptodata = {
        aesEnc : { data: "", secret: "", cipher: "" },  
        aesDec : { cipher: "", secret: "", data: "" },
        shaHash : { data: "", secret: "", hash: "" },
        rsaEnc : { pub: "", data: "", cipher: "" },
        rsaDec : { priv: "", data: "", cipher: "" },
        menuItem : 1
    }

// encryption helper function
    function encrypt_helper(cryptodata, callback) {
        
        var cipher = crypto.createCipher('aes-256-ctr', cryptodata.aesEnc.secret)
        var crypted = cipher.update(cryptodata.aesEnc.data,'utf8','hex')
        crypted += cipher.final('hex');
        
        cryptodata.aesEnc.cipher = crypted

        callback(cryptodata)
    }

// decryption helper function
    function decrypt_helper(cryptodata, callback) {
        var decipher = crypto.createDecipher('aes-256-ctr', cryptodata.aesDec.secret)
        var dec = decipher.update(cryptodata.aesDec.cipher,'hex','utf8')
        dec += decipher.final('utf8');

        cryptodata.aesDec.data = dec

        callback (cryptodata)

    }


// hashing helper function
    function hash_helper(cryptodata, callback) {

        // create hash
        var hash = crypto.createHmac('sha512', cryptodata.shaHash.secret)
        hash.update(cryptodata.shaHash.data)
        cryptodata.shaHash.hash = hash.digest('hex') 

        callback (cryptodata)

    }


// login and serve up index
    app.get('/', function (req, res) {

        cryptodata = {
            aesEnc : { data: "", secret: "", cipher: "" },  
            aesDec : { cipher: "", secret: "", data: "" },
            shaHash : { data: "", secret: "", hash: "" },
            rsaEnc : { pub: "", data: "", cipher: "" },
            rsaDec : { priv: "", data: "", cipher: "" }
        }

        res.setHeader('Content-Type', 'text/html');

        cryptodata.menuItem = 1
        res.render('./index', {cryptodata: cryptodata})
    })

// 1. AES 256 Encrypt
    app.post('/encrypt', urlencodedParser, function (req, res) {

        cryptodata.aesEnc.data = req.body.data
        cryptodata.aesEnc.secret = req.body.secret

        encrypt_helper (cryptodata, function (cryptodata) {
            
            cryptodata.aesDec.data = ""
            cryptodata.menuItem = 1
            res.render('./index', {cryptodata: cryptodata})
        })
    })


// 2. AES 256 Decrypt
    app.post('/decrypt', urlencodedParser, function (req, res) {
       
        cryptodata.aesDec.cipher = req.body.cipher
        cryptodata.aesDec.secret = req.body.secret

        decrypt_helper (cryptodata, function (cryptodata) {
         
            cryptodata.menuItem = 2
            res.render('./index', {cryptodata: cryptodata})
        })
    })
    

// 3. SHA-2 Hash
    app.post('/hash', urlencodedParser, function (req, res) {
        
        cryptodata.shaHash.data = req.body.data
        cryptodata.shaHash.secret = req.body.secret

        hash_helper (cryptodata, function (cryptodata) {
            cryptodata.menuItem = 3
            res.render('./index', {cryptodata: cryptodata})
        })
    })


// 4. RSA Key Generation
    app.post('/rsaKeys', urlencodedParser, function (req, res) {
            
        // create a pair of keys (a private key contains both keys...)
        var keys = ursa.generatePrivateKey();

        var privPem = keys.toPrivatePem('base64');
        var pubPem = keys.toPublicPem('base64');
       
        cryptodata.rsaEnc.pub = pubPem
        cryptodata.rsaDec.priv = privPem

        cryptodata.menuItem = 4
        res.render('./index', {cryptodata: cryptodata})
    })


// 5. RSA Encryption
    app.post('/rsaEncrypt', urlencodedParser, function (req, res) {

        cryptodata.rsaEnc.data = req.body.data
        cryptodata.rsaEnc.pub = req.body.pub
                
        // encrypt, with the public key
        var data = new Buffer(cryptodata.rsaEnc.data)
        var pub = ursa.createPublicKey(cryptodata.rsaEnc.pub, 'base64')
        cryptodata.rsaEnc.cipher = pub.encrypt(data)

        cryptodata.menuItem = 5
        res.render('./index', {cryptodata: cryptodata})
    })


// 6. RSA Decryption
    app.post('/rsaDecrypt', urlencodedParser, function (req, res) {

        cryptodata.rsaDec.priv = req.body.priv

        // copy the cipher binary data as the body encoding will mess the binary up
        cryptodata.rsaDec.cipher = cryptodata.rsaEnc.cipher
                
        // decrypt, with the private key
        var priv = ursa.createPrivateKey(cryptodata.rsaDec.priv, '', 'base64')
        cryptodata.rsaDec.data = priv.decrypt(cryptodata.rsaDec.cipher).toString('ascii')

        cryptodata.menuItem = 6
        res.render('./index', {cryptodata: cryptodata})
    })


// EOL
}


