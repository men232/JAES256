var crypto = require('crypto');

module.exports = JAES256;

// JAES256: Constructor
function JAES256(secret_key) {
	// Define name constant
	Object.defineProperty(this, 'salt', {
		value: this.hash(secret_key, 'sha1'),
		writable: false
	});
}

// JAES256: Calculate sha1 hash
JAES256.prototype.hash = function(data, hash, encoding) {
	var sha1 = crypto.createHash(hash || 'sha1'),
		shasum = sha1.update(data);

	return shasum.digest(encoding);
};

// JAES256: Encrypt text function
JAES256.prototype.encrypt = function(shared_key, text) {
	var data = new Buffer(28 + Buffer.byteLength(text, 'utf8')),
		unix = +new Date() / 1000;

	// Fill data to be encrypted
	data.write(this.salt.toString('binary'), 0, 'binary', 20);
	data.writeDoubleLE(unix, 20);
	data.write(text, 28, 'utf8');

	// Make signature && encrypt data
	var signature = this.hash(data, 'sha1');
	aes_key = shared_key + signature.toString('hex'),
		cipher = crypto.createCipher('aes-256-ctr', aes_key),
		crypted = Buffer.concat([signature, cipher.update(data), cipher.final()]);

	return crypted;
};

// JAES256: Decrypt buffer function
JAES256.prototype.decrypt = function(shared_key, data, skiptTmestamp) {
	var signature = data.slice(0, 20),
		aes_key = shared_key + signature.toString('hex'),
		data = data.slice(20, data.length);

	// Encrypting data
	var decipher = crypto.createDecipher('aes-256-ctr', aes_key),
		decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

	var salt = decrypted.slice(0, 20),
		unix = decrypted.readDoubleLE(20);
	data = decrypted.slice(28);

	// Validate signature / salt / timestamp
	var data_hash = this.hash(decrypted, 'sha1');
	skiptTmestamp = skiptTmestamp || false;

	if (data_hash.toString('hex') !== signature.toString('hex')) {
		throw new Error('signature of data not valid.');
	} else if (salt.toString('hex') !== this.salt.toString('hex')) {
		throw new Error('salt of data not valid.');
	} else if (!skiptTmestamp && Math.round(+new Date() / 1000) - unix > 60) {
		throw new Error('timestamp of data has expired.');
	}

	return data.toString('utf8');
};

// JAES256: Encrypt object function
JAES256.prototype.objectEncrypt = function(shared_key, object, callback) {
	var arg_len = arguments.length;

	if (typeof object != 'object') {
		var err = new Error('object encrypting error, data is:', typeof object);

		if (arg_len > 2) {
			return callback();
		}

		throw arr;
	}

	var text = JSON.stringify(object);

	if (arg_len > 2) {
		callback(null, this.encrypt(shared_key, text));
	} else {
		return this.encrypt(shared_key, text);
	}
};

// JAES256: Encrypt object function
JAES256.prototype.objectDecrypt = function(shared_key, data, skiptTmestamp, callback) {
	var arg_len = arguments.length;

	try {
		var text = this.decrypt(shared_key, skiptTmestamp, data);

		if (arg_len > 2) {
			callback(null, JSON.parse(text));
		} else {
			return JSON.parse(text);
		}
	} catch (err) {
		if (arg_len > 2) {
			callback(err);
		}

		throw err;
	}
};

/* EXAMPLE:
var salt = 'secret_string';

var alice = new JAES256(salt);
var bob = new JAES256(salt);

var crypt = alice.objectEncrypt('shared_key', {test:'This IS My Text',hello:5});

console.log(bob.objectDecrypt('shared_key', crypt));

*/