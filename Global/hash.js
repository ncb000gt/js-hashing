importClass(java.security.MessageDigest);
importClass(net.iharder.Base64);

if (!(global.hash)) {
    global.hash = {};
}

global.hash = {
    /**
     * Encodes the string sent in. The strength can vary and you can specify a salt, number of iterations, and type of hash.
     * Technique described at: http://www.owasp.org/index.php/Hashing_Java
     *
     * <code>
     * var hash = inn.user.encode('the quick brown dog runs over the fence.');
     * </code>
     *
     * @param {String} str
     * @param {String} salt - optional - An empty string is used for the salt should one not be provided
     * @param {Number|String} iteration - optional - Number of times to hash the string
     * @param {String} type - optional - Type of Hash you would like to use. For example: [SHA-1|SHA-256]
     * @return {Array} returns the encoded byte array
     */
    encode: function(str, salt, iterations, type) {
	salt = salt || '';
	iterations = iterations || 1000;
	type = type || 'SHA-256';

	var digest = MessageDigest.getInstance(type);
	digest.reset();
	digest.update(Packages.java.lang.String(salt).getBytes("UTF-8"));
	var input = digest.digest(Packages.java.lang.String(str).getBytes("UTF-8"));
	for (var i = 0; i < iterations; i++) {
            digest.reset();
            input = digest.digest(input);
	}
	return input;
    },
    /**
     * Converts the byte array to base64.
     *
     * <code>
     * var b64 = hash.to_base64(Packages.java.lang.String('Hi').getBytes('UTF-8'));
     * </code>
     *
     * @param {Array} bytes - Array of bytes to encode
     * @return {String} Base64 string from the encoded bytes
     */
    to_base64: function(bytes) {
	return Base64.encodeBytes(bytes);
    },
    /**
     * Converts the base64 string to a byte array
     *
     * <code>
     * var bytes = hash.from_base64(<base64 string>);
     * </code>
     *
     * @param {String} str - Base64 string to decode
     * @return {Array} Array of bytes representing the encoded data.
     */
    from_base64: function(str) {
	return Base64.decode(str);
    },
    /**
     * Generates a random salt based on characters and numbers.
     * The seed for the random function is a timestamp in milliseconds.
     *
     * <code>
     * var salt = inn.user.generate_salt(25);
     * </code>
     *
     * @param {String} size - optional
     * @return {String} returns the salt
     */
    generate_salt: function(size) {
	size = size || 20;
	var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var clen = chars.length;
	var seed = new Date().getTime();
	var salt = [];

	for (var i = 0; i < size; i++) {
	    salt.push(chars[Math.round(Math.random(seed) * clen)]);
	}

	salt = salt.join('');
	return salt;
    }
};