const multiHashing = require('../build/Release/multihashing')

var tests = [
	new Buffer('The quick brown fox jumps over the lazy dog'),
];

console.log(multiHashing.yescrypt(tests[0]));
