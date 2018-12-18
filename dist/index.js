'use strict';

var _passwordSheriff = require('password-sheriff');

var _zxcvbn = require('zxcvbn');

var _zxcvbn2 = _interopRequireDefault(_zxcvbn);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var getPasswordStrength = function getPasswordStrength(password) {
	return (0, _zxcvbn2.default)(password).score;
};

var testPassword = function testPassword(password) {
	var requirements = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

	var response = {};
	var errors = {};
	var passing = true;

	var rules = configureRules(requirements);

	if (rules.length && !rules.length.check(password)) {
		passing = false;
		errors.length = false;
	}

	if (rules.upperCase && !rules.upperCase.check(password)) {
		passing = false;
		errors.upperCase = false;
	}

	if (rules.numbers && !rules.numbers.check(password)) {
		passing = false;
		errors.numbers = false;
	}

	if (rules.specialCharacters && !rules.specialCharacters.check(password)) {
		passing = false;
		errors.specialCharacters = false;
	}

	if (rules.dictionary && !rules.dictionary.check(password)) {
		passing = false;
		errors.dictionary = false;
	}

	response.result = passing;

	if (errors) {
		response.errors = errors;
	}

	return response;
};

var configureRules = function configureRules(requirements) {

	var enforcer = {};

	/**
  * Minimum length
  */
	if (requirements.length) {
		enforcer.length = new _passwordSheriff.PasswordPolicy({ length: { minLength: requirements.length } });
	}

	/**
  * Items that are required
  */
	if (requirements.require && requirements.require.indexOf('upperCase') > -1) {
		enforcer.upperCase = new _passwordSheriff.PasswordPolicy({ contains: { expressions: [_passwordSheriff.charsets.upperCase] } });
	}

	if (requirements.require && requirements.require.indexOf('numbers') > -1) {
		enforcer.numbers = new _passwordSheriff.PasswordPolicy({ contains: { expressions: [_passwordSheriff.charsets.numbers] } });
	}

	if (requirements.require && requirements.require.indexOf('specialCharacters') > -1) {
		enforcer.specialCharacters = new _passwordSheriff.PasswordPolicy({ contains: { expressions: [_passwordSheriff.charsets.specialCharacters] } });
	}

	/**
  * Items that are prevented/excluded
  */
	if (requirements.exclude && requirements.exclude.indexOf('dictionary') > -1) {
		enforcer.dictionary = new _passwordSheriff.PasswordPolicy({ noDictionary: { allow: false } }, { noDictionary: new DictionaryWordsRule() });
	}

	return enforcer;
};

/**
 * Custom password sheriff policy incorporating zxcvbn
 * dictionary word validation
 */
var DictionaryWordsRule = function DictionaryWordsRule() {};

DictionaryWordsRule.prototype.validate = function (options) {
	if (!options) {
		throw new Error('options should be an object');
	}
	if (typeof options.allow !== 'boolean') {
		throw new Error('options should be boolean');
	}
};

DictionaryWordsRule.prototype.assert = function (options) {
	var password = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

	return !(options.allow === false && containsDictionaryWords(password));
};

DictionaryWordsRule.prototype.explain = function (options) {
	if (options.allow === false) {
		return {
			code: 'dictionary',
			message: 'Password should not contain special characters.'
		};
	} else {
		return {
			code: 'dictionary',
			message: 'Password can contain special characters.'
		};
	}
};

var containsDictionaryWords = function containsDictionaryWords(testString) {
	var result = (0, _zxcvbn2.default)(testString);
	var sequenceArray = result.sequence;
	var containsWord = false;

	sequenceArray.forEach(function (sequence) {
		if (sequence.pattern === 'dictionary') {
			containsWord = true;
		}
	});

	return containsWord;
};

module.exports = {
	strength: getPasswordStrength,
	test: testPassword
};

// //@TODO Cleanup for es6 exports
// const Constable = {
// 	strength: getPasswordStrength,
// 	test: testPassword
// };
//
// export default Constable;
