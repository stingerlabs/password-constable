import PasswordPolicy from 'password-sheriff';
import charsets from 'password-sheriff';
import zxcvbn from 'zxcvbn'

module.exports = {
	strength: getPasswordStrength
};

function getPasswordStrength(password) {
	return zxcvbn(password).score;
}