import { expect } from 'chai'
import Constable from './index'

describe('password-constable', () => {
	describe('password strength score', () => {
		const score = Constable.strength('zxcvbn');

		it('should return password strength', () => {
			expect(score).to.be.a('number');
		});
		it('should have a score of 0 for weak password "zxcvbn"', () => {
			expect(score).to.equal(0);
		});
	});
});