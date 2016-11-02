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
	describe('password length enforcement', () => {
		it('should be passing if longer than requirements', () => {
			expect(Constable.test('fffffffff', {length:8})).to.be.a('object');
			expect(Constable.test('fffffffff', {length:8}).result).to.equal(true);
		});
		it('should be failing if shorter than requirements', () => {
			expect(Constable.test('fff', {length:8}).result).to.equal(false);
			expect(Constable.test('fff', {length:8}).errors).to.include.keys('length');
		});
	});
	describe('password upper case enforcement', () => {
		it('should be failing when requiring upperCase and not providing them', () => {
			expect(Constable.test('fff', {require:['upperCase']}).result).to.equal(false);
			expect(Constable.test('fff', {require:['upperCase']}).errors).to.include.keys('upperCase');
		});
		it('should be passing when requiring upperCase and providing them', () => {
			expect(Constable.test('fffFFF', {require:['upperCase']}).result).to.equal(true);
		});
		it('should be passing when not requiring upperCase', () => {
			expect(Constable.test('fff').result).to.equal(true);
			expect(Constable.test('fffffffff', {length:8}).result).to.equal(true);
		});
	});
	describe('password numbers enforcement', () => {
		it('should be failing when requiring numbers and not providing them', () => {
			expect(Constable.test('fff', {require: ['numbers']}).result).to.equal(false);
			expect(Constable.test('fff', {require: ['numbers']}).errors).to.include.keys('numbers');
		});
		it('should be passing when requiring numbers and providing them', () => {
			expect(Constable.test('fff8', {require: ['numbers']}).result).to.equal(true);
		});
		it('should be passing when not requiring numbers', () => {
			expect(Constable.test('fff').result).to.equal(true);
		});
	});
	describe('special characters enforcement', () => {
		it('should be failing when requiring special characters and not providing them', () => {
			expect(Constable.test('fff', {require: ['specialCharacters']}).result).to.equal(false);
			expect(Constable.test('fff', {require: ['specialCharacters']}).errors).to.include.keys('specialCharacters');
		});
		it('should be passing when requiring special characters and providing them', () => {
			expect(Constable.test('fff&', {require: ['specialCharacters']}).result).to.equal(true);
		});
		it('should be passing when not requiring special characters', () => {
			expect(Constable.test('fff').result).to.equal(true);
		});
	});
	describe('dictionary words enforcements', () => {
		it('should be failing when excluding dictionary words and providing them', () => {
			expect(Constable.test('badge', {exclude: ['dictionary']}).result).to.equal(false);
		});
		it('should be passing when excluding dictionary words and not providing them', () => {
			expect(Constable.test('fff', {exclude: ['dictionary']}).result).to.equal(true);
		});
	});
	describe('mixed enforcements', () => {
		it('should pass with mixed requirements', () => {
			expect(Constable.test('ffffffffF9', {length: 8, require: ['upperCase', 'numbers']}).result).to.equal(true);
			expect(Constable.test('ffffffffF9&', {length: 8, require: ['upperCase', 'numbers', 'specialCharacters']}).result).to.equal(true);
			expect(Constable.test('ffffffffF9&', {length: 8, require: ['upperCase', 'numbers', 'specialCharacters'], exclude: ['dictionary']}).result).to.equal(true);
			expect(Constable.test('ballffffffffF9&', {length: 8, require: ['upperCase', 'numbers', 'specialCharacters'], exclude: ['dictionary']}).result).to.equal(false);
		});
	});
});
