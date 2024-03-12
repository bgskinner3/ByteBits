/* eslint-disable no-undef */
import { BlowfishHandler } from '../src/index'


// eslint-disable-next-line no-undef
describe("FizzBuzz", () => {
   
    test('encrypted', () => {
        const x = BlowfishHandler.initializeBlowfish('hello')
        const encrypt = BlowfishHandler.encryptData("fuck", x)
      expect(encrypt).toBe('fizz');
    });

    // test('[5] should result in "buzz"', () => {
    //   expect(fizz_buzz([5])).toBe('buzz');
    // });

    // test('[15] should result in "fizzbuzz"', () => {
    //   expect(fizz_buzz([15])).toBe('fizzbuzz');
    // });

    // test('[1,2,3] should result in "1, 2, fizz"', () => {
    //   expect(fizz_buzz([3])).toBe('fizz');
    // });

});