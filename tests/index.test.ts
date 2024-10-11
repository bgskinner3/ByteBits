/* eslint-disable no-undef */
import { BlowfishHandler, BlowfishEncryptDecrypt } from '../src/index';
// TODO: ADD MORE TESTING FOR OTHER FACTORS 
describe('Blowfish Default initialization, encryption, decryption', () => {
  let initialization: BlowfishEncryptDecrypt;
  test('Setting up the encryption', () => {
    initialization = BlowfishHandler.initializeBlowfish();

    expect(initialization).toBeInstanceOf(BlowfishEncryptDecrypt);
  });

  const word1 = 'sourceid=@caCMS';
  test('Testing encryption and decryption', () => {
    let wordToEncrypt: string | null = word1;
    wordToEncrypt = BlowfishHandler.encryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).not.toBe(word1);
    // Encrypted value should match the folloowing regular expression
    expect(wordToEncrypt).toMatch(/^[0-9A-Z]+$/);

    wordToEncrypt =
      wordToEncrypt &&
      BlowfishHandler.decryptData("B135F962EFC393732BC110B5C5CC406DF72758861139DD85EC4E045906DF7DE0D2D247A1BB5573382E7D2518D500CCA4D6662E8D7C53B190BEE135F439F52E20FB51AC497144264393180678BB266B390C36B7A464AC53FA6685ECC5D16752D7760D1946176615CE4CDF3E395AC5D77295C9759415B3D814426226297B978545A3B186AFE94D2B3A1A3E448A9991AF79C807B9E0E1A8F6F9D5F40CF56B4B376BB355360F7076D33CD25B568002F4DBE709E31AC946196EB50DEDB797B93B4E1BF0DF7B9EB4BA5B473E7CCBE7249AD377DDFF51445443A90A29E4CEC358F8E8176F695E029F818FD25C6166359C5480E2F2B2AFA5B4CED4A7B12A54D295D51DA3787BA3F47214B72BE20C2DB74874A00D", initialization);

    expect(wordToEncrypt)
  });
});

describe('Blowfish custom seed phrase initialization, encryption, decryption', () => {
  let initialization: BlowfishEncryptDecrypt;
  const customSeedPhrase = '212System';
  test('Setting up the encryption', () => {
    initialization = BlowfishHandler.initializeBlowfish(customSeedPhrase);

    expect(initialization).toBeInstanceOf(BlowfishEncryptDecrypt);
  });

  const word1 = 'sourceid=@caCMS!1d|membershipid=4382122664790005';
  test('Testing encryption and decryption with custom phrase', () => {
    let wordToEncrypt: string | null = word1;
    wordToEncrypt = BlowfishHandler.encryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).not.toBe(word1);
    // Encrypted value should match the folloowing regular expression
    expect(wordToEncrypt).toMatch(/^[0-9A-Z]+$/);

    wordToEncrypt =
      wordToEncrypt &&
      BlowfishHandler.decryptData("38663622969750367D36D897147703586396C96F1E35843BEFE5FD52C0891EB2501A60F630CCE58C9B21F135FF1200BD910E645F5AD8F28E291EBA665352E0F154FA17D6907576B26830192A72B268B34F423F105AC482280A5AF1C7572FE2DA4F5796767CBB0A3EFE8BA44D095DBE41", initialization);
console.log(wordToEncrypt, "HERE")
    // expect(wordToEncrypt).toBe('HERE');
  });
});



// describe('Blowfish Decryption', () => {
//   let initialization: BlowfishEncryptDecrypt;

//   test('Setting up the encryption', () => {
//     initialization = BlowfishHandler.initializeBlowfish('212System');

//     expect(initialization).toBeInstanceOf(BlowfishEncryptDecrypt);
//   });

//   const word1 = '38663622969750367D36D897147703586396C96F1E35843BEFE5FD52C0891EB2501A60F630CCE58C9B21F135FF1200BD910E645F5AD8F28E291EBA665352E0F154FA17D6907576B2947247268FD10654797B3D89989691351B0CF4A63260514E34BFB37DAB10053C46324C8422F251A4';




//   test('Testing encryption and decryption with custom phrase', () => {
//     let wordToEncrypt: string | null = word1;


//     wordToEncrypt =
//       wordToEncrypt &&
//       BlowfishHandler.decryptData(wordToEncrypt, initialization);

//     expect(wordToEncrypt).not.toBe(word1);
//   });
// });