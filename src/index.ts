import { BlowfishHandler } from "./blowfish/blowfish-handler";



// function CryptoGuard(input: string): string {
//     BlowfishHandler.initializeBlowfish("string")
//     const regex = /^[0-9A-Z]+$/;
//     const shouldDecrypt = regex.test(input);

//     // useEffect(() => {
//     //   const processData = () => {
//     //     if (!shouldDecrypt) {
//     //       const encryption = BlowfishHandler.encryptData(input);
//     //       console.log(encryption);
//     //       setData(encryption);
//     //     }
//     //     if (shouldDecrypt && value !== null) {
//     //       const encryption = BlowfishHandler.decryptData(input);
//     //       setData(encryption);
//     //     }
//     //   };
//     //   if (!value) {
//     //     processData();
//     //   }
//     // }, [input, value, shouldDecrypt]);

//     // return value !== null ? value : '';
//     return ''
// }


export {
    BlowfishHandler
}


// export function ThisTest() {
//     const handler = BlowfishHandler.initializeBlowfish("FUCK YOU")
//     const test = "Your mother"
//     const res = BlowfishHandler.encryptData(test, handler)
//     return res
// }

// const res = ThisTest()
// console.log(res)