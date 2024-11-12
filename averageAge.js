const sealModule = require('node-seal');
const fs = require('fs');
const path = require('path');

async function calculateAverageAge() {
  try {
    // Initialize SEAL instance
    const seal = await sealModule();

    // Set encryption parameters
    const schemeType = seal.SchemeType.ckks;
    const polyModulusDegree = 8192;
    const coeffModulus = seal.CoeffModulus.Create(
      polyModulusDegree,
      Int32Array.from([60, 40, 40, 60])
    );

    const parms = seal.EncryptionParameters(schemeType);
    parms.setPolyModulusDegree(polyModulusDegree);
    parms.setCoeffModulus(coeffModulus);

    // Create encryption context
    const context = seal.Context(parms, true, seal.SecurityLevel.tc128);
    if (!context.parametersSet()) {
      throw new Error('Encryption parameters are not valid!');
    }
    console.log('Encryption parameters are valid.');

    // Key generation
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();

    const encryptor = seal.Encryptor(context, publicKey);
    const evaluator = seal.Evaluator(context);
    const decryptor = seal.Decryptor(context, secretKey);
    const encoder = seal.CKKSEncoder(context);

    const scale = Math.pow(2, 40);

    // Load the generated data
    const dataPath = path.join(__dirname, 'data', 'individuals.json');
    const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const individuals = data.individuals;

    // Extract the ages
    const ages = individuals.map(individual => individual.age);
    const count = ages.length;

    // Encrypt and sum the ages
    let encryptedAgeSum = null;
    for (let i = 0; i < ages.length; i++) {
      const age = ages[i];
      const plain = encoder.encode(Float64Array.from([age]), scale);
      const encrypted = encryptor.encrypt(plain);

      if (i === 0) {
        encryptedAgeSum = encrypted;
      } else {
        encryptedAgeSum = evaluator.add(encryptedAgeSum, encrypted);
      }
    }
    console.log('Encrypted sum of ages computed.');

    // Compute average age
    const plainInverseCount = encoder.encode(Float64Array.from([1 / count]), scale);
    let encryptedAverageAge = evaluator.multiplyPlain(encryptedAgeSum, plainInverseCount);
    console.log('Computed encrypted average age.');

    // Rescale the encrypted average
    encryptedAverageAge = evaluator.rescaleToNext(encryptedAverageAge);
    encryptedAverageAge.setScale(scale);

    // Decrypt and decode the result
    const decryptedAgeResult = decryptor.decrypt(encryptedAverageAge);
    const decodedAgeResult = encoder.decode(decryptedAgeResult);
    const averageAge = decodedAgeResult[0];

    console.log(`Average Age: ${averageAge}`);
  } catch (error) {
    console.error('An error occurred:', error.message);
  }
}

calculateAverageAge();
