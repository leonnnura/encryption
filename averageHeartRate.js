const sealModule = require('node-seal');
const fs = require('fs');
const path = require('path');

async function calculateAverageHeartRate() {
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

    // Extract the heart rates for computation
    const heartRates = individuals.map(individual => individual.heart_rate);
    const count = heartRates.length;

    // Encrypt and sum the heart rates
    let encryptedSum = null;
    for (let i = 0; i < heartRates.length; i++) {
      const rate = heartRates[i];
      const plain = encoder.encode(Float64Array.from([rate]), scale);
      const encrypted = encryptor.encrypt(plain);

      if (i === 0) {
        encryptedSum = encrypted;
      } else {
        encryptedSum = evaluator.add(encryptedSum, encrypted);
      }
    }
    console.log('Encrypted sum of heart rates computed.');

    // Multiply by the inverse of the count to compute the average
    const inverseCount = 1 / count;
    const plainInverseCount = encoder.encode(Float64Array.from([inverseCount]), scale);
    let encryptedAverage = evaluator.multiplyPlain(encryptedSum, plainInverseCount);
    console.log('Computed encrypted average heart rate.');

    // Rescale the encrypted average
    encryptedAverage = evaluator.rescaleToNext(encryptedAverage);
    encryptedAverage.setScale(scale);

    // Decrypt and decode the result
    const decryptedResult = decryptor.decrypt(encryptedAverage);
    const decodedResult = encoder.decode(decryptedResult);
    const averageHeartRate = decodedResult[0];

    console.log(`Average Heart Rate: ${averageHeartRate}`);
  } catch (error) {
    console.error('An error occurred:', error.message);
  }
}

calculateAverageHeartRate();
