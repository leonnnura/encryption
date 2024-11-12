const sealModule = require('node-seal');
const fs = require('fs');
const path = require('path');

async function healthDataAnalysis() {
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
    const count = individuals.length;
    const plainInverseCount = encoder.encode(Float64Array.from([1 / count]), scale);

    /*** 1. Calculate Average Age ***/
    console.log('\nCalculating Average Age...');
    const ages = individuals.map(ind => ind.age);

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

    let encryptedAverageAge = evaluator.multiplyPlain(encryptedAgeSum, plainInverseCount);
    console.log('Computed encrypted average age.');

    encryptedAverageAge = evaluator.rescaleToNext(encryptedAverageAge);
    encryptedAverageAge.setScale(scale);

    const decryptedAgeResult = decryptor.decrypt(encryptedAverageAge);
    const decodedAgeResult = encoder.decode(decryptedAgeResult);
    const averageAge = decodedAgeResult[0];

    console.log(`Average Age: ${averageAge}`);

    /*** 2. Calculate Average Cholesterol Level ***/
    console.log('\nCalculating Average Cholesterol Level...');
    const cholesterolLevels = individuals.map(ind => ind.cholesterol);

    let encryptedCholesterolSum = null;
    for (let i = 0; i < cholesterolLevels.length; i++) {
      const cholesterol = cholesterolLevels[i];
      const plain = encoder.encode(Float64Array.from([cholesterol]), scale);
      const encrypted = encryptor.encrypt(plain);

      if (i === 0) {
        encryptedCholesterolSum = encrypted;
      } else {
        encryptedCholesterolSum = evaluator.add(encryptedCholesterolSum, encrypted);
      }
    }
    console.log('Encrypted sum of cholesterol levels computed.');

    let encryptedAverageCholesterol = evaluator.multiplyPlain(encryptedCholesterolSum, plainInverseCount);
    console.log('Computed encrypted average cholesterol level.');

    encryptedAverageCholesterol = evaluator.rescaleToNext(encryptedAverageCholesterol);
    encryptedAverageCholesterol.setScale(scale);

    const decryptedCholesterolResult = decryptor.decrypt(encryptedAverageCholesterol);
    const decodedCholesterolResult = encoder.decode(decryptedCholesterolResult);
    const averageCholesterol = decodedCholesterolResult[0];

    console.log(`Average Cholesterol Level: ${averageCholesterol}`);

    /*** 3. Calculate Average Blood Pressure ***/
    console.log('\nCalculating Average Blood Pressure...');
    const systolicBP = individuals.map(ind => ind.blood_pressure.systolic);
    const diastolicBP = individuals.map(ind => ind.blood_pressure.diastolic);

    // Function to compute average of a list
    async function computeEncryptedAverage(values, label) {
      let encryptedSum = null;
      for (let i = 0; i < values.length; i++) {
        const value = values[i];
        const plain = encoder.encode(Float64Array.from([value]), scale);
        const encrypted = encryptor.encrypt(plain);

        if (i === 0) {
          encryptedSum = encrypted;
        } else {
          encryptedSum = evaluator.add(encryptedSum, encrypted);
        }
      }
      console.log(`Encrypted sum of ${label} computed.`);

      // Compute average
      let encryptedAverage = evaluator.multiplyPlain(encryptedSum, plainInverseCount);
      encryptedAverage = evaluator.rescaleToNext(encryptedAverage);
      encryptedAverage.setScale(scale);

      // Decrypt and decode the result
      const decryptedResult = decryptor.decrypt(encryptedAverage);
      const decodedResult = encoder.decode(decryptedResult);
      const average = decodedResult[0];

      console.log(`Average ${label}: ${average}`);
    }

    // Compute average systolic blood pressure
    await computeEncryptedAverage(systolicBP, 'Systolic Blood Pressure');

    // Compute average diastolic blood pressure
    await computeEncryptedAverage(diastolicBP, 'Diastolic Blood Pressure');

    /*** 4. Calculate Disease Prevalence ***/
    console.log('\nCalculating Disease Prevalence...');
    const diseaseIndicators = individuals.map(ind => ind.disease_indicator);

    let encryptedDiseaseSum = null;
    for (let i = 0; i < diseaseIndicators.length; i++) {
      const indicator = diseaseIndicators[i];
      const plain = encoder.encode(Float64Array.from([indicator]), scale);
      const encrypted = encryptor.encrypt(plain);

      if (i === 0) {
        encryptedDiseaseSum = encrypted;
      } else {
        encryptedDiseaseSum = evaluator.add(encryptedDiseaseSum, encrypted);
      }
    }
    console.log('Encrypted sum of disease indicators computed.');

    let encryptedDiseasePrevalence = evaluator.multiplyPlain(encryptedDiseaseSum, plainInverseCount);
    console.log('Computed encrypted disease prevalence.');

    encryptedDiseasePrevalence = evaluator.rescaleToNext(encryptedDiseasePrevalence);
    encryptedDiseasePrevalence.setScale(scale);

    const decryptedDiseaseResult = decryptor.decrypt(encryptedDiseasePrevalence);
    const decodedDiseaseResult = encoder.decode(decryptedDiseaseResult);
    const diseasePrevalence = decodedDiseaseResult[0] * 100; // Convert to percentage

    console.log(`Disease Prevalence: ${diseasePrevalence}%`);

    /*** 5. Compute Variance of Age ***/
        // console.log('\nComputing Variance of Age...');

        // // Use the 'ages' array already declared earlier
        // // const ages = individuals.map(ind => ind.age); // Remove this line
        // const varianceCount = ages.length; // Use a different variable name if 'count' is declared earlier

        // // Encrypt and sum the squared differences
        // let encryptedVarianceSum = null;
        // for (let i = 0; i < varianceCount; i++) {
        // const age = ages[i];

        // // Encode and encrypt the age
        // const plainAge = encoder.encode(Float64Array.from([age]), scale);
        // const encryptedAge = encryptor.encrypt(plainAge);

        // // Encode the mean age
        // const meanAgePlain = encoder.encode(Float64Array.from([averageAge]), scale);

        // // Subtract mean age from encrypted age
        // const diff = evaluator.subPlain(encryptedAge, meanAgePlain);

        // // Square the difference
        // let squaredDiff = evaluator.multiply(diff, diff);

        // // Rescale after multiplication
        // squaredDiff = evaluator.rescaleToNext(squaredDiff);
        // squaredDiff.setScale(Math.sqrt(squaredDiff.scale));

        // if (encryptedVarianceSum === null) {
        //     encryptedVarianceSum = squaredDiff;
        // } else {
        //     // Ensure scales and modulus levels match before addition
        //     encryptedVarianceSum = evaluator.add(encryptedVarianceSum, squaredDiff);
        // }
        // }
        // console.log('Encrypted sum of squared differences computed.');

        // // Re-encode inverse count at the new scale after rescaling
        // const varianceScale = encryptedVarianceSum.scale;
        // const plainInverseVarianceCount = encoder.encode(
        // Float64Array.from([1 / varianceCount]),
        // varianceScale
        // );

        // // Multiply by inverse count
        // let encryptedVariance = evaluator.multiplyPlain(
        // encryptedVarianceSum,
        // plainInverseVarianceCount
        // );

        // // Rescale after multiplication
        // encryptedVariance = evaluator.rescaleToNext(encryptedVariance);
        // encryptedVariance.setScale(Math.sqrt(encryptedVariance.scale));

        // // Decrypt and decode the result
        // const decryptedVarianceResult = decryptor.decrypt(encryptedVariance);
        // const decodedVarianceResult = encoder.decode(decryptedVarianceResult);
        // const variance = decodedVarianceResult[0];

        // console.log(`Variance of Age: ${variance}`);


    /*** 6. Compute Average Risk Score ***/
    // console.log('\nComputing Average Risk Score...');
    // const ageWeight = 0.3;
    // const cholesterolWeight = 0.4;
    // const bpWeight = 0.3;

    // const plainAgeWeight = encoder.encode(Float64Array.from([ageWeight]), scale);
    // const plainCholesterolWeight = encoder.encode(Float64Array.from([cholesterolWeight]), scale);
    // const plainBpWeight = encoder.encode(Float64Array.from([bpWeight]), scale);

    // let encryptedRiskScoreSum = null;
    // for (let i = 0; i < individuals.length; i++) {
    //   const individual = individuals[i];

    //   // Encode and encrypt individual factors
    //   const plainAge = encoder.encode(Float64Array.from([individual.age]), scale);
    //   const encryptedAge = encryptor.encrypt(plainAge);

    //   const plainCholesterol = encoder.encode(Float64Array.from([individual.cholesterol]), scale);
    //   const encryptedCholesterol = encryptor.encrypt(plainCholesterol);

    //   const systolicBp = individual.blood_pressure.systolic;
    //   const plainBp = encoder.encode(Float64Array.from([systolicBp]), scale);
    //   const encryptedBp = encryptor.encrypt(plainBp);

    //   // Multiply factors by weights
    //   const weightedAge = evaluator.multiplyPlain(encryptedAge, plainAgeWeight);
    //   const weightedCholesterol = evaluator.multiplyPlain(encryptedCholesterol, plainCholesterolWeight);
    //   const weightedBp = evaluator.multiplyPlain(encryptedBp, plainBpWeight);

    //   // Rescale
    //   const rescaledAge = evaluator.rescaleToNext(weightedAge);
    //   rescaledAge.setScale(scale);

    //   const rescaledCholesterol = evaluator.rescaleToNext(weightedCholesterol);
    //   rescaledCholesterol.setScale(scale);

    //   const rescaledBp = evaluator.rescaleToNext(weightedBp);
    //   rescaledBp.setScale(scale);

    //   // Sum weighted factors
    //   let encryptedRiskScore = evaluator.add(rescaledAge, rescaledCholesterol);
    //   encryptedRiskScore = evaluator.add(encryptedRiskScore, rescaledBp);

    //   // Sum up all risk scores
    //   if (encryptedRiskScoreSum === null) {
    //     encryptedRiskScoreSum = encryptedRiskScore;
    //   } else {
    //     encryptedRiskScoreSum = evaluator.add(encryptedRiskScoreSum, encryptedRiskScore);
    //   }
    // }
    // console.log('Encrypted sum of risk scores computed.');

    // let encryptedAverageRiskScore = evaluator.multiplyPlain(encryptedRiskScoreSum, plainInverseCount);
    // encryptedAverageRiskScore = evaluator.rescaleToNext(encryptedAverageRiskScore);
    // encryptedAverageRiskScore.setScale(scale);

    // const decryptedRiskScoreResult = decryptor.decrypt(encryptedAverageRiskScore);
    // const decodedRiskScoreResult = encoder.decode(decryptedRiskScoreResult);
    // const averageRiskScore = decodedRiskScoreResult[0];

    // console.log(`Average Risk Score: ${averageRiskScore}`);

    // /*** 7. Compute Covariance between Age and Cholesterol ***/
    // console.log('\nComputing Covariance between Age and Cholesterol...');
    // const meanCholesterolPlain = encoder.encode(Float64Array.from([averageCholesterol]), scale);

    // let encryptedCovarianceSum = null;
    // for (let i = 0; i < individuals.length; i++) {
    //   const age = individuals[i].age;
    //   const cholesterol = individuals[i].cholesterol;

    //   const plainAge = encoder.encode(Float64Array.from([age]), scale);
    //   const encryptedAge = encryptor.encrypt(plainAge);

    //   const plainCholesterol = encoder.encode(Float64Array.from([cholesterol]), scale);
    //   const encryptedCholesterol = encryptor.encrypt(plainCholesterol);

    //   // Compute differences using subPlain
    //   const diffAge = evaluator.subPlain(encryptedAge, meanAgePlain);
    //   const diffCholesterol = evaluator.subPlain(encryptedCholesterol, meanCholesterolPlain);

    //   // Multiply differences
    //   let productDiff = evaluator.multiply(diffAge, diffCholesterol);
    //   productDiff = evaluator.rescaleToNext(productDiff);
    //   productDiff.setScale(scale);

    //   if (encryptedCovarianceSum === null) {
    //     encryptedCovarianceSum = productDiff;
    //   } else {
    //     encryptedCovarianceSum = evaluator.add(encryptedCovarianceSum, productDiff);
    //   }
    // }
    // console.log('Encrypted sum of products of differences computed.');

    // let encryptedCovariance = evaluator.multiplyPlain(encryptedCovarianceSum, plainInverseCount);
    // encryptedCovariance = evaluator.rescaleToNext(encryptedCovariance);
    // encryptedCovariance.setScale(scale);

    // const decryptedCovarianceResult = decryptor.decrypt(encryptedCovariance);
    // const decodedCovarianceResult = encoder.decode(decryptedCovarianceResult);
    // const covariance = decodedCovarianceResult[0];

    // console.log(`Covariance between Age and Cholesterol: ${covariance}`);

  } catch (error) {
    console.error('An error occurred:', error.message);
  }
}

healthDataAnalysis();
