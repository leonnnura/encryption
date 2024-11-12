const fs = require('fs');
const path = require('path');

function generateRandomIndividuals(count) {
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
    console.log(`Created directory: ${dataDir}`);
  }

  const firstNames = ['John', 'Jane', 'Alice', 'Bob', 'Carol', 'Dave', 'Eve', 'Frank', 'Grace', 'Heidi'];
  const lastNames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Miller', 'Davis', 'Garcia', 'Rodriguez', 'Wilson'];

  const individuals = [];

  for (let i = 0; i < count; i++) {
    const individual = {
      id: i + 1,
      name: firstNames[Math.floor(Math.random() * firstNames.length)],
      surname: lastNames[Math.floor(Math.random() * lastNames.length)],
      age: Math.floor(Math.random() * 50) + 20, // Age between 20 and 70
      heart_rate: Math.floor(Math.random() * 40) + 60, // Heart rate between 60 and 100
      blood_pressure: {
        systolic: Math.floor(Math.random() * 60) + 90, // Systolic between 90 and 150
        diastolic: Math.floor(Math.random() * 40) + 60, // Diastolic between 60 and 100
      },
      cholesterol: Math.floor(Math.random() * 200) + 100, // Cholesterol between 100 and 300
      disease_indicator: Math.random() < 0.3 ? 1 : 0, // 30% chance of disease presence
      // Add other fields as needed
    };

    individuals.push(individual);
  }

  // Save the data to a JSON file
  fs.writeFileSync(path.join(dataDir, 'individuals.json'), JSON.stringify({ individuals }, null, 2));
  console.log(`Generated data for ${count} individuals.`);
}

generateRandomIndividuals(50);
