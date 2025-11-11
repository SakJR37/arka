exports.handler = async (event) => {
  console.log("Delivery Shipping Calculator triggered", JSON.stringify(event, null, 2));

  const { origin, destination, weight } = event;

  if (!origin || !destination || !weight) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: "Missing required fields: origin, destination, weight"
      })
    };
  }

  // Simulate standard delivery calculation
  const baseHours = 48; // 2 days base
  const weightFactor = Math.ceil(weight / 10); // Add hours based on weight
  const estimatedHours = baseHours + (weightFactor * 4);
  
  const baseCost = 10.00;
  const weightCost = weight * 0.50;
  const totalCost = baseCost + weightCost;

  return {
    statusCode: 200,
    body: JSON.stringify({
      type: "delivery",
      origin,
      destination,
      weight,
      estimatedHours,
      estimatedDays: Math.ceil(estimatedHours / 24),
      cost: parseFloat(totalCost.toFixed(2)),
      currency: "USD",
      available: true,
      message: "Standard home delivery"
    })
  };
};
