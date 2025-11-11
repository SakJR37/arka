exports.handler = async (event) => {
  console.log("Pickup Shipping Calculator triggered", JSON.stringify(event, null, 2));

  const { origin, destination } = event;

  if (!origin || !destination) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: "Missing required fields: origin, destination"
      })
    };
  }

  // Simulate pickup time calculation
  const estimatedHours = Math.floor(Math.random() * 24) + 1; // 1-24 hours
  const cost = 0; // Pickup is free

  return {
    statusCode: 200,
    body: JSON.stringify({
      type: "pickup",
      origin,
      destination,
      estimatedHours,
      estimatedDays: Math.ceil(estimatedHours / 24),
      cost,
      currency: "USD",
      available: true,
      message: "Customer pickup from store"
    })
  };
};
