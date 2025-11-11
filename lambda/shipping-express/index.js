exports.handler = async (event) => {
  console.log("Express Shipping Calculator triggered", JSON.stringify(event, null, 2));

  const { origin, destination, priority = 1 } = event;

  if (!origin || !destination) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: "Missing required fields: origin, destination"
      })
    };
  }

  // Simulate express shipping calculation
  const baseHours = 12; // Next day delivery
  const priorityFactor = priority > 3 ? 6 : baseHours; // Same day for high priority
  const estimatedHours = priorityFactor;
  
  const baseCost = 25.00;
  const priorityCost = priority > 3 ? 15.00 : 0;
  const totalCost = baseCost + priorityCost;

  return {
    statusCode: 200,
    body: JSON.stringify({
      type: "express",
      origin,
      destination,
      priority,
      estimatedHours,
      estimatedDays: Math.ceil(estimatedHours / 24),
      cost: parseFloat(totalCost.toFixed(2)),
      currency: "USD",
      available: true,
      message: priority > 3 ? "Same-day express delivery" : "Next-day express delivery"
    })
  };
};
