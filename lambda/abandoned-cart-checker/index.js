const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require("@aws-sdk/client-sqs");
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");

const sqsClient = new SQSClient({ region: process.env.AWS_REGION || "us-east-1" });
const snsClient = new SNSClient({ region: process.env.AWS_REGION || "us-east-1" });

exports.handler = async (event) => {
  console.log("Abandoned Cart Checker Lambda triggered", JSON.stringify(event, null, 2));

  const queueUrl = process.env.SQS_QUEUE_URL;
  const snsTopicArn = process.env.SNS_TOPIC_ARN;

  try {
    // Receive messages from SQS
    const receiveParams = {
      QueueUrl: queueUrl,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 5
    };

    const receiveCommand = new ReceiveMessageCommand(receiveParams);
    const { Messages } = await sqsClient.send(receiveCommand);

    if (!Messages || Messages.length === 0) {
      console.log("No abandoned cart messages found");
      return {
        statusCode: 200,
        body: JSON.stringify({ message: "No abandoned carts to process" })
      };
    }

    console.log(`Processing ${Messages.length} abandoned cart messages`);

    // Process each message
    for (const message of Messages) {
      try {
        const cartData = JSON.parse(message.Body);
        console.log("Processing cart:", cartData);

        // Publish notification to SNS
        const publishParams = {
          TopicArn: snsTopicArn,
          Subject: "Abandoned Cart Alert",
          Message: JSON.stringify({
            type: "ABANDONED_CART",
            cartId: cartData.cartId,
            userId: cartData.userId,
            items: cartData.items,
            totalValue: cartData.totalValue,
            abandonedAt: cartData.abandonedAt,
            action: "SEND_REMINDER_EMAIL"
          })
        };

        const publishCommand = new PublishCommand(publishParams);
        await snsClient.send(publishCommand);

        console.log(`Notification sent for cart ${cartData.cartId}`);

        // Delete message from queue
        const deleteParams = {
          QueueUrl: queueUrl,
          ReceiptHandle: message.ReceiptHandle
        };

        const deleteCommand = new DeleteMessageCommand(deleteParams);
        await sqsClient.send(deleteCommand);

        console.log(`Message deleted for cart ${cartData.cartId}`);

      } catch (error) {
        console.error("Error processing message:", error);
      }
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ 
        message: "Abandoned carts processed successfully",
        processed: Messages.length
      })
    };

  } catch (error) {
    console.error("Lambda execution error:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        error: "Failed to process abandoned carts",
        details: error.message
      })
    };
  }
};
