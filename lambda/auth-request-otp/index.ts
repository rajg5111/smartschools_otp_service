import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import * as crypto from "crypto";
import * as bcrypt from "bcryptjs";

const dbClient = new DynamoDBClient({});
const ddbDocClient = DynamoDBDocumentClient.from(dbClient);
const sesClient = new SESClient({});
const snsClient = new SNSClient({});

const OTP_TABLE_NAME = process.env.OTP_TABLE_NAME;
const FROM_EMAIL_ADDRESS = process.env.FROM_EMAIL_ADDRESS;

export const handler = async (event: any) => {
  try {
    const { emailOrPhone } = JSON.parse(event.body);
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailOrPhone);

    if (!emailOrPhone) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "emailOrPhone is required" }),
        headers: {
          "Access-Control-Allow-Origin": "*",
        },
      };
    }

    // 1. Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // 2. Hash the OTP
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otp, salt);

    // 3. Store in DynamoDB with a 5-minute TTL
    const ttl = Math.floor(Date.now() / 1000) + 300; // 5 minutes from now
    const putCommand = new PutCommand({
      TableName: OTP_TABLE_NAME,
      Item: {
        emailOrPhone: emailOrPhone,
        otp: hashedOtp,
        expires: ttl,
      },
    });
    await ddbDocClient.send(putCommand);
    let msg = "";
    // 4. Send OTP via SES
    if (isEmail) {
      await sendOtpEmail(emailOrPhone, otp);
      msg = "OTP has been sent to your email.";
    } else {
      // Assumes phone number is in E.164 format (e.g., +12223334444)
      await sendOtpSms(emailOrPhone, otp);
      msg = "OTP has been sent to your phone.";
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ message: msg }),
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal server error" }),
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    };
  }
};
async function sendOtpEmail(emailOrPhone: any, otp: string) {
  const sendEmailCommand = new SendEmailCommand({
    Source: FROM_EMAIL_ADDRESS,
    Destination: {
      ToAddresses: [emailOrPhone],
    },
    Message: {
      Subject: { Data: "Your SmartSchools Admin Portal OTP" },
      Body: {
        Text: { Data: `Your One-Time Password is: ${otp}` },
      },
    },
  });
  await sesClient.send(sendEmailCommand);
}
async function sendOtpSms(phoneNumber: string, otp: string) {
  const command = new PublishCommand({
    Message: `Your SmartSchools Admin Portal OTP is: ${otp}`,
    PhoneNumber: phoneNumber,
  });
  await snsClient.send(command);
}
