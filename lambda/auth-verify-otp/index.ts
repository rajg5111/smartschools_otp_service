import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  DeleteCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import * as bcrypt from "bcryptjs";
import * as jwt from "jsonwebtoken";

const dbClient = new DynamoDBClient({});
const ddbDocClient = DynamoDBDocumentClient.from(dbClient);
const secretsManagerClient = new SecretsManagerClient({});

const OTP_TABLE_NAME = process.env.OTP_TABLE_NAME;
const JWT_SECRET_ARN = process.env.JWT_SECRET_ARN;

let jwtSecret: string;

const getJwtSecret = async () => {
  if (jwtSecret) {
    return jwtSecret;
  }
  const command = new GetSecretValueCommand({ SecretId: JWT_SECRET_ARN });
  const data = await secretsManagerClient.send(command);
  if (data.SecretString) {
    const secret = JSON.parse(data.SecretString);
    jwtSecret = secret.key;
    return jwtSecret;
  }
  throw new Error("JWT Secret not found");
};

export const handler = async (event: any) => {
  try {
    const { emailOrPhone, otp } = JSON.parse(event.body);

    if (!emailOrPhone || !otp) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "emailOrPhone and OTP are required" }),
        headers: { "Access-Control-Allow-Origin": "*" },
      };
    }

    // 1. Retrieve OTP from DynamoDB
    const getCommand = new GetCommand({
      TableName: OTP_TABLE_NAME,
      Key: { emailOrPhone },
    });
    const result = await ddbDocClient.send(getCommand);
    const storedOtpRecord = result.Item;

    if (!storedOtpRecord) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Invalid or expired OTP" }),
        headers: { "Access-Control-Allow-Origin": "*" },
      };
    }

    // 2. Compare the submitted OTP with the stored hash
    const isValid = await bcrypt.compare(otp, storedOtpRecord.otp);

    if (!isValid) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Invalid or expired OTP" }),
        headers: { "Access-Control-Allow-Origin": "*" },
      };
    }

    // 3. OTP is valid, delete it to prevent reuse
    const deleteCommand = new DeleteCommand({
      TableName: OTP_TABLE_NAME,
      Key: { emailOrPhone },
    });
    await ddbDocClient.send(deleteCommand);

    // 4. Generate a JWT
    const secret = await getJwtSecret();
    const token = jwt.sign({ emailOrPhone, role: "admin" }, secret, {
      expiresIn: "8h",
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ token }),
      headers: { "Access-Control-Allow-Origin": "*" },
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal server error" }),
      headers: { "Access-Control-Allow-Origin": "*" },
    };
  }
};
