import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import * as jwt from "jsonwebtoken";

const secretsManagerClient = new SecretsManagerClient({});
const JWT_SECRET_ARN = process.env.JWT_SECRET_ARN;

let jwtSecret: string;

// Function to retrieve the JWT secret from Secrets Manager, with caching
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
  throw new Error("JWT Secret not found in Secrets Manager");
};

// Helper function to generate an IAM policy
const generatePolicy = (
  principalId: string,
  effect: string,
  resource: string
) => {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };
};

export const handler = async (event: any) => {
  const token = event.authorizationToken;

  if (!token) {
    return generatePolicy("user", "Deny", event.methodArn);
  }

  try {
    const secret = await getJwtSecret();
    // The 'Bearer ' prefix is removed from the token string
    const decoded = jwt.verify(token.substring(7), secret);

    // You can add additional checks here, e.g., check if the user exists in a database

    return generatePolicy("user", "Allow", event.methodArn);
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return generatePolicy("user", "Deny", event.methodArn);
  }
};
