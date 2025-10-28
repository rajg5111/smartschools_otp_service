#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { SmartSchoolsOtpServiceStack } from "../lib/smartschools_otp_service-stack";

interface AppContext {
  environment: string;
  domainName: string;
  account: string;
  region: string;
}
if (!process.env.SMARTSCHOOLS_DOMAIN_NAME) {
  throw new Error(
    "Missing required environment variable: SMARTSCHOOLS_DOMAIN_NAME"
  );
}
if (!process.env.SMARTSCHOOLS_AWS_ENVIRONMENT) {
  throw new Error(
    "Missing required environment variable: SMARTSCHOOLS_AWS_ENVIRONMENT"
  );
}

if (!process.env.SMARTSCHOOLS_AWS_ACCOUNT) {
  throw new Error(
    "Missing required environment variable: SMARTSCHOOLS_AWS_ACCOUNT"
  );
}
if (!process.env.SMARTSCHOOLS_AWS_REGION) {
  throw new Error(
    "Missing required environment variable: SMARTSCHOOLS_AWS_REGION"
  );
}
const context: AppContext = {
  domainName: process.env.SMARTSCHOOLS_DOMAIN_NAME,
  environment: process.env.SMARTSCHOOLS_AWS_ENVIRONMENT,
  account: process.env.SMARTSCHOOLS_AWS_ACCOUNT,
  region: process.env.SMARTSCHOOLS_AWS_REGION,
};
const stackName = `${context.environment}-otp-service`;

const app = new cdk.App();
new SmartSchoolsOtpServiceStack(app, stackName, {
  environment: context.environment,
  domainName: context.domainName,
  // env: { account: context.account, region: context.region },
});
