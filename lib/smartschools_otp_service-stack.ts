import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";

interface SmartSchoolsOtpServiceStackProps extends cdk.StackProps {
  environment: string;
}

export class SmartSchoolsOtpServiceStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props?: SmartSchoolsOtpServiceStackProps
  ) {
    super(scope, id, props);

    // DynamoDB table to store OTPs
    const otpTable = new dynamodb.Table(this, "OtpTable", {
      partitionKey: {
        name: "emailOrPhone",
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: "expires",
      tableName: `otp_table_${props?.environment}`,
    });

    // Secret for JWT
    const jwtSecret = new secretsmanager.Secret(this, "JwtSecret", {
      secretName: "smartschools/jwt-secret",
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: "key",
        excludePunctuation: true,
        includeSpace: false,
      },
    });

    // API Gateway
    const api = new apigateway.RestApi(this, "AuthApi", {
      restApiName: "SmartSchools Auth Service",
      defaultCorsPreflightOptions: {
        allowOrigins: [
          "https://smartskools.online",
          "https://admin.smartskools.online",
        ],
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    // Lambda for requesting OTP
    const requestOtpLambda = new NodejsFunction(this, "RequestOtpHandler", {
      runtime: lambda.Runtime.NODEJS_22_X,
      entry: "lambda/auth-request-otp/index.ts",
      handler: "handler",
      environment: {
        OTP_TABLE_NAME: otpTable.tableName,
        FROM_EMAIL_ADDRESS:
          process.env.FROM_EMAIL_ADDRESS || "noreply@smartskools.online", // Configure a verified SES email
      },
      timeout: cdk.Duration.seconds(100),
    });

    // Lambda for verifying OTP and generating JWT
    const verifyOtpLambda = new NodejsFunction(this, "VerifyOtpHandler", {
      runtime: lambda.Runtime.NODEJS_22_X,
      entry: "lambda/auth-verify-otp/index.ts",
      handler: "handler",
      environment: {
        OTP_TABLE_NAME: otpTable.tableName,
        JWT_SECRET_ARN: jwtSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(100),
    });

    // Grant permissions
    otpTable.grantReadWriteData(requestOtpLambda);
    otpTable.grantReadWriteData(verifyOtpLambda);
    jwtSecret.grantRead(verifyOtpLambda);

    // SES send email permission for request-otp lambda
    requestOtpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ses:SendEmail", "ses:SendRawEmail"],
        resources: ["*"], // It's better to restrict this to your SES identity ARN
      })
    );

    // SNS publish message permission for request-otp lambda
    requestOtpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sns:Publish"],
        resources: ["*"], // It's better to restrict this to a specific topic ARN if possible
      })
    );

    // API Gateway Integrations
    const requestOtpIntegration = new apigateway.LambdaIntegration(
      requestOtpLambda
    );
    const verifyOtpIntegration = new apigateway.LambdaIntegration(
      verifyOtpLambda
    );

    const authResource = api.root.addResource("auth");
    authResource
      .addResource("request-otp")
      .addMethod("POST", requestOtpIntegration);
    authResource
      .addResource("verify-otp")
      .addMethod("POST", verifyOtpIntegration);

    // JWT Authorizer Lambda
    const authorizerLambda = new NodejsFunction(this, "JwtAuthorizerLambda", {
      runtime: lambda.Runtime.NODEJS_22_X,
      entry: "lambda/auth-jwt-authorizer/index.ts",
      handler: "handler",
      environment: {
        JWT_SECRET_ARN: jwtSecret.secretArn,
      },
    });
    jwtSecret.grantRead(authorizerLambda);

    // Route 53, ACM, and Custom Domain for API Gateway
    const domainName = "auth.smartskools.online";

    // Look up the hosted zone
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: "smartskools.online",
    });

    // Create a certificate
    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: domainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // Create a custom domain
    const customDomain = new apigateway.DomainName(this, "CustomDomain", {
      domainName: domainName,
      certificate: certificate,
      endpointType: apigateway.EndpointType.REGIONAL,
    });

    // Map the custom domain to the API
    new apigateway.BasePathMapping(this, "ApiMapping", {
      domainName: customDomain,
      restApi: api,
    });

    // Create a Route 53 A record
    new route53.ARecord(this, "ApiARecord", {
      zone: hostedZone,
      recordName: "auth",
      target: route53.RecordTarget.fromAlias(
        new route53Targets.ApiGatewayDomain(customDomain)
      ),
    });

    new cdk.CfnOutput(this, "ApiUrl", {
      value: api.url,
    });
  }
}
