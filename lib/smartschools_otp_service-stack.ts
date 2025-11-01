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
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as logs from "aws-cdk-lib/aws-logs";

interface SmartSchoolsOtpServiceStackProps extends cdk.StackProps {
  environment: string;
  domainName: string;
}

export class SmartSchoolsOtpServiceStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: SmartSchoolsOtpServiceStackProps
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
      tableName: `${props.environment}_otp_table`,
    });

    // Secret for JWT

    const jwtSecret = new secretsmanager.Secret(this, "JwtSecret", {
      secretName: `${props.environment}_smartschools/jwt-secret`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: "key",
        excludePunctuation: true,
        includeSpace: false,
      },
    });

    // API Gateway
    // Read allowed origins from an SSM parameter. The parameter value can be a JSON array
    // (e.g. ["https://app.example.com"]), or a comma-separated string of origins.
    // Read allowed origins from SSM as a single string value (JSON array or comma-separated).
    // Use `valueFromLookup` so the parameter is resolved at synth time and we get a concrete
    // string to parse into a JS array (avoids encoded list token errors at synth time).
    const rawOrigins = ssm.StringParameter.valueFromLookup(
      this,
      `/${props.environment}/auth/cors/allowed_origins`
    );

    let schoolOrigins: string[] = [];
    try {
      const parsed = JSON.parse(rawOrigins);
      if (Array.isArray(parsed)) {
        schoolOrigins = parsed.map((v) => String(v).trim()).filter(Boolean);
      } else {
        schoolOrigins = String(parsed)
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }
    } catch (e) {
      // not valid JSON — treat as comma-separated list
      schoolOrigins = String(rawOrigins)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }

    const api = new apigateway.RestApi(this, "AuthApi", {
      restApiName: `${props.environment} Auth Service`,
      defaultCorsPreflightOptions: {
        allowOrigins: [...schoolOrigins],
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    // Lambda for requesting OTP
    const requestOtpLambda = new NodejsFunction(this, "RequestOtpHandler", {
      runtime: lambda.Runtime.NODEJS_22_X,
      entry: "lambda/auth-request-otp/index.ts",
      functionName: `${props.environment}-RequestOtpHandler`,
      memorySize: 128,
      handler: "handler",
      environment: {
        OTP_TABLE_NAME: otpTable.tableName,
        FROM_EMAIL_ADDRESS:
          props.environment === "prod"
            ? `noreply@${props.domainName}`
            : `${props.environment}_noreply@${props.domainName}`,
      },
      timeout: cdk.Duration.seconds(10),
      logGroup: new logs.LogGroup(this, "RequestOtpLogGroup", {
        logGroupName: `/aws/lambda/${props.environment}-RequestOtpHandler`,
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });

    // Lambda for verifying OTP and generating JWT
    const verifyOtpLambda = new NodejsFunction(this, "VerifyOtpHandler", {
      runtime: lambda.Runtime.NODEJS_22_X,
      memorySize: 128,
      entry: "lambda/auth-verify-otp/index.ts",
      functionName: `${props.environment}-VerifyOtpHandler`,
      handler: "handler",
      environment: {
        OTP_TABLE_NAME: otpTable.tableName,
        JWT_SECRET_ARN: jwtSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(10),
      logGroup: new logs.LogGroup(this, "VerifyOtpLogGroup", {
        logGroupName: `/aws/lambda/${props.environment}-VerifyOtpHandler`,
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
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
      functionName: `${props.environment}-JwtAuthorizerLambda`,
      memorySize: 128,
      handler: "handler",
      environment: {
        JWT_SECRET_ARN: jwtSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(10),
      logGroup: new logs.LogGroup(this, "JwtAuthorizerLogGroup", {
        logGroupName: `/aws/lambda/${props.environment}-JwtAuthorizerLambda`,
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });
    jwtSecret.grantRead(authorizerLambda);

    // Publish authorizer Lambda ARN into SSM so other stacks can consume it
    new ssm.StringParameter(this, "AuthorizerLambdaArnParam", {
      parameterName: `/${props.environment}/auth/authorizer_lambda_arn`,
      stringValue: authorizerLambda.functionArn,
      description: "ARN of the OTP service JWT authorizer Lambda",
    });

    new cdk.CfnOutput(this, "AuthorizerLambdaArn", {
      value: authorizerLambda.functionArn,
    });

    // Create explicit CloudWatch LogGroups for the Lambdas with 7-day retention.
    // This ensures logs are retained for a limited time instead of indefinitely.

    // Route 53, ACM, and Custom Domain for API Gateway
    const domainName =
      props.environment === "prod"
        ? `auth.${props.domainName}`
        : `${props.environment}.auth.${props.domainName}`;

    // Look up the hosted zone
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: props.domainName,
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
      recordName: `${props.environment}.auth`,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.ApiGatewayDomain(customDomain)
      ),
    });

    new cdk.CfnOutput(this, "ApiUrl", {
      value: api.url,
    });
  }
}
