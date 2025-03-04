using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Intake.Common;
using Intake.LambdaAuthorizer.Error;
using Intake.LambdaAuthorizer.Model;
using Intake.LambdaAuthorizer.Model.Auth;
using System.Text.Json;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Intake.LambdaAuthorizer
{
    public class AuthorizerConFunction
    {
        private readonly string issuerUrl;
        private readonly string audienceUrl;
        private readonly string expectedFeature;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> configurationManager;

        public AuthorizerConFunction()
            : this(Environment.GetEnvironmentVariable("issuerUrl"),
                  Environment.GetEnvironmentVariable("audienceUrl"),
                  Environment.GetEnvironmentVariable("expectedFeature"))
        {
        }


        public AuthorizerConFunction(string issuerUrl, string audienceUrl, string expectedFeature)
        {
            this.issuerUrl = issuerUrl;
            this.audienceUrl = audienceUrl;
            this.expectedFeature = expectedFeature;

            configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
             issuerUrl + "/.well-known/oauth-authorization-server",
             new OpenIdConnectConfigurationRetriever(),
             new HttpDocumentRetriever());
        }

        public APIGatewayProxyResponse ReturnTokenException()
        {
            var response =
                       new APIGatewayProxyResponse()
                       {
                           StatusCode = 401,
                           Headers = new Dictionary<string, string>()
                       };
            response.Headers.Add(MessagesDictionary.Header_prefix, "MSG_" + MessagesDictionary.ERR_TokenValidationFailed.ToString());
            return response;
        }

        /// <summary>
        /// A simple function that takes the token authorizer and returns a policy based on the authentication token included.
        /// </summary>
        /// <param name="input">token authorization received by api-gateway event sources</param>
        /// <param name="context"></param>
        /// <returns>IAM Auth Policy</returns>

        // public async Task<APIGatewayProxyResponse> FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        public async Task<APIGatewayCustomAuthorizerResponse> FunctionHandler(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
        {
            try
            {

                Console.WriteLine(JsonSerializer.Serialize(request));
                var tokenQuery = request.QueryStringParameters?["token"];
                Console.WriteLine(JsonSerializer.Serialize(tokenQuery));
                context.Logger.LogLine($"Token: {tokenQuery}");

                var token = await ValidateToken(tokenQuery.Replace("Bearer ", string.Empty), issuerUrl, configurationManager, context.Logger);

                if (token == null)
                {
                    context.Logger.LogLine(MessagesDictionary.ReturnExplanationOfError(MessagesDictionary.ERR_TokenValidationFailed));
                    context.Logger.LogLine(MessagesDictionary.Info_INTAKE_TokenValidationFailed);

                    ReturnTokenException();
                }

                var principalId = token.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;
                var givenName = token.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.GivenName)?.Value;
                var familyName = token.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.FamilyName)?.Value;
                var email = token.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Email)?.Value;

                if (string.IsNullOrWhiteSpace(principalId))
                {
                    context.Logger.LogLine($"Principal Id {expectedFeature} not found on token");

                    context.Logger.LogLine(MessagesDictionary.ReturnExplanationOfError(MessagesDictionary.ERR_TokenValidationFailed));
                    context.Logger.LogLine(MessagesDictionary.Info_INTAKE_TokenValidationFailed);

                    ReturnTokenException();

                }

                var headers = request.Headers;
                var queryStringParameters = request.QueryStringParameters;
                var stageVariables = request.StageVariables;
                var requestContext = request.RequestContext;

                return new APIGatewayCustomAuthorizerResponse()
                {

                    PrincipalID = principalId,
                    PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                    {
                        Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
                        {
                            new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                            {
                                Effect = "Allow",
                                Resource = new HashSet<string> { "*" },
                                Action = new HashSet<string> { "execute-api:Invoke"}
                            }
                        }
                    },
                    Context = new APIGatewayCustomAuthorizerContextOutput()
                    {
                        {"UserId", principalId },
                        {"Email", email },
                        {"Name", $"{givenName} {familyName}" },

                    },
                    UsageIdentifierKey = requestContext.ApiId
                };
            }
            catch (Exception ex)
            {
                if (ex is UnauthorizedException)
                    throw;

                context.Logger.LogLine($"Unhandled error occured: {ex.Message}");
                context.Logger.LogLine(ex.ToString());

                context.Logger.LogLine(MessagesDictionary.ReturnExplanationOfError(MessagesDictionary.ERR_TokenValidationFailed));
                context.Logger.LogLine(MessagesDictionary.Info_INTAKE_TokenValidationFailed);

                ReturnTokenException();

                throw new UnauthorizedException();

            }
        }


        private async Task<JwtSecurityToken> ValidateToken(
        string token,
        string issuer,
        IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
        ILambdaLogger logger,
        CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = audienceUrl,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                // Allow for some drift in server time
                ClockSkew = TimeSpan.FromMinutes(2),

            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                     .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken) rawValidatedToken;
            }
            catch (SecurityTokenValidationException e)
            {
                logger.LogLine("Unable to validate JWT token: " + e.Message);
                logger.LogLine(e.ToString());

                logger.LogLine(MessagesDictionary.ReturnExplanationOfError(MessagesDictionary.ERR_TokenValidationFailed));
                logger.LogLine(MessagesDictionary.Info_INTAKE_TokenValidationFailed);

                ReturnTokenException();
                return null;
            }
        }
    }
}
