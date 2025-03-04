using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Intake.LambdaAuthorizer.Model;
using Intake.LambdaAuthorizer.Model.Auth;

/*
 * https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/LICENSE
 */
namespace Intake.LambdaAuthorizer
{
    /// <summary>
    /// Receives a set of allowed and denied methods and generates a valid AWS policy for the API Gateway authorizer.
    /// </summary>
    public class AuthPolicyBuilder
    {
        /// <summary>
        /// The policy version used for the evaluation. This should always be "2012-10-17"
        /// </summary>
        private const string POLICY_VERSION = "2012-10-17";

        /// <summary>
        /// The regular expression used to validate resource paths for the policy
        /// </summary>
        private readonly Regex pathRegex = new Regex("^[/.a-zA-Z0-9-\\*]+$");

        // these are the values exctracted from the API Options passed into the construction
        // these options default to a "*" if the input option was empty
        private readonly string restApiId;
        private readonly string region;
        private readonly string stage;

        /// <summary>
        /// The AWS account id the policy will be generated for. This is used to create the method ARNs.
        /// </summary>
        public string AwsAccountId { get; }

        /// <summary>
        /// The principal used for the policy, this should be a unique identifier for the end user.
        /// </summary>
        public string PrincipalId { get; }

        // these are the internal lists of allowed and denied methods. These are lists
        // of objects and each object has 2 properties: A resource ARN and a nullable
        // conditions statement.
        // the build method processes these lists and generates the approriate
        // statements for the final policy
        private struct Method
        {
            internal string ArnResource;
            internal IDictionary<ConditionOperator, IDictionary<ConditionKey, string>> Conditions;
        }
        private readonly List<Method> allowMethods = new List<Method>();
        private readonly List<Method> denyMethods = new List<Method>();

        /// <param name="principalId">The calling user principal</param>
        /// <param name="awsAccountId">The AWS account ID of the API owner</param>
        /// <param name="apiOptions">API Gateway RestApi Id, a region for the RestApi, and a stage that calls should be allowed/denied for</param>
        public AuthPolicyBuilder(string principalId, string awsAccountId, ApiOptions apiOptions)
        {
            PrincipalId = principalId;
            AwsAccountId = awsAccountId;

            restApiId = string.IsNullOrWhiteSpace(apiOptions?.RestApiId) ? "*" : apiOptions.RestApiId;
            region = string.IsNullOrWhiteSpace(apiOptions?.Region) ? "*" : apiOptions.Region;
            stage = string.IsNullOrWhiteSpace(apiOptions?.Stage) ? "*" : apiOptions.Stage;
        }

        public void DenyAllMethods(ICollection<Condition> conditions = null)
        {
            AddMethod(Effect.Deny, HttpVerb.All, "*", conditions);
        }

        public void DenyMethod(HttpVerb verb, string resource, ICollection<Condition> conditions = null)
        {
            AddMethod(Effect.Deny, verb, resource, conditions);
        }

        public void AllowAllMethods(ICollection<Condition> conditions = null)
        {
            AddMethod(Effect.Allow, HttpVerb.All, "*", conditions);
        }

        public void AllowMethod(HttpVerb verb, string resource, ICollection<Condition> conditions = null)
        {
            AddMethod(Effect.Allow, verb, resource, conditions);
        }

        public AuthPolicy Build()
        {
            var statements = new List<Statement>();
            foreach (var method in allowMethods)
            {
                statements.Add(new Statement
                {
                    Effect = Effect.Allow.ToString(),
                    Resource = method.ArnResource,
                    Action = "execute-api:Invoke",
                    Condition = method.Conditions
                });
            }
            foreach (var method in denyMethods)
            {
                statements.Add(new Statement
                {
                    Effect = Effect.Deny.ToString(),
                    Resource = method.ArnResource,
                    Action = "execute-api:Invoke",
                    Condition = method.Conditions
                });
            }

            return new AuthPolicy
            {
                PrincipalId = PrincipalId,
                PolicyDocument = new PolicyDocument
                {
                    Version = POLICY_VERSION,
                    Statement = statements
                }
            };
        }

        private void AddMethod(Effect effect, HttpVerb verb, string resource, ICollection<Condition> conditions = null)
        {
            if (verb == null)
                throw new ArgumentNullException(nameof(verb));
            if (resource == null)
                throw new ArgumentNullException(nameof(resource));

            if (!pathRegex.IsMatch(resource))
                throw new Exception($"Invalid resource path: {resource}. Path should match {pathRegex}");

            var cleanedResource = resource.First() == '/' ? resource.Substring(1) : resource;

            var arn = new ApiGatewayArn
            {
                RestApiId = restApiId,
                Region = region,
                Stage = stage,
                AwsAccountId = AwsAccountId,
                Verb = verb.ToString(),
                Resource = cleanedResource
            };

            switch (effect)
            {
                case Effect.Deny:
                    denyMethods.Add(new Method
                    {
                        ArnResource = arn.ToString(),
                        Conditions = ConditionsToDictionary(conditions)
                    });
                    return;
                case Effect.Allow:
                    allowMethods.Add(new Method
                    {
                        ArnResource = arn.ToString(),
                        Conditions = ConditionsToDictionary(conditions)
                    });
                    return;
            }
        }

        private IDictionary<ConditionOperator, IDictionary<ConditionKey, string>> ConditionsToDictionary(ICollection<Condition> conditions = null)
        {
            if (conditions == null)
                return null;

            if (conditions.GroupBy(x => x.Operator).Any(x => x.Count() > 1))
                throw new Exception($"Condition Operators Must be Unique per Statement");

            return conditions.ToDictionary(condition => condition.Operator, condition => condition.KeyPairs);
        }
    }
}
