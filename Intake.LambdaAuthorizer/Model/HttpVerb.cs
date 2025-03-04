/*
 * https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/LICENSE
 */
namespace Intake.LambdaAuthorizer.Model
{
    /// <summary>
    /// A set of existing HTTP verbs supported by API Gateway.
    /// This class is here to avoid spelling mistakes in the policy.
    /// </summary>
    public sealed class HttpVerb
    {
        private readonly string verb;

        private HttpVerb(string verb)
        {
            this.verb = verb;
        }

        public override string ToString()
        {
            return verb;
        }

        public static HttpVerb Get => new HttpVerb("GET");
        public static HttpVerb Post => new HttpVerb("POST");
        public static HttpVerb Put => new HttpVerb("PUT");
        public static HttpVerb Patch => new HttpVerb("PATCH");
        public static HttpVerb Head => new HttpVerb("HEAD");
        public static HttpVerb Delete => new HttpVerb("DELETE");
        public static HttpVerb Options => new HttpVerb("OPTIONS");
        public static HttpVerb All => new HttpVerb("*");
    }
}
