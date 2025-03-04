using Newtonsoft.Json;
/*
 * https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/LICENSE
 */
namespace Intake.LambdaAuthorizer.Model
{
    public class TokenAuthorizerContext
    {
        [JsonProperty(PropertyName = "Type")]
        public string Type { get; set; }
        [JsonProperty(PropertyName = "AuthorizationToken")]
        public string AuthorizationToken { get; set; }
        [JsonProperty(PropertyName = "MethodArn")]
        public string MethodArn { get; set; }
    }
}
