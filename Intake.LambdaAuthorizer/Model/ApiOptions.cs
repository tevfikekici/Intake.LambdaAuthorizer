﻿/*
 * https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/LICENSE
 */
namespace Intake.LambdaAuthorizer.Model
{
    public class ApiOptions
    {
        public string Region { get; set; }
        public string RestApiId { get; set; }
        public string Stage { get; set; }

        public ApiOptions()
        {
        }

        public ApiOptions(string region, string restApiId, string stage)
        {
            Region = region;
            RestApiId = restApiId;
            Stage = stage;
        }
    }
}
