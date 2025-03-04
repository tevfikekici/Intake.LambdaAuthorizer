using System.Collections.Generic;
using Newtonsoft.Json;

namespace Intake.LambdaAuthorizer.Model.Auth
{
    public class PolicyDocument
    {
        [JsonProperty(PropertyName = "Version")]
        public string Version { get; set; }
        [JsonProperty(PropertyName = "Statement")]
        public IEnumerable<Statement> Statement { get; set; }
    }
}
