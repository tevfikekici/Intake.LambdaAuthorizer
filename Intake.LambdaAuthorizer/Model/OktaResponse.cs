using Newtonsoft.Json;

namespace Intake.LambdaAuthorizer.Model
{
    public class OktaResponse
    {
        [JsonProperty("token_type")]
        public string TokenType { get; set; }
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("id_token")]
        public string IdToken { get; set; }
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        public string Scope { get; set; }
    }
}
