namespace Intake.LambdaAuthorizer.Error
{
    public class UnauthorizedException : System.Exception
    {
        public UnauthorizedException() : base("Unauthorized")
        {
        }
    }
}
