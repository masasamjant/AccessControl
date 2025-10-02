namespace Masasamjant.AccessControl.Authentication
{
    public sealed class AuthenticationItemValidation
    {
        public AuthenticationItemValidation(bool valid, string? unvalidReason)
        {
            IsValid = valid;
            UnvalidReason = valid ? null : unvalidReason;
        }

        public bool IsValid { get; }

        public string? UnvalidReason { get; }
    }
}
