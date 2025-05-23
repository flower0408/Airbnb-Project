package errors

const (
	InvalidTokenError         = "Token is invalid"
	InvalidUserTokenError     = "Invalid user token"
	ExpiredTokenError         = "Verification token has expired"
	UsernameExist             = "Username already exists"
	InvalidCredentials        = "Invalid username or password"
	ErrorToken                = "Error generating token"
	NotVerificatedUser        = "User wasn't verified yet"
	InvalidResendMailError    = "Invalid resend mail"
	EmailAlreadyExist         = "Email already exists in database"
	InvalidRequestFormatError = "Invalid request format"
	NotFoundMailError         = "Mail not found in database"
	NotMatchingPasswordsError = "Passwords doesn't matching"
	BlackList                 = "Password is in the blacklist"
	InvalidPasswordFormat     = "Invalid password format"
	EmptyPassword             = "New password is empty"
	ErrorDeleteAccommodation  = "Error deleting accommodations"
)
