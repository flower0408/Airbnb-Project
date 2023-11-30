export class VerificationRequest {
    user_token: string = "";
    mail_token: string = "";

    VerificationRequest(user_token: string, mail_token: string) {
        this.user_token = user_token;
        this.mail_token = mail_token;
    }
}