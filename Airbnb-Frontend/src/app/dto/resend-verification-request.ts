export class ResendVerificationRequest {
    user_mail: string = "";
    user_token: string = "";

    ResendVerificationRequest(user_mail: string, user_token: string) {
        this.user_mail = user_mail;
        this.user_token = user_token;
    }
}