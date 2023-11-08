export class LoginDTO {
    username: string = "";
    password: string = "";

    LoginDTO(username: string, password: string) {
        this.username = username;
        this.password = password;
    }
}