export class ChangePasswordDTO {
    old_password: string = "";
    new_password: string = "";
    new_password_confirm: string = "";

    ChangePasswordDTO(old_password: string, new_password: string, new_password_confirm: string) {
        this.old_password = old_password;
        this.new_password = new_password;
        this.new_password_confirm = new_password_confirm;
    }
}